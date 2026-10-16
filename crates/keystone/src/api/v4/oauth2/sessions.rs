// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! Operator listing of the OAuth2 sessions (refresh token families) of a
//! user, for incident triage (`keystone-manage oauth2 sessions list`).

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};

use openstack_keystone_api_types::v4::oauth2_revocation::{
    Oauth2Session, Oauth2SessionList, Oauth2SessionListParameters,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// List the OAuth2 sessions of a user.
#[utoipa::path(
    get,
    path = "/{domain_id}/sessions",
    operation_id = "/oauth2/session:list",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
        Oauth2SessionListParameters,
    ),
    responses(
        (status = OK, description = "Sessions of the user", body = Oauth2SessionList),
    ),
    security(("x-auth" = [])),
    tag = "oauth2_revocation"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::sessions::list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    Path(domain_id): Path<String>,
    Query(query): Query<Oauth2SessionListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/oauth2/session/list",
            &user_auth,
            serde_json::json!({"domain_id": domain_id, "user_id": query.user_id}),
            None,
        )
        .await?;

    let oauth2_sessions = state
        .provider
        .get_oauth2_session_provider()
        .list_refresh_token_families_by_user(&state, &domain_id, &query.user_id)
        .await?
        .into_iter()
        .map(|f| Oauth2Session {
            family_id: f.family_id,
            client_id: f.client_id,
            user_id: f.user_id,
            issued_at: f.issued_at,
            last_rotated: f.last_rotated,
            revoked_at: f.revoked_at,
            revocation_reason: f.revocation_reason,
        })
        .collect();

    Ok((StatusCode::OK, Json(Oauth2SessionList { oauth2_sessions })).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_api_types::v4::oauth2_revocation::Oauth2SessionList;
    use openstack_keystone_core_types::oauth2_session::RefreshTokenFamilySummary;

    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;

    const URI: &str = "/domain_id/sessions?user_id=u1";

    fn request(authenticated: bool) -> Request<Body> {
        let mut builder = Request::builder().method("GET").uri(URI);
        if authenticated {
            builder = builder.extension(test_fixture_scoped());
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn test_list_sessions() {
        let mut mock = MockOauth2SessionProvider::default();
        mock.expect_list_refresh_token_families_by_user()
            .returning(|_, _, _| {
                Ok(vec![RefreshTokenFamilySummary {
                    family_id: "f1".into(),
                    domain_id: "domain_id".into(),
                    client_id: "c1".into(),
                    user_id: "u1".into(),
                    issued_at: 10,
                    last_rotated: 20,
                    revoked_at: None,
                    revocation_reason: None,
                }])
            });
        let provider = Provider::mocked_builder().mock_oauth2_session(mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: Oauth2SessionList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.oauth2_sessions.len(), 1);
        assert_eq!(res.oauth2_sessions[0].last_rotated, 20);
    }

    #[tokio::test]
    async fn test_policy_denied() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api.as_service().oneshot(request(false)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
