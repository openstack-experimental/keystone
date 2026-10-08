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
//
// SPDX-License-Identifier: Apache-2.0
//! User: OAuth2 consents (list the applications the user has approved).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use openstack_keystone_api_types::v4::oauth2_consent::{Oauth2Consent, Oauth2ConsentList};
use openstack_keystone_core::auth::ExecutionContext;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// List the applications a user has approved
///
/// Returns the OAuth2 clients the user ticked "remember my decision" for.
/// A user may list their own; an administrator may list anyone's.
#[utoipa::path(
    get,
    path = "/{user_id}/oauth2/consents",
    description = "List the OAuth2 applications a user has approved",
    params(("user_id" = String, Path, description = "User ID")),
    responses(
        (status = OK, description = "The approved applications", body = Oauth2ConsentList),
        (status = 404, description = "User not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1")))),
    ),
    security(("x-auth" = [])),
    tag = "users"
)]
#[tracing::instrument(
    name = "api::v4::user::oauth2_consents",
    level = "debug",
    skip(state, user_auth)
)]
pub(super) async fn oauth2_consents(
    Auth(user_auth): Auth,
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/oauth2/consent/list",
            &user_auth,
            json!({"user_id": &user_id}),
            None,
        )
        .await?;

    let exec = ExecutionContext::from_auth(&state, &user_auth);
    let user = state
        .provider
        .get_identity_provider()
        .get_user(&exec, &user_id)
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "user".to_string(),
            identifier: user_id.clone(),
        })?;

    let mut consents = Vec::new();
    for consent in state
        .provider
        .get_oauth2_session_provider()
        .list_consents(&state, &user.domain_id, &user_id)
        .await?
    {
        let client_name = state
            .provider
            .get_oauth2_client_provider()
            .get_by_client_id(&ExecutionContext::internal(&state), &consent.client_id)
            .await
            .ok()
            .flatten()
            .map(|c| c.name);
        consents.push(Oauth2Consent {
            client_id: consent.client_id,
            client_name,
            scopes: consent.scopes,
            authorization_target: consent.authorization_target,
            granted_at: consent.granted_at,
            updated_at: consent.updated_at,
        });
    }
    Ok((StatusCode::OK, Json(Oauth2ConsentList { consents })).into_response())
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

    use openstack_keystone_api_types::v4::oauth2_consent::Oauth2ConsentList;
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use openstack_keystone_core_types::oauth2_session::Consent;

    use super::super::openapi_router;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::identity::MockIdentityProvider;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;

    fn identity() -> MockIdentityProvider {
        let mut identity = MockIdentityProvider::default();
        identity.expect_get_user().returning(|_, id| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id(id)
                    .domain_id("domain-1")
                    .enabled(true)
                    .name("alice")
                    .build()
                    .unwrap(),
            ))
        });
        identity
    }

    fn clients() -> MockOauth2ClientProvider {
        let mut clients = MockOauth2ClientProvider::default();
        clients.expect_get_by_client_id().returning(|_, _| Ok(None));
        clients
    }

    fn sessions() -> MockOauth2SessionProvider {
        let mut sessions = MockOauth2SessionProvider::default();
        sessions
            .expect_list_consents()
            .withf(|_, domain, user| domain == "domain-1" && user == "foo")
            .returning(|_, _, _| {
                Ok(vec![Consent {
                    domain_id: "domain-1".into(),
                    user_id: "foo".into(),
                    client_id: "client-1".into(),
                    scopes: vec!["openid".into(), "email".into()],
                    authorization_target: None,
                    granted_at: 5,
                    updated_at: 6,
                }])
            });
        sessions
    }

    fn request(auth: bool) -> Request<Body> {
        let builder = Request::builder().uri("/foo/oauth2/consents");
        if auth {
            builder.extension(test_fixture_scoped())
        } else {
            builder
        }
        .body(Body::empty())
        .unwrap()
    }

    #[tokio::test]
    async fn test_list_returns_the_remembered_consents() {
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity())
                .mock_oauth2_session(sessions())
                .mock_oauth2_client(clients()),
            true,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: Oauth2ConsentList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.consents.len(), 1);
        assert_eq!(res.consents[0].client_id, "client-1");
        assert_eq!(res.consents[0].scopes, ["openid", "email"]);
        assert_eq!(res.consents[0].granted_at, 5);
    }

    #[tokio::test]
    async fn test_list_policy_input_contract() {
        let (state, policy) = get_capturing_state(
            Provider::mocked_builder()
                .mock_identity(identity())
                .mock_oauth2_session(sessions())
                .mock_oauth2_client(clients()),
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/oauth2/consent/list");
        policy_contract::assert_object_keys(&calls[0].target, &["user_id"]);
        policy_contract::assert_existing_presence(&calls[0].existing, false);
        policy_contract::assert_no_secrets(&calls[0].target);
    }

    #[tokio::test]
    async fn test_list_policy_denied() {
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity())
                .mock_oauth2_session(MockOauth2SessionProvider::default()),
            false,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_unauth() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(false)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_unknown_user_is_not_found() {
        let mut identity = MockIdentityProvider::default();
        identity.expect_get_user().returning(|_, _| Ok(None));
        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity),
            true,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
