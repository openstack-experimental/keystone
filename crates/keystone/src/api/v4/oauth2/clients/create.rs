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
//! OAuth2 client: create.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use openstack_keystone_api_types::v4::oauth2_client::{
    OAuth2Client, OAuth2ClientCreateRequest, OAuth2ClientCreateResponse,
};
use validator::Validate;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Register a new OAuth2 client (relying party).
#[utoipa::path(
    post,
    path = "/{domain_id}/clients",
    operation_id = "/oauth2/client:create",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    request_body = OAuth2ClientCreateRequest,
    responses(
        (status = CREATED, description = "OAuth2 client object", body = OAuth2ClientCreateResponse),
    ),
    security(("x-auth" = [])),
    tag = "oauth2_client"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::clients::create",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn create(
    Auth(user_auth): Auth,
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<OAuth2ClientCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/oauth2/client/create",
            &user_auth,
            serde_json::json!({"oauth2_client": req.oauth2_client, "domain_id": domain_id}),
            None,
        )
        .await?;

    let confidential = req.oauth2_client.confidential;
    let mut data: openstack_keystone_core_types::oauth2_client::OAuth2ClientResourceCreate =
        req.into();
    data.domain_id = domain_id;
    let exec = ExecutionContext::from_auth(&state, &user_auth);
    let (created, client_secret) = state
        .provider
        .get_oauth2_client_provider()
        .create(&exec, data, confidential)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(OAuth2ClientCreateResponse {
            oauth2_client: OAuth2Client::from(created),
            client_secret,
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_api_types::v4::oauth2_client::{
        OAuth2ClientCreate, OAuth2ClientCreateRequest, OAuth2ClientCreateResponse,
    };
    use openstack_keystone_core_types::oauth2_client as provider_types;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::Provider;

    fn sample_resource(confidential: bool) -> provider_types::OAuth2ClientResource {
        provider_types::OAuth2ClientResource {
            client_id: "client-1".into(),
            provider_id: "provider-1".into(),
            domain_id: "domain_id".into(),
            client_secret_hash: confidential
                .then(|| "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA".to_string()),
            redirect_uris: vec!["https://rp.example.com/callback".into()],
            token_endpoint_auth_method: "client_secret_basic".into(),
            grant_types: vec![provider_types::GrantType::AuthorizationCode],
            require_pkce: !confidential,
            allowed_scopes: vec!["openid".into()],
            pre_authorized: false,
            enabled: true,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }

    fn sample_create(confidential: bool) -> OAuth2ClientCreateRequest {
        OAuth2ClientCreateRequest {
            oauth2_client: OAuth2ClientCreate {
                provider_id: "provider-1".into(),
                confidential,
                redirect_uris: vec!["https://rp.example.com/callback".into()],
                token_endpoint_auth_method: "client_secret_basic".into(),
                grant_types: vec![],
                require_pkce: !confidential,
                allowed_scopes: vec!["openid".into()],
                pre_authorized: false,
                claims_template: Default::default(),
            },
        }
    }

    #[tokio::test]
    async fn test_create() {
        let vsc = test_fixture_scoped();
        let mut mock = MockOauth2ClientProvider::default();
        mock.expect_create().returning(|_, _, confidential| {
            Ok((sample_resource(confidential), Some("kosc_secret".into())))
        });
        let provider = Provider::mocked_builder().mock_oauth2_client(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_create(true);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/domain_id/clients")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: OAuth2ClientCreateResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.oauth2_client.provider_id, "provider-1");
        assert_eq!(res.client_secret.as_deref(), Some("kosc_secret"));
    }

    #[tokio::test]
    async fn test_create_forbidden() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_create(true);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/domain_id/clients")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_create(true);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/domain_id/clients")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
