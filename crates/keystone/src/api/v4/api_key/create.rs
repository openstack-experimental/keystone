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
//! API Key: create.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use secrecy::ExposeSecret;
use validator::Validate;

use openstack_keystone_api_types::v4::api_key::{
    ApiKey, ApiKeyCreateRequest, ApiKeyCreateResponse,
};
use openstack_keystone_core_types::api_key::ApiClientResourceCreate;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api_key::{crypto, token};
use crate::keystone::ServiceState;

/// Create a new API Key.
#[utoipa::path(
    post,
    path = "/",
    operation_id = "/api_key:create",
    request_body = ApiKeyCreateRequest,
    responses(
        (status = CREATED, description = "API Key object, including the one-time bearer token", body = ApiKeyCreateResponse),
    ),
    security(("x-auth" = [])),
    tag="api_key"
)]
#[tracing::instrument(
    name = "api::v4::api_key::create",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(req): Json<ApiKeyCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/api_key/create",
            &user_auth,
            serde_json::json!({"api_key": req.api_key}),
            None,
        )
        .await?;

    let cfg = state.config_manager.config.read().await.api_key.clone();
    let generated = token::generate();
    let secret_hash = crypto::hash_secret(generated.entropy.expose_secret(), &cfg).await?;

    let data = ApiClientResourceCreate {
        domain_id: req.api_key.domain_id,
        provider_id: req.api_key.provider_id,
        client_id: uuid::Uuid::new_v4().simple().to_string(),
        lookup_hash: generated.lookup_hash,
        secret_hash,
        allowed_ips: req.api_key.allowed_ips,
        description: req.api_key.description,
        expires_at: req.api_key.expires_at.timestamp(),
    };

    let res = state
        .provider
        .get_api_key_provider()
        .create(&state, data)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(ApiKeyCreateResponse {
            api_key: ApiKey::from(res),
            token: generated.token,
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
    use chrono::{TimeZone, Utc};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_api_types::v4::api_key::{ApiKeyCreate, ApiKeyCreateRequest};
    use openstack_keystone_core_types::api_key as provider_types;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api_key::MockApiKeyProvider;
    use crate::provider::Provider;

    fn sample_resource_core() -> provider_types::ApiClientResource {
        provider_types::ApiClientResource {
            domain_id: "domain_id".into(),
            provider_id: "provider-1".into(),
            client_id: "client-1".into(),
            lookup_hash: "lookup-hash".into(),
            secret_hash: "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA".into(),
            allowed_ips: None,
            description: Some("test key".into()),
            enabled: true,
            created_at: 1_000,
            expires_at: 2_000,
            last_used_at: None,
            revoked_at: None,
            revoked_by: None,
        }
    }

    fn sample_request() -> ApiKeyCreateRequest {
        ApiKeyCreateRequest {
            api_key: ApiKeyCreate {
                domain_id: "domain_id".into(),
                provider_id: "provider-1".into(),
                allowed_ips: None,
                description: Some("test key".into()),
                expires_at: Utc.timestamp_opt(2_000, 0).unwrap(),
            },
        }
    }

    #[tokio::test]
    async fn test_create() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockApiKeyProvider::default();
        mock.expect_create()
            .returning(|_, _| Ok(sample_resource_core()));
        provider = provider.mock_api_key(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_request();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(res["api_key"]["client_id"], "client-1");
        // The one-time bearer token must be present in the create response.
        assert!(res["token"].as_str().unwrap().starts_with("kscim_"));
    }

    #[tokio::test]
    async fn test_create_policy_denied() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_api_key(MockApiKeyProvider::default()),
            false,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_request();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
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
        let state = get_mocked_state(
            Provider::mocked_builder().mock_api_key(MockApiKeyProvider::default()),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_request();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
