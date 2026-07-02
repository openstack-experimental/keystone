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
//! API Key: show.
//!
//! Not specified by ADR 0021 §5.B (which only lists create/list/update), but
//! added for consistency with every other v4 resource and because
//! update/revoke/simulate-access all resolve a key by `client_id` anyway.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

use openstack_keystone_api_types::v4::api_key::{ApiKey, ApiKeyResponse};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// Query parameters for `GET /v4/api-keys/{client_id}`.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(super) struct ShowParams {
    /// Domain the key belongs to.
    domain_id: String,
}

/// Show an API Key by `client_id`.
#[utoipa::path(
    get,
    path = "/{client_id}",
    operation_id = "/api_key:show",
    params(
        ("client_id" = String, Path, description = "API Key client_id"),
        ShowParams,
    ),
    responses(
        (status = OK, description = "API Key object", body = ApiKeyResponse),
    ),
    security(("x-auth" = [])),
    tag="api_key"
)]
#[tracing::instrument(
    name = "api::v4::api_key::show",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(client_id): Path<String>,
    Query(params): Query<ShowParams>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_api_key_provider()
        .get_by_client_id(&state, &params.domain_id, &client_id)
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "api_key".into(),
            identifier: client_id.clone(),
        })?;

    state
        .policy_enforcer
        .enforce(
            "identity/api_key/show",
            &user_auth,
            serde_json::json!({"api_key": null}),
            Some(serde_json::json!({"api_key": ApiKey::from(current.clone())})),
        )
        .await?;

    Ok((
        StatusCode::OK,
        Json(ApiKeyResponse {
            api_key: ApiKey::from(current),
        }),
    )
        .into_response())
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

    use openstack_keystone_api_types::v4::api_key::ApiKeyResponse;
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
            description: None,
            enabled: true,
            created_at: 1_000,
            expires_at: 2_000,
            last_used_at: None,
            revoked_at: None,
            revoked_by: None,
        }
    }

    #[tokio::test]
    async fn test_show() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockApiKeyProvider::default();
        mock.expect_get_by_client_id()
            .returning(|_, _, _| Ok(Some(sample_resource_core())));
        provider = provider.mock_api_key(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/client-1?domain_id=domain_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ApiKeyResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.api_key.client_id, "client-1");
    }

    #[tokio::test]
    async fn test_show_not_found() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockApiKeyProvider::default();
        mock.expect_get_by_client_id().returning(|_, _, _| Ok(None));
        provider = provider.mock_api_key(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/missing?domain_id=domain_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_show_policy_denied() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockApiKeyProvider::default();
        mock.expect_get_by_client_id()
            .returning(|_, _, _| Ok(Some(sample_resource_core())));
        provider = provider.mock_api_key(mock);

        let state = get_mocked_state(provider, false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/client-1?domain_id=domain_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_show_unauthorized() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_api_key(MockApiKeyProvider::default()),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/client-1?domain_id=domain_id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
