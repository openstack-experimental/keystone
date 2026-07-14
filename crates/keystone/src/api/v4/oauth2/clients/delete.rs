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
//! OAuth2 client: delete (soft-delete -- disables and stamps the tombstone,
//! record retained for Phase 4's refresh-token family-tree invalidation).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_api_types::v4::oauth2_client::OAuth2Client;
use openstack_keystone_core::auth::ExecutionContext;

/// Revoke (soft-delete) an OAuth2 client.
#[utoipa::path(
    delete,
    path = "/{domain_id}/clients/{provider_id}",
    operation_id = "/oauth2/client:delete",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
        ("provider_id" = String, Path, description = "Client provider_id"),
    ),
    responses(
        (status = NO_CONTENT, description = "OAuth2 client revoked"),
    ),
    security(("x-auth" = [])),
    tag = "oauth2_client"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::clients::delete",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn delete(
    Auth(user_auth): Auth,
    Path((domain_id, provider_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let exec = ExecutionContext::from_auth(&state, &user_auth);

    let current = state
        .provider
        .get_oauth2_client_provider()
        .get(&exec, &domain_id, &provider_id)
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "oauth2_client".into(),
            identifier: provider_id.clone(),
        })?;

    state
        .policy_enforcer
        .enforce(
            "identity/oauth2/client/delete",
            &user_auth,
            serde_json::Value::Null,
            Some(serde_json::json!({"oauth2_client": OAuth2Client::from(current)})),
        )
        .await?;

    state
        .provider
        .get_oauth2_client_provider()
        .delete(&exec, &domain_id, &provider_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::oauth2_client as provider_types;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::Provider;

    fn sample_resource() -> provider_types::OAuth2ClientResource {
        provider_types::OAuth2ClientResource {
            client_id: "client-1".into(),
            provider_id: "provider-1".into(),
            domain_id: "domain_id".into(),
            client_secret_hash: None,
            redirect_uris: vec![],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec![],
            require_pkce: true,
            allowed_scopes: vec![],
            pre_authorized: false,
            enabled: true,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }

    #[tokio::test]
    async fn test_delete_soft_deletes() {
        let vsc = test_fixture_scoped();
        let mut mock = MockOauth2ClientProvider::default();
        mock.expect_get()
            .returning(|_, _, _| Ok(Some(sample_resource())));
        mock.expect_delete().returning(|_, _, _| {
            Ok(provider_types::OAuth2ClientResource {
                enabled: false,
                deleted_at: Some(1),
                ..sample_resource()
            })
        });
        let provider = Provider::mocked_builder().mock_oauth2_client(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/domain_id/clients/provider-1")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_policy_denied() {
        let vsc = test_fixture_scoped();
        let mut mock = MockOauth2ClientProvider::default();
        mock.expect_get()
            .returning(|_, _, _| Ok(Some(sample_resource())));
        let provider = Provider::mocked_builder().mock_oauth2_client(mock);

        let state = get_mocked_state(provider, false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/domain_id/clients/provider-1")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_delete_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/domain_id/clients/provider-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
