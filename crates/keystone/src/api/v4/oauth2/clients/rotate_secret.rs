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
//! OAuth2 client: rotate-secret.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use openstack_keystone_api_types::v4::oauth2_client::{
    OAuth2Client, OAuth2ClientRotateSecretResponse,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Generate and persist a fresh client secret, returned exactly once.
#[utoipa::path(
    post,
    path = "/{domain_id}/clients/{provider_id}/rotate-secret",
    operation_id = "/oauth2/client:rotate_secret",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
        ("provider_id" = String, Path, description = "Client provider_id"),
    ),
    responses(
        (status = OK, description = "One-time plaintext client secret", body = OAuth2ClientRotateSecretResponse),
    ),
    security(("x-auth" = [])),
    tag = "oauth2_client"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::clients::rotate_secret",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn rotate_secret(
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
            "identity/oauth2/client/rotate_secret",
            &user_auth,
            serde_json::Value::Null,
            Some(serde_json::json!({"oauth2_client": OAuth2Client::from(current)})),
        )
        .await?;

    let (_, client_secret) = state
        .provider
        .get_oauth2_client_provider()
        .rotate_secret(&exec, &domain_id, &provider_id)
        .await?;

    Ok((
        StatusCode::OK,
        Json(OAuth2ClientRotateSecretResponse { client_secret }),
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

    use openstack_keystone_api_types::v4::oauth2_client::OAuth2ClientRotateSecretResponse;
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
            client_secret_hash: Some("$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA".into()),
            redirect_uris: vec!["https://rp.example.com/callback".into()],
            token_endpoint_auth_method: "client_secret_basic".into(),
            grant_types: vec![],
            require_pkce: false,
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
    async fn test_rotate_secret_returns_plaintext_once() {
        let vsc = test_fixture_scoped();
        let mut mock = MockOauth2ClientProvider::default();
        mock.expect_get()
            .returning(|_, _, _| Ok(Some(sample_resource())));
        mock.expect_rotate_secret()
            .returning(|_, _, _| Ok((sample_resource(), "kosc_new_secret".to_string())));
        let provider = Provider::mocked_builder().mock_oauth2_client(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/domain_id/clients/provider-1/rotate-secret")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: OAuth2ClientRotateSecretResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.client_secret, "kosc_new_secret");
    }

    #[tokio::test]
    async fn test_rotate_secret_not_found() {
        let vsc = test_fixture_scoped();
        let mut mock = MockOauth2ClientProvider::default();
        mock.expect_get().returning(|_, _, _| Ok(None));
        let provider = Provider::mocked_builder().mock_oauth2_client(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/domain_id/clients/nonexistent/rotate-secret")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_rotate_secret_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/domain_id/clients/provider-1/rotate-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
