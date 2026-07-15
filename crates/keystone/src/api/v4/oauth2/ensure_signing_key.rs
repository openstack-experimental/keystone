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
//! `POST /v4/oauth2/{domain_id}/ensure-signing-key` (ADR 0026 §3).
//!
//! SystemAdmin-only (`policy/oauth2/key/ensure_signing_key.rego`) --
//! idempotently provisions a `Primary` signing key for a domain if it
//! doesn't already have one. This is a bootstrap/repair operation: domains
//! created through the Rust API's own `POST /v3/domains` already get keys
//! via `Oauth2KeyHook` firing on the domain-create event, but a domain
//! provisioned any other way (e.g. the legacy Python `keystone-manage
//! bootstrap`, which writes directly to the DB and never calls the Rust
//! API) never fires that hook and is left without signing keys forever.
//! Unlike `rotate-signing-key`, this is safe to call whether or not the
//! domain already has a key.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use openstack_keystone_api_types::v4::oauth2_key::EnsureSigningKeyResponse;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

#[utoipa::path(
    post,
    path = "/{domain_id}/ensure-signing-key",
    operation_id = "/oauth2/key:ensure_signing_key",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "Signing key present", body = EnsureSigningKeyResponse),
    ),
    security(("x-auth" = [])),
    tag = "oauth2_key"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::ensure_signing_key",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn ensure_signing_key(
    Auth(user_auth): Auth,
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/oauth2/key/ensure_signing_key",
            &user_auth,
            serde_json::Value::Null,
            None,
        )
        .await?;

    let key = state
        .provider
        .get_oauth2_key_provider()
        .ensure_domain_keys(&state, &domain_id)
        .await?;

    Ok((
        StatusCode::OK,
        Json(EnsureSigningKeyResponse { kid: key.kid }),
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

    use openstack_keystone_key_repository::asymmetric::{SigningAlgorithm, generate_keypair};

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::oauth2_key::MockOauth2KeyProvider;
    use crate::provider::Provider;

    fn request() -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/domain-1/ensure-signing-key")
            .header("content-type", "application/json")
            .extension(test_fixture_scoped())
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_ensure_signing_key_returns_kid() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_ensure_domain_keys()
            .returning(|_, _| Ok(generate_keypair(SigningAlgorithm::Es256).unwrap()));
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api.as_service().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["kid"].is_string());
    }

    #[tokio::test]
    async fn test_unauthorized_without_auth_extension() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/domain-1/ensure-signing-key")
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
