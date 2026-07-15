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
//! `POST /v4/oauth2/{domain_id}/confirm-rotate-signing-key` (ADR 0026 §3).
//!
//! Stage 2 of the emergency rotation dual-control flow: a second operator
//! (must differ from the one that called `rotate-signing-key` with
//! `emergency: true` -- enforced by the provider layer, which holds the
//! stored initiator identity) confirms within the 15-minute window,
//! promoting the staged key to `Primary` and adding `revoke_jtis` to the
//! domain's JTI revocation list.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::audit::{
    CorrelationId, build_initiator_from_vsc, emit_oauth2_emergency_key_rotation_critical_event,
};
use crate::keystone::ServiceState;

/// Request body for `confirm-rotate-signing-key`.
#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct ConfirmRotateSigningKeyRequest {
    /// The `pending_rotation_id` returned by `rotate-signing-key`.
    rotation_id: String,
    /// JTIs known to have been issued by the compromised key during the
    /// incident window, to add to the JTI revocation list (ADR 0026 §3).
    /// Empty by default: this repository has no audit-log query capability
    /// to derive this list automatically (see ADR 0026 §3 amendment).
    #[serde(default)]
    revoke_jtis: Vec<String>,
}

/// Response body for `confirm-rotate-signing-key`.
#[derive(Debug, Serialize, ToSchema)]
pub(super) struct ConfirmRotateSigningKeyResponse {
    /// The newly active `Primary` key's `kid`.
    kid: String,
}

#[utoipa::path(
    post,
    path = "/{domain_id}/confirm-rotate-signing-key",
    operation_id = "/oauth2/key:confirm_rotate_signing_key",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    request_body = ConfirmRotateSigningKeyRequest,
    responses(
        (status = OK, description = "Confirmation result", body = ConfirmRotateSigningKeyResponse),
    ),
    security(("x-auth" = [])),
    tag = "oauth2_key"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::confirm_rotate_signing_key",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn confirm_rotate_signing_key(
    Auth(user_auth): Auth,
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    CorrelationId(correlation_id): CorrelationId,
    Json(req): Json<ConfirmRotateSigningKeyRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/oauth2/key/confirm_rotate_signing_key",
            &user_auth,
            serde_json::Value::Null,
            None,
        )
        .await?;

    let confirmer = user_auth.inner().principal().get_user_id();
    let revoke_jtis = req.revoke_jtis.clone();

    let key = state
        .provider
        .get_oauth2_key_provider()
        .confirm_emergency_rotation(
            &state,
            &domain_id,
            &req.rotation_id,
            &confirmer,
            req.revoke_jtis,
        )
        .await?;

    emit_oauth2_emergency_key_rotation_critical_event(
        &state.audit_dispatcher,
        &correlation_id,
        build_initiator_from_vsc(&user_auth),
        &domain_id,
        &key.kid,
        &revoke_jtis,
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(ConfirmRotateSigningKeyResponse { kid: key.kid }),
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

    use openstack_keystone_core_types::oauth2_key::Oauth2KeyProviderError;
    use openstack_keystone_key_repository::asymmetric::{SigningAlgorithm, generate_keypair};

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::oauth2_key::MockOauth2KeyProvider;
    use crate::provider::Provider;

    fn request(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/domain-1/confirm-rotate-signing-key")
            .header("content-type", "application/json")
            .extension(test_fixture_scoped())
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn test_confirm_success_returns_kid() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_confirm_emergency_rotation()
            .returning(|_, _, _, _, _| Ok(generate_keypair(SigningAlgorithm::Es256).unwrap()));
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(request(r#"{"rotation_id": "rotation-1"}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["kid"].is_string());
    }

    #[tokio::test]
    async fn test_dual_control_violation_is_forbidden() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_confirm_emergency_rotation()
            .returning(|_, _, _, _, _| Err(Oauth2KeyProviderError::DualControlViolation));
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(request(r#"{"rotation_id": "rotation-1"}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_expired_rotation_is_conflict() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_confirm_emergency_rotation()
            .returning(|_, _, _, _, _| {
                Err(Oauth2KeyProviderError::RotationExpired(
                    "rotation-1".to_string(),
                ))
            });
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(request(r#"{"rotation_id": "rotation-1"}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_unknown_rotation_id_is_not_found() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_confirm_emergency_rotation()
            .returning(|_, _, _, _, _| {
                Err(Oauth2KeyProviderError::NoPendingRotation(
                    "unknown".to_string(),
                ))
            });
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(request(r#"{"rotation_id": "unknown"}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
                    .uri("/domain-1/confirm-rotate-signing-key")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"rotation_id": "rotation-1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
