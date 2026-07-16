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
//! `POST /v4/oauth2/{domain_id}/rotate-signing-key` (ADR 0026 §3).
//!
//! SystemAdmin-only (`policy/oauth2/key/rotate_signing_key.rego`) --
//! unlike `OAuth2Client` CRUD there is no Tier 2 domain-manager path, since
//! a signing key affects every token the domain has ever issued.
//!
//! `emergency: false` (default) commits the rotation immediately (ADR §3,
//! "Normal Rotation Flow"). `emergency: true` only stages it (ADR §3,
//! "Emergency Rotation"): the response carries `pending_rotation_id`, and a
//! second operator must call
//! `POST /v4/oauth2/{domain_id}/confirm-rotate-signing-key` within 15
//! minutes.
//!
//! `local_quorum_bypass: true` (ADR 0028 §2) stages a candidate written only
//! to this node's local emergency store, entirely bypassing Raft/quorum --
//! for use when the cluster has lost quorum and the ordinary `emergency`
//! path (a Raft proposal) would block forever. Requires `justification` and
//! is refused unless the node's `[local_emergency]` guardrail currently
//! permits it (bypass enabled, quorum unreachable, leaderless grace period
//! elapsed). The response carries `local_rotation_id`; reconciliation once
//! quorum returns is a separate operation (ADR 0028 §4, not yet
//! implemented).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use openstack_keystone_api_types::v4::oauth2_key::{
    RotateSigningKeyRequest, RotateSigningKeyResponse,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::audit::{CorrelationId, build_initiator_from_vsc, emit_oauth2_key_rotation_event};
use crate::keystone::ServiceState;

#[utoipa::path(
    post,
    path = "/{domain_id}/rotate-signing-key",
    operation_id = "/oauth2/key:rotate_signing_key",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    request_body = RotateSigningKeyRequest,
    responses(
        (status = OK, description = "Rotation result", body = RotateSigningKeyResponse),
    ),
    security(("x-auth" = [])),
    tag = "oauth2_key"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::rotate_signing_key",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn rotate_signing_key(
    Auth(user_auth): Auth,
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    CorrelationId(correlation_id): CorrelationId,
    Json(req): Json<RotateSigningKeyRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/oauth2/key/rotate_signing_key",
            &user_auth,
            serde_json::Value::Null,
            None,
        )
        .await?;

    let initiator = user_auth.inner().principal().get_user_id();

    let response = if req.local_quorum_bypass {
        let justification = req.justification.clone().ok_or_else(|| {
            KeystoneApiError::BadRequest(
                "justification is required when local_quorum_bypass is set".to_string(),
            )
        })?;
        let staged = state
            .provider
            .get_oauth2_key_provider()
            .stage_local_emergency_rotation(&state, &domain_id, &initiator, &justification)
            .await?;
        RotateSigningKeyResponse {
            kid: None,
            pending_rotation_id: None,
            expires_at: None,
            local_rotation_id: Some(staged.rotation_id),
        }
    } else if req.emergency {
        let pending = state
            .provider
            .get_oauth2_key_provider()
            .stage_emergency_rotation(&state, &domain_id, &initiator)
            .await?;
        RotateSigningKeyResponse {
            kid: None,
            pending_rotation_id: Some(pending.rotation_id),
            expires_at: Some(pending.expires_at),
            local_rotation_id: None,
        }
    } else {
        let key = state
            .provider
            .get_oauth2_key_provider()
            .rotate_signing_key(&state, &domain_id)
            .await?;
        emit_oauth2_key_rotation_event(
            &state.audit_dispatcher,
            &correlation_id,
            build_initiator_from_vsc(&user_auth),
            &domain_id,
            &key.kid,
        );
        RotateSigningKeyResponse {
            kid: Some(key.kid),
            pending_rotation_id: None,
            expires_at: None,
            local_rotation_id: None,
        }
    };

    Ok((StatusCode::OK, Json(response)).into_response())
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

    use openstack_keystone_core_types::oauth2_key::{Oauth2KeyProviderError, PendingRotationInfo};
    use openstack_keystone_key_repository::asymmetric::{SigningAlgorithm, generate_keypair};

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::oauth2_key::MockOauth2KeyProvider;
    use crate::provider::Provider;

    fn request(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/domain-1/rotate-signing-key")
            .header("content-type", "application/json")
            .extension(test_fixture_scoped())
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn test_normal_rotation_returns_kid() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_rotate_signing_key()
            .returning(|_, _| Ok(generate_keypair(SigningAlgorithm::Es256).unwrap()));
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(request(r#"{"emergency": false}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["kid"].is_string());
        assert!(json.get("pending_rotation_id").is_none());
    }

    #[tokio::test]
    async fn test_default_request_is_not_emergency() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_rotate_signing_key()
            .returning(|_, _| Ok(generate_keypair(SigningAlgorithm::Es256).unwrap()));
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api.as_service().oneshot(request("{}")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_emergency_rotation_returns_pending_rotation_id() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_stage_emergency_rotation().returning(|_, _, _| {
            Ok(PendingRotationInfo {
                rotation_id: "rotation-1".to_string(),
                expires_at: 1_000_900,
            })
        });
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(request(r#"{"emergency": true}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["pending_rotation_id"], "rotation-1");
        assert_eq!(json["expires_at"], 1_000_900);
        assert!(json.get("kid").is_none());
    }

    #[tokio::test]
    async fn test_local_quorum_bypass_returns_local_rotation_id() {
        use openstack_keystone_core_types::oauth2_key::LocalEmergencyRotationInfo;

        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_stage_local_emergency_rotation()
            .withf(
                |_, domain_id: &str, _initiator: &str, justification: &str| {
                    domain_id == "domain-1" && justification == "suspected key compromise"
                },
            )
            .returning(|_, _, _, justification| {
                Ok(LocalEmergencyRotationInfo {
                    rotation_id: "local-rotation-1".to_string(),
                    justification: justification.to_string(),
                })
            });
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(request(
                r#"{"local_quorum_bypass": true, "justification": "suspected key compromise"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["local_rotation_id"], "local-rotation-1");
        assert!(json.get("kid").is_none());
        assert!(json.get("pending_rotation_id").is_none());
    }

    #[tokio::test]
    async fn test_local_quorum_bypass_without_justification_is_rejected() {
        // No `expect_stage_local_emergency_rotation()` set: the handler
        // must reject before ever calling the provider.
        let mock = MockOauth2KeyProvider::default();
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(request(r#"{"local_quorum_bypass": true}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_local_quorum_bypass_refused_by_guardrail_surfaces_forbidden() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_stage_local_emergency_rotation()
            .returning(|_, _, _, _| Err(Oauth2KeyProviderError::LocalEmergencyBypassNotAllowed));
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(request(
                r#"{"local_quorum_bypass": true, "justification": "suspected key compromise"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
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
                    .uri("/domain-1/rotate-signing-key")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
