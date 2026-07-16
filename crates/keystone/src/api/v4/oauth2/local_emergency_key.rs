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
//! `GET /v4/oauth2/{domain_id}/local-emergency-candidates` and
//! `POST /v4/oauth2/{domain_id}/reconcile-local-emergency-key` (ADR 0028 §6).
//!
//! Reconciliation of a `--local-quorum-bypass` candidate (staged via
//! `rotate-signing-key` with `local_quorum_bypass: true`, see
//! `rotate_signing_key.rs`) once Raft quorum has returned. Both handlers
//! must be called against the specific node holding the chosen candidate --
//! reconciliation does not fan out across the cluster. The list endpoint
//! exists so an operator can see any `LOCAL_EMERGENCY_CONFLICT` (ADR 0028
//! §5) before picking a `rotation_id`.
//!
//! SystemAdmin-only, same posture as `rotate-signing-key`.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use openstack_keystone_api_types::v4::oauth2_key::{
    ListLocalEmergencyCandidatesResponse, LocalEmergencyCandidateSummary,
    ReconcileLocalEmergencyKeyRequest, ReconcileLocalEmergencyKeyResponse,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::audit::{
    CorrelationId, build_initiator_from_vsc, emit_oauth2_local_emergency_key_reconciled_event,
};
use crate::keystone::ServiceState;

#[utoipa::path(
    get,
    path = "/{domain_id}/local-emergency-candidates",
    operation_id = "/oauth2/key:list_local_emergency_candidates",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "Local emergency candidates on this node", body = ListLocalEmergencyCandidatesResponse),
    ),
    security(("x-auth" = [])),
    tag = "oauth2_key"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::list_local_emergency_candidates",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list_local_emergency_candidates(
    Auth(user_auth): Auth,
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/oauth2/key/list_local_emergency_candidates",
            &user_auth,
            serde_json::Value::Null,
            None,
        )
        .await?;

    let candidates = state
        .provider
        .get_oauth2_key_provider()
        .list_local_emergency_candidates(&state, &domain_id)
        .await?
        .into_iter()
        .map(|c| LocalEmergencyCandidateSummary {
            rotation_id: c.rotation_id,
            initiator: c.initiator,
            justification: c.justification,
            created_at_unix: c.created_at_unix,
            origin_node_id: c.origin_node_id,
            conflicted: c.conflicted,
            revoked: c.revoked,
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(ListLocalEmergencyCandidatesResponse { candidates }),
    )
        .into_response())
}

#[utoipa::path(
    post,
    path = "/{domain_id}/reconcile-local-emergency-key",
    operation_id = "/oauth2/key:reconcile_local_emergency_key",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    request_body = ReconcileLocalEmergencyKeyRequest,
    responses(
        (status = OK, description = "Reconciliation result", body = ReconcileLocalEmergencyKeyResponse),
    ),
    security(("x-auth" = [])),
    tag = "oauth2_key"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::reconcile_local_emergency_key",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn reconcile_local_emergency_key(
    Auth(user_auth): Auth,
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    CorrelationId(correlation_id): CorrelationId,
    Json(req): Json<ReconcileLocalEmergencyKeyRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/oauth2/key/reconcile_local_emergency_key",
            &user_auth,
            serde_json::Value::Null,
            None,
        )
        .await?;

    let confirmer = user_auth.inner().principal().get_user_id();

    let key = state
        .provider
        .get_oauth2_key_provider()
        .reconcile_local_emergency_rotation(&state, &domain_id, &req.rotation_id, &confirmer)
        .await?;

    let event_id = emit_oauth2_local_emergency_key_reconciled_event(
        &state.audit_dispatcher,
        &correlation_id,
        build_initiator_from_vsc(&user_auth),
        &domain_id,
        &req.rotation_id,
        &key.kid,
    )
    .await;
    // Design gap 2 (ADR 0028 implementation plan): record the pointer from
    // rotation_id to this audit event so reconciliation/audit tooling can
    // find it without scanning the whole spool. Best-effort -- the audit
    // event itself (dispatched above) is the durable record; a missing
    // pointer only costs a spool scan, never audit visibility.
    if let Some(store) = state.local_emergency_store.read().await.as_ref()
        && let Err(e) = store.put_audit_pointer(&req.rotation_id, &event_id).await
    {
        tracing::warn!(
            rotation_id = req.rotation_id,
            error = %e,
            "failed to record local emergency audit pointer"
        );
    }

    Ok((
        StatusCode::OK,
        Json(ReconcileLocalEmergencyKeyResponse { kid: key.kid }),
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

    use openstack_keystone_core_types::oauth2_key::{
        LocalEmergencyCandidateSummary as CoreLocalEmergencyCandidateSummary,
        Oauth2KeyProviderError,
    };
    use openstack_keystone_key_repository::asymmetric::{SigningAlgorithm, generate_keypair};

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::oauth2_key::MockOauth2KeyProvider;
    use crate::provider::Provider;

    fn get_request(uri: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("content-type", "application/json")
            .extension(test_fixture_scoped())
            .body(Body::empty())
            .unwrap()
    }

    fn post_request(uri: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .extension(test_fixture_scoped())
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn test_list_returns_candidates() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_list_local_emergency_candidates()
            .returning(|_, _| {
                Ok(vec![CoreLocalEmergencyCandidateSummary {
                    rotation_id: "rot-1".to_string(),
                    initiator: "operator-a".to_string(),
                    justification: "suspected key compromise".to_string(),
                    created_at_unix: 1_000_000,
                    origin_node_id: None,
                    conflicted: false,
                    revoked: false,
                }])
            });
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(get_request("/domain-1/local-emergency-candidates"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["candidates"][0]["rotation_id"], "rot-1");
        assert_eq!(json["candidates"][0]["conflicted"], false);
    }

    #[tokio::test]
    async fn test_list_unauthorized_without_auth_extension() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/domain-1/local-emergency-candidates")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_reconcile_success_returns_kid() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_reconcile_local_emergency_rotation()
            .returning(|_, _, _, _| Ok(generate_keypair(SigningAlgorithm::Es256).unwrap()));
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(post_request(
                "/domain-1/reconcile-local-emergency-key",
                r#"{"rotation_id": "rot-1"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["kid"].is_string());
    }

    #[tokio::test]
    async fn test_reconcile_unknown_rotation_id_is_not_found() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_reconcile_local_emergency_rotation()
            .returning(|_, _, _, _| {
                Err(Oauth2KeyProviderError::LocalEmergencyCandidateNotFound(
                    "rot-unknown".to_string(),
                ))
            });
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(post_request(
                "/domain-1/reconcile-local-emergency-key",
                r#"{"rotation_id": "rot-unknown"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_reconcile_dual_control_violation_is_forbidden() {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_reconcile_local_emergency_rotation()
            .returning(|_, _, _, _| Err(Oauth2KeyProviderError::DualControlViolation));
        let provider = Provider::mocked_builder().mock_oauth2_key(mock);
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(post_request(
                "/domain-1/reconcile-local-emergency-key",
                r#"{"rotation_id": "rot-1"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_reconcile_unauthorized_without_auth_extension() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/domain-1/reconcile-local-emergency-key")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"rotation_id": "rot-1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
