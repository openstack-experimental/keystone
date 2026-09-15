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
//! # Create trust API
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use validator::Validate;

use super::types::{TrustCreateRequest, TrustResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::role::RoleListParametersBuilder;

/// Create a new trust.
///
/// Trust authorization is decided by `policy/trust/create.rego` off the
/// caller's identity (`credentials.user_id` must match the requested
/// `trustor_user_id`) rather than the resource's own role list -- the
/// trustor-holds-the-role invariant is enforced provider-side
/// (`TrustService::create_trust`), not by policy.
#[utoipa::path(
    post,
    path = "/",
    responses(
        (status = CREATED, description = "Trust created", body = TrustResponse),
        (status = 400, description = "Invalid input"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal error")
    ),
    tag="OS-TRUST"
)]
#[tracing::instrument(name = "api::v3::trust_create", level = "debug", skip(state))]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(mut payload): Json<TrustCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    payload.validate()?;

    // Roles may be referenced by `id` or by `name` (matching python
    // keystone); resolve name-only references to an id here since the
    // provider layer only deals in role ids.
    for role in payload.trust.roles.iter_mut() {
        if role.id.is_none() {
            let name = role
                .name
                .clone()
                .ok_or_else(|| KeystoneApiError::BadRequest("role id or name required".into()))?;
            let resolved = state
                .provider
                .get_role_provider()
                .list_roles(
                    &ExecutionContext::internal(&state),
                    &RoleListParametersBuilder::default()
                        .name(name.clone())
                        .build()?,
                )
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| KeystoneApiError::BadRequest(format!("role `{name}` not found")))?;
            role.id = Some(resolved.id);
        }
    }

    state
        .policy_enforcer
        .enforce(
            "identity/trust/create",
            &user_auth,
            json!({"trust": payload.trust}),
            None,
        )
        .await?;

    let created = state
        .provider
        .get_trust_provider()
        .create_trust(
            &ExecutionContext::from_auth(&state, &user_auth),
            payload.into(),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(TrustResponse {
            trust: created.into(),
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

    use openstack_keystone_core_types::trust::TrustBuilder;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::os_trust::trust::types::{
        Trust as ApiTrust, TrustCreate, TrustCreateRequest, TrustResponse,
    };
    use crate::provider::Provider;
    use crate::trust::MockTrustProvider;

    fn create_request() -> TrustCreateRequest {
        create_request_for("trustor", None)
    }

    fn create_request_for(trustor_user_id: &str, project_id: Option<&str>) -> TrustCreateRequest {
        TrustCreateRequest {
            trust: TrustCreate {
                id: None,
                trustor_user_id: trustor_user_id.into(),
                trustee_user_id: "trustee".into(),
                project_id: project_id.map(Into::into),
                impersonation: false,
                expires_at: None,
                remaining_uses: None,
                redelegated_trust_id: None,
                redelegation_count: None,
                roles: Vec::new(),
                extra: None,
            },
        }
    }

    /// Gate B2 (security review V3a, issue #990): asserts the handler feeds
    /// `enforce()` the contract `identity/trust/create.rego` expects --
    /// single `trust` key, no `existing`, and no leaked secret field.
    #[tokio::test]
    async fn test_create_policy_input_contract() {
        let mut trust_mock = MockTrustProvider::default();
        trust_mock.expect_create_trust().returning(|_, t| {
            Ok(TrustBuilder::default()
                .id("new_trust_id")
                .trustor_user_id(t.trustor_user_id)
                .trustee_user_id(t.trustee_user_id)
                .impersonation(t.impersonation)
                .build()
                .unwrap())
        });

        let vsc = test_fixture_scoped();
        let (state, policy) = crate::api::tests::get_capturing_state(
            Provider::mocked_builder().mock_trust(trust_mock),
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(
                        serde_json::to_string(&create_request()).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/trust/create");
        crate::api::tests::policy_contract::assert_object_keys(&calls[0].target, &["trust"]);
        crate::api::tests::policy_contract::assert_existing_presence(&calls[0].existing, false);
        crate::api::tests::policy_contract::assert_no_secrets(&calls[0].target);
    }

    #[tokio::test]
    async fn test_create() {
        let mut trust_mock = MockTrustProvider::default();
        trust_mock.expect_create_trust().returning(|_, t| {
            Ok(TrustBuilder::default()
                .id("new_trust_id")
                .trustor_user_id(t.trustor_user_id)
                .trustee_user_id(t.trustee_user_id)
                .impersonation(t.impersonation)
                .build()
                .unwrap())
        });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_trust(trust_mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(
                        serde_json::to_string(&create_request()).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: TrustResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            ApiTrust {
                id: "new_trust_id".into(),
                trustor_user_id: "trustor".into(),
                trustee_user_id: "trustee".into(),
                project_id: None,
                impersonation: false,
                expires_at: None,
                remaining_uses: None,
                redelegated_trust_id: None,
                redelegation_count: None,
                roles: Vec::new(),
                extra: None,
            },
            res.trust,
        );
    }

    #[tokio::test]
    async fn test_create_forbidden() {
        let trust_mock = MockTrustProvider::default();

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_trust(trust_mock),
            false,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(
                        serde_json::to_string(&create_request()).unwrap(),
                    ))
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
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(
                        serde_json::to_string(&create_request()).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Gate B3 (security review V3a, issue #990): drives this handler and
    /// the real `identity/trust/create.rego` decision (via
    /// `get_state_with_real_policy`'s real `opa run` subprocess + the
    /// production `HttpPolicyEnforcer`) through the trustor/non-trustor and
    /// delegated-allowed/delegated-escape matrix -- trusts are one of the
    /// three delegation mechanisms I1-I5 exist to bound, and this endpoint
    /// had neither B2 nor B3 coverage before. Requires `opa` on `PATH`.
    mod real_policy_decision {
        use openstack_keystone_core::auth::ValidatedSecurityContext;

        use super::*;
        use crate::api::tests::get_state_with_real_policy;
        use crate::api::tests::real_policy_fixtures::{member_vsc, restricted_app_cred_vsc};
        use crate::provider::ProviderBuilder;

        fn allowing_provider() -> ProviderBuilder {
            let mut trust_mock = MockTrustProvider::default();
            trust_mock.expect_create_trust().returning(|_, t| {
                Ok(TrustBuilder::default()
                    .id("new_trust_id")
                    .trustor_user_id(t.trustor_user_id)
                    .trustee_user_id(t.trustee_user_id)
                    .project_id(t.project_id.unwrap_or_default())
                    .impersonation(t.impersonation)
                    .build()
                    .unwrap())
            });
            Provider::mocked_builder().mock_trust(trust_mock)
        }

        async fn create_request_status(
            vsc: ValidatedSecurityContext,
            req: TrustCreateRequest,
            provider_builder: ProviderBuilder,
        ) -> StatusCode {
            let (state, _opa_guard) = get_state_with_real_policy(provider_builder).await;
            let mut api = openapi_router()
                .layer(TraceLayer::new_for_http())
                .with_state(state);

            api.as_service()
                .oneshot(
                    Request::builder()
                        .uri("/")
                        .extension(vsc)
                        .header("Content-Type", "application/json")
                        .method("POST")
                        .body(Body::from(serde_json::to_string(&req).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }

        /// "A trust is always self-issued": the caller creating a trust as
        /// its own trustor is allowed, with no role requirement at the
        /// policy layer (`policy/trust/create.rego`'s own documented
        /// posture -- role sufficiency is checked provider-side).
        #[tokio::test]
        async fn trustor_creating_own_trust_is_allowed() {
            let status = create_request_status(
                member_vsc("trustor", "p1", &[]),
                create_request_for("trustor", None),
                allowing_provider(),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
        }

        /// A caller may not create a trust on someone else's behalf, even
        /// with full member roles -- matches python keystone's
        /// `identity:create_trust`, which has no admin bypass.
        #[tokio::test]
        async fn non_trustor_creating_trust_for_someone_else_is_denied() {
            let status = create_request_status(
                member_vsc("attacker", "p1", &["member"]),
                create_request_for("victim", None),
                Provider::mocked_builder(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }

        /// OSSA-2026-015: a restricted application credential creating a
        /// trust as its own trustor, bound to its own delegation project, is
        /// allowed.
        #[tokio::test]
        async fn delegated_trustor_bound_to_own_project_is_allowed() {
            let status = create_request_status(
                restricted_app_cred_vsc("trustor", "p1"),
                create_request_for("trustor", Some("p1")),
                allowing_provider(),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
        }

        /// OSSA-2026-015: a delegated caller must not be able to create a
        /// trust that escapes its own delegation project -- here, an
        /// unscoped (no `project_id`) trust, which
        /// `not_delegated_or_bound_to_own_project` must still deny for a
        /// delegated caller.
        #[tokio::test]
        async fn delegated_trustor_escaping_own_project_is_denied() {
            let status = create_request_status(
                restricted_app_cred_vsc("trustor", "p1"),
                create_request_for("trustor", None),
                Provider::mocked_builder(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
    }
}
