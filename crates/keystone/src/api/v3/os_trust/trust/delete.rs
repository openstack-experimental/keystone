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
//! Delete trust API.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Delete a trust.
///
/// Deleting a trust immediately revokes any tokens issued from it (see
/// `TrustService::delete_trust`).
#[utoipa::path(
    delete,
    path = "/{trust_id}",
    description = "Delete trust by ID",
    params(),
    responses(
        (status = NO_CONTENT, description = "Trust deleted"),
        (status = 404, description = "Trust not found", example = json!(KeystoneApiError::NotFound{resource: "trust".into(), identifier: "id = 1".into()}))
    ),
    tag="OS-TRUST"
)]
#[tracing::instrument(name = "api::trust_delete", level = "debug", skip(state))]
pub(super) async fn delete(
    Auth(user_auth): Auth,
    Path(trust_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_trust_provider()
        .get_trust(&ExecutionContext::from_auth(&state, &user_auth), &trust_id)
        .await?;

    state
        .policy_enforcer
        .enforce(
            "identity/trust/delete",
            &user_auth,
            serde_json::Value::Null,
            Some(json!({"trust": current})),
        )
        .await?;

    match current {
        Some(_) => {
            state
                .provider
                .get_trust_provider()
                .delete_trust(&ExecutionContext::from_auth(&state, &user_auth), &trust_id)
                .await?;

            Ok(StatusCode::NO_CONTENT.into_response())
        }
        _ => Err(KeystoneApiError::NotFound {
            resource: "trust".into(),
            identifier: trust_id,
        }),
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::trust::TrustBuilder;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::provider::Provider;
    use crate::trust::MockTrustProvider;

    #[tokio::test]
    async fn test_delete_success() {
        let mut trust_mock = MockTrustProvider::default();
        trust_mock
            .expect_get_trust()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(
                    TrustBuilder::default()
                        .id("foo")
                        .trustor_user_id("trustor")
                        .trustee_user_id("trustee")
                        .impersonation(false)
                        .build()
                        .unwrap(),
                ))
            });
        trust_mock
            .expect_delete_trust()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(()));

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
                    .method("DELETE")
                    .uri("/foo")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let mut trust_mock = MockTrustProvider::default();
        trust_mock
            .expect_get_trust()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

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
                    .method("DELETE")
                    .uri("/foo")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_forbidden() {
        let mut trust_mock = MockTrustProvider::default();
        trust_mock
            .expect_get_trust()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(
                    TrustBuilder::default()
                        .id("foo")
                        .trustor_user_id("trustor")
                        .trustee_user_id("trustee")
                        .impersonation(false)
                        .build()
                        .unwrap(),
                ))
            });

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
                    .method("DELETE")
                    .uri("/foo")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Gate B2 (security review V3a, issue #990): asserts the handler feeds
    /// `enforce()` the contract `identity/trust/delete.rego` expects -- the
    /// stored trust under `existing`, no leaked secret field.
    #[tokio::test]
    async fn test_delete_policy_input_contract() {
        let mut trust_mock = MockTrustProvider::default();
        trust_mock
            .expect_get_trust()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(
                    TrustBuilder::default()
                        .id("foo")
                        .trustor_user_id("trustor")
                        .trustee_user_id("trustee")
                        .impersonation(false)
                        .build()
                        .unwrap(),
                ))
            });
        trust_mock
            .expect_delete_trust()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(()));

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
                    .method("DELETE")
                    .uri("/foo")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/trust/delete");
        crate::api::tests::policy_contract::assert_existing_presence(&calls[0].existing, true);
        crate::api::tests::policy_contract::assert_object_keys(
            calls[0].existing.as_ref().unwrap(),
            &["trust"],
        );
        crate::api::tests::policy_contract::assert_no_secrets(calls[0].existing.as_ref().unwrap());
    }

    /// Gate B3 (security review V3a, issue #990): drives this handler and
    /// the real `identity/trust/delete.rego` decision through the
    /// trustor/trustee/admin matrix. Only the trustor (or admin) may
    /// delete -- the trustee has no authority to revoke a delegation it did
    /// not grant.
    mod real_policy_decision {
        use openstack_keystone_core::auth::ValidatedSecurityContext;

        use super::*;
        use crate::api::tests::get_state_with_real_policy;
        use crate::api::tests::real_policy_fixtures::member_vsc;
        use crate::provider::ProviderBuilder;

        fn provider_allowing_delete() -> ProviderBuilder {
            let mut trust_mock = MockTrustProvider::default();
            trust_mock.expect_get_trust().returning(|_, _| {
                Ok(Some(
                    TrustBuilder::default()
                        .id("foo")
                        .trustor_user_id("trustor")
                        .trustee_user_id("trustee")
                        .impersonation(false)
                        .build()
                        .unwrap(),
                ))
            });
            trust_mock.expect_delete_trust().returning(|_, _| Ok(()));
            Provider::mocked_builder().mock_trust(trust_mock)
        }

        fn provider_denying_delete() -> ProviderBuilder {
            let mut trust_mock = MockTrustProvider::default();
            trust_mock.expect_get_trust().returning(|_, _| {
                Ok(Some(
                    TrustBuilder::default()
                        .id("foo")
                        .trustor_user_id("trustor")
                        .trustee_user_id("trustee")
                        .impersonation(false)
                        .build()
                        .unwrap(),
                ))
            });
            Provider::mocked_builder().mock_trust(trust_mock)
        }

        async fn delete_status(
            vsc: ValidatedSecurityContext,
            provider_builder: ProviderBuilder,
        ) -> StatusCode {
            let (state, _opa_guard) = get_state_with_real_policy(provider_builder).await;
            let mut api = openapi_router()
                .layer(TraceLayer::new_for_http())
                .with_state(state);

            api.as_service()
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri("/foo")
                        .extension(vsc)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }

        #[tokio::test]
        async fn trustor_deleting_own_trust_is_allowed() {
            assert_eq!(
                delete_status(
                    member_vsc("trustor", "p1", &["member"]),
                    provider_allowing_delete()
                )
                .await,
                StatusCode::NO_CONTENT
            );
        }

        #[tokio::test]
        async fn trustee_deleting_trust_is_denied() {
            assert_eq!(
                delete_status(
                    member_vsc("trustee", "p1", &["member"]),
                    provider_denying_delete()
                )
                .await,
                StatusCode::FORBIDDEN
            );
        }

        #[tokio::test]
        async fn admin_deleting_any_trust_is_allowed() {
            assert_eq!(
                delete_status(
                    member_vsc("admin_user", "p1", &["admin"]),
                    provider_allowing_delete()
                )
                .await,
                StatusCode::NO_CONTENT
            );
        }
    }

    #[tokio::test]
    async fn test_delete_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
