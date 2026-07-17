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

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use openstack_keystone_api_types::v3::credential::{Credential, CredentialResponse};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Get single credential.
#[utoipa::path(
    get,
    path = "/{credential_id}",
    description = "Get credential by ID",
    params(),
    responses(
        (status = OK, description = "Credential object", body = CredentialResponse),
        (status = 404, description = "Credential not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="credentials"
)]
#[tracing::instrument(name = "api::credential_get", level = "debug", skip(state))]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(credential_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_credential_provider()
        .get_credential(
            &ExecutionContext::from_auth(&state, &user_auth),
            &credential_id,
        )
        .await?;

    state
        .policy_enforcer
        .enforce(
            "identity/credential/show",
            &user_auth,
            serde_json::Value::Null,
            Some(super::credential_policy_input(&current)),
        )
        .await?;

    match current {
        Some(current) => Ok((
            StatusCode::OK,
            Json(CredentialResponse {
                credential: Credential::from(current),
            }),
        )
            .into_response()),
        _ => Err(KeystoneApiError::NotFound {
            resource: "credential".into(),
            identifier: credential_id,
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

    use openstack_keystone_core_types::credential::CredentialBuilder;

    use super::super::openapi_router;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::credential::MockCredentialProvider;
    use crate::provider::Provider;

    /// Gate B2 (issue #978): `identity/credential/show.rego` documents
    /// `input.target = null`, `input.existing.credential = <stored>`. Assert
    /// the handler actually feeds that shape, and that the stripped `blob`
    /// never reaches the policy engine.
    #[tokio::test]
    async fn test_show_policy_input_contract() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_get_credential()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| {
                Ok(Some(
                    CredentialBuilder::default()
                        .id("foo")
                        .blob(r#"{"seed":"AAAA"}"#)
                        .r#type("totp")
                        .user_id("uid")
                        .build()
                        .unwrap(),
                ))
            });

        let vsc = test_fixture_scoped();
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_credential(credential_mock)).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/credential/show");
        assert_eq!(calls[0].target, serde_json::Value::Null);
        policy_contract::assert_existing_presence(&calls[0].existing, true);
        policy_contract::assert_object_keys(calls[0].existing.as_ref().unwrap(), &["credential"]);
        policy_contract::assert_no_secrets(calls[0].existing.as_ref().unwrap());
    }

    #[tokio::test]
    async fn test_get_not_found_not_allowed() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_get_credential()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_credential(credential_mock),
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
                    .uri("/foo")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Gate B3 (security review V3a, issue #979): drives this handler and
    /// the real `identity/credential/show.rego` decision through the
    /// authorized/unauthorized/delegated-allowed/delegated-escape matrix
    /// via a real `opa run` subprocess, exercising
    /// `credential_common.bound_to_own_delegation_project`
    /// (OSSA-2026-015). Also underlies `credential::list`'s per-item
    /// re-check (ADR 0019 §2, CVE-2019-19687). Requires `opa` on `PATH`.
    mod real_policy_decision {
        use openstack_keystone_core::auth::ValidatedSecurityContext;

        use super::*;
        use crate::api::tests::get_state_with_real_policy;
        use crate::api::tests::real_policy_fixtures::{member_vsc, restricted_app_cred_vsc};
        use crate::provider::ProviderBuilder;

        fn provider_with_credential(
            owner_user_id: &'static str,
            existing_project_id: Option<&'static str>,
        ) -> ProviderBuilder {
            let mut credential_mock = MockCredentialProvider::default();
            credential_mock
                .expect_get_credential()
                .withf(|_, id: &'_ str| id == "cred1")
                .returning(move |_, _| {
                    let mut builder = CredentialBuilder::default();
                    builder
                        .id("cred1")
                        .blob(r#"{"seed":"AAAA"}"#)
                        .r#type("totp")
                        .user_id(owner_user_id);
                    if let Some(project_id) = existing_project_id {
                        builder.project_id(project_id);
                    }
                    Ok(Some(builder.build().unwrap()))
                });
            Provider::mocked_builder().mock_credential(credential_mock)
        }

        async fn show_request(
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
                        .uri("/cred1")
                        .extension(vsc)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }

        #[tokio::test]
        async fn owner_reading_own_non_delegated_credential_is_allowed() {
            let status = show_request(
                member_vsc("u1", "p1", &["member"]),
                provider_with_credential("u1", None),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }

        #[tokio::test]
        async fn non_owner_reading_someone_elses_credential_is_denied() {
            let status = show_request(
                member_vsc("u2", "p1", &["member"]),
                provider_with_credential("u1", None),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }

        /// OSSA-2026-015: a delegated caller reading a credential bound to
        /// its own delegation project is allowed.
        #[tokio::test]
        async fn delegated_caller_reading_credential_bound_to_own_project_is_allowed() {
            let status = show_request(
                restricted_app_cred_vsc("u1", "p1"),
                provider_with_credential("u1", Some("p1")),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }

        /// OSSA-2026-015: a delegated caller must not be able to read an
        /// unscoped credential (e.g. TOTP/MFA seed) it owns.
        #[tokio::test]
        async fn delegated_caller_reading_unscoped_credential_is_denied() {
            let status = show_request(
                restricted_app_cred_vsc("u1", "p1"),
                provider_with_credential("u1", None),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
    }
}
