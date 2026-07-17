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
//! # Create credential API

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use validator::Validate;

use super::types::{CredentialCreateRequest, CredentialResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Create a new credential.
#[utoipa::path(
    post,
    path = "/",
    responses(
        (status = CREATED, description = "Credential created", body = CredentialResponse),
        (status = 400, description = "Invalid input"),
        (status = 500, description = "Internal error")
    ),
    tag="credentials"
)]
#[tracing::instrument(name = "api::v3::credential_create", level = "debug", skip(state))]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(payload): Json<CredentialCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    payload.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/credential/create",
            &user_auth,
            super::credential_policy_input(&payload.credential),
            None,
        )
        .await?;

    let created = state
        .provider
        .get_credential_provider()
        .create_credential(
            &ExecutionContext::from_auth(&state, &user_auth),
            payload.into(),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(CredentialResponse {
            credential: created.into(),
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

    use openstack_keystone_core_types::credential::{CredentialBuilder, CredentialCreate};

    use super::super::openapi_router;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::api::v3::credential::types::{CredentialCreateBuilder, CredentialResponse};
    use crate::credential::MockCredentialProvider;
    use crate::provider::Provider;

    /// Gate B2 (security review V3a, issue #978): asserts the handler feeds
    /// `enforce()` the contract `identity/credential/create.rego` expects --
    /// single `credential` key, no `existing`, and no leaked `blob`.
    #[tokio::test]
    async fn test_create_policy_input_contract() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_create_credential()
            .returning(|_, _| {
                Ok(CredentialBuilder::default()
                    .id("new_id")
                    .blob(r#"{"seed":"AAAA"}"#)
                    .r#type("totp")
                    .user_id("uid")
                    .build()
                    .unwrap())
            });

        let vsc = test_fixture_scoped();
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_credential(credential_mock)).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = crate::api::v3::credential::types::CredentialCreateRequest {
            credential: CredentialCreateBuilder::default()
                .blob(r#"{"seed":"AAAA"}"#)
                .r#type("totp")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
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
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/credential/create");
        policy_contract::assert_object_keys(&calls[0].target, &["credential"]);
        policy_contract::assert_existing_presence(&calls[0].existing, false);
        policy_contract::assert_no_secrets(&calls[0].target);
    }

    #[tokio::test]
    async fn test_create() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_create_credential()
            .withf(|_, rec: &CredentialCreate| {
                rec.r#type == "totp" && rec.blob == r#"{"seed":"AAAA"}"#
            })
            .returning(|_, _| {
                Ok(CredentialBuilder::default()
                    .id("new_id")
                    .blob(r#"{"seed":"AAAA"}"#)
                    .r#type("totp")
                    .user_id("uid")
                    .build()
                    .unwrap())
            });

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_credential(credential_mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let req = crate::api::v3::credential::types::CredentialCreateRequest {
            credential: CredentialCreateBuilder::default()
                .blob(r#"{"seed":"AAAA"}"#)
                .r#type("totp")
                .build()
                .unwrap(),
        };

        let response = api
            .as_service()
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
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: CredentialResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.credential.id, "new_id");
    }

    /// Gate B3 (security review V3a, issue #979): drives this handler and
    /// the real `identity/credential/create.rego` decision (via
    /// `get_state_with_real_policy`'s real `opa run` subprocess + the
    /// production `HttpPolicyEnforcer`, instead of a canned allow/deny)
    /// through the authorized/unauthorized/delegated-allowed/
    /// delegated-escape matrix. `test_create_policy_input_contract` above
    /// proves the handler builds a well-shaped policy input; this proves
    /// the real policy actually decides on it as expected -- closing the
    /// gap a mock can never catch (a handler feeding OPA a subtly wrong
    /// document that a mock accepts, but the real policy would not).
    /// Requires `opa` on `PATH`.
    mod real_policy_decision {
        use openstack_keystone_core::auth::ValidatedSecurityContext;

        use super::*;
        use crate::api::tests::get_state_with_real_policy;
        use crate::api::tests::real_policy_fixtures::{member_vsc, restricted_app_cred_vsc};
        use crate::provider::ProviderBuilder;

        /// A `MockCredentialProvider` whose `create_credential` always
        /// succeeds -- only reached by the scenarios the real policy is
        /// expected to allow; the denied scenarios never get this far.
        fn allowing_provider() -> ProviderBuilder {
            let mut credential_mock = crate::credential::MockCredentialProvider::default();
            credential_mock
                .expect_create_credential()
                .returning(|_, rec| {
                    let mut builder =
                        openstack_keystone_core_types::credential::CredentialBuilder::default();
                    builder
                        .id("new_id")
                        .blob(rec.blob.clone())
                        .r#type(rec.r#type.clone())
                        .user_id(rec.user_id.clone().unwrap_or_default());
                    if let Some(project_id) = &rec.project_id {
                        builder.project_id(project_id.clone());
                    }
                    Ok(builder.build().unwrap())
                });
            Provider::mocked_builder().mock_credential(credential_mock)
        }

        async fn create_request(
            vsc: ValidatedSecurityContext,
            credential: crate::api::v3::credential::types::CredentialCreate,
            provider_builder: ProviderBuilder,
        ) -> StatusCode {
            let (state, _opa_guard) = get_state_with_real_policy(provider_builder).await;
            let mut api = openapi_router()
                .layer(TraceLayer::new_for_http())
                .with_state(state);

            let req = crate::api::v3::credential::types::CredentialCreateRequest { credential };

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

        #[tokio::test]
        async fn authorized_member_creating_own_credential_is_allowed() {
            let status = create_request(
                member_vsc("u1", "p1", &["member"]),
                CredentialCreateBuilder::default()
                    .blob(r#"{"seed":"AAAA"}"#)
                    .r#type("totp")
                    .user_id("u1")
                    .build()
                    .unwrap(),
                allowing_provider(),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
        }

        #[tokio::test]
        async fn unauthorized_caller_with_no_roles_is_denied() {
            let status = create_request(
                member_vsc("u1", "p1", &[]),
                CredentialCreateBuilder::default()
                    .blob(r#"{"seed":"AAAA"}"#)
                    .r#type("totp")
                    .user_id("u1")
                    .build()
                    .unwrap(),
                Provider::mocked_builder(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }

        /// OSSA-2026-015: a restricted application credential creating a
        /// non-ec2 credential bound to its own delegation project is
        /// allowed.
        #[tokio::test]
        async fn delegated_credential_bound_to_own_project_is_allowed() {
            let status = create_request(
                restricted_app_cred_vsc("u1", "p1"),
                CredentialCreateBuilder::default()
                    .blob(r#"{"seed":"AAAA"}"#)
                    .r#type("totp")
                    .user_id("u1")
                    .project_id("p1")
                    .build()
                    .unwrap(),
                allowing_provider(),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
        }

        /// OSSA-2026-015: a delegated caller whose token scope is pinned to
        /// its own delegation project (no Rust-side scope-drift) must still
        /// be denied by the real Rego policy from creating a credential
        /// that escapes that project (here: no `project_id` on the target
        /// at all, i.e. an unscoped credential) -- this is the
        /// `credential_common.not_delegated_or_bound_to_own_project` check
        /// itself, not the Rust-side tripwire in `Credentials::try_from`.
        #[tokio::test]
        async fn delegated_credential_escaping_own_project_is_denied() {
            let status = create_request(
                restricted_app_cred_vsc("u1", "p1"),
                CredentialCreateBuilder::default()
                    .blob(r#"{"seed":"AAAA"}"#)
                    .r#type("totp")
                    .user_id("u1")
                    .build()
                    .unwrap(),
                Provider::mocked_builder(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
    }
}
