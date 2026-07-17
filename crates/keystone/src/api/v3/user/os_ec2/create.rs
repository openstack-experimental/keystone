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
//! # Create an OS-EC2 credential for a user

use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_core_types::credential::CredentialCreateBuilder;

use super::types::{Ec2CredentialCreateRequest, Ec2CredentialResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Create a new EC2 credential for a user. `access`/`secret` are
/// auto-generated (UUIDs) when omitted from the request (ADR 0019 §2,
/// "Automatic Creation").
#[utoipa::path(
    post,
    path = "/{user_id}/credentials/OS-EC2",
    description = "Create an EC2 credential for a user (OS-EC2 legacy API)",
    responses(
        (status = CREATED, description = "EC2 credential created", body = Ec2CredentialResponse),
        (status = 400, description = "Invalid input"),
    ),
    tag="OS-EC2"
)]
#[tracing::instrument(name = "api::os_ec2_create", level = "debug", skip(state))]
pub(super) async fn create(
    Auth(user_auth): Auth,
    Path(user_id): Path<String>,
    State(state): State<ServiceState>,
    Json(payload): Json<Ec2CredentialCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    payload.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/os_ec2/create_credential",
            &user_auth,
            json!({"user_id": &user_id, "tenant_id": &payload.project_id}),
            None,
        )
        .await?;

    let access = payload
        .access
        .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let secret = payload
        .secret
        .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let blob = serde_json::json!({"access": access, "secret": secret}).to_string();

    let rec = CredentialCreateBuilder::default()
        .blob(blob)
        .r#type("ec2")
        .project_id(payload.project_id)
        .user_id(user_id)
        .build()?;

    let created = state
        .provider
        .get_credential_provider()
        .create_credential(&ExecutionContext::from_auth(&state, &user_auth), rec)
        .await?;

    Ok((
        StatusCode::CREATED,
        axum::Json(Ec2CredentialResponse {
            credential: super::to_ec2_credential(created)?,
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
    use crate::api::v3::user::os_ec2::types::Ec2CredentialResponse;
    use crate::credential::MockCredentialProvider;
    use crate::provider::Provider;

    /// Gate B2 (issue #978): `identity/os_ec2/create_credential.rego`
    /// documents `input.target = {"user_id": ..., "tenant_id": ...}`,
    /// `input.existing = null`.
    #[tokio::test]
    async fn test_create_policy_input_contract() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_create_credential()
            .returning(|_, rec| {
                Ok(CredentialBuilder::default()
                    .id("cred_id")
                    .blob(rec.blob.clone())
                    .r#type("ec2")
                    .user_id("foo")
                    .project_id("pid")
                    .build()
                    .unwrap())
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
                    .uri("/foo/credentials/OS-EC2")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(r#"{"tenant_id":"pid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/os_ec2/create_credential");
        policy_contract::assert_object_keys(&calls[0].target, &["user_id", "tenant_id"]);
        policy_contract::assert_existing_presence(&calls[0].existing, false);
        policy_contract::assert_no_secrets(&calls[0].target);
    }

    #[tokio::test]
    async fn test_create_auto_generates_access_and_secret() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_create_credential()
            .withf(|_, rec: &CredentialCreate| {
                rec.r#type == "ec2"
                    && rec.user_id.as_deref() == Some("foo")
                    && rec.project_id.as_deref() == Some("pid")
            })
            .returning(|_, rec| {
                Ok(CredentialBuilder::default()
                    .id("cred_id")
                    .blob(rec.blob.clone())
                    .r#type("ec2")
                    .user_id("foo")
                    .project_id("pid")
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

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo/credentials/OS-EC2")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(r#"{"tenant_id":"pid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: Ec2CredentialResponse = serde_json::from_slice(&body).unwrap();
        assert!(!res.credential.access.is_empty());
        assert!(!res.credential.secret.is_empty());
        assert_eq!(res.credential.project_id, "pid");
    }

    #[tokio::test]
    async fn test_create_with_explicit_access_and_secret() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_create_credential()
            .withf(|_, rec: &CredentialCreate| rec.blob.contains("AKIA123"))
            .returning(|_, rec| {
                Ok(CredentialBuilder::default()
                    .id("cred_id")
                    .blob(rec.blob.clone())
                    .r#type("ec2")
                    .user_id("foo")
                    .project_id("pid")
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

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo/credentials/OS-EC2")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(
                        r#"{"tenant_id":"pid","access":"AKIA123","secret":"s3cr3t"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: Ec2CredentialResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.credential.access, "AKIA123");
        assert_eq!(res.credential.secret, "s3cr3t");
    }

    #[tokio::test]
    async fn test_create_denied() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo/credentials/OS-EC2")
                    .extension(vsc)
                    .header("Content-Type", "application/json")
                    .method("POST")
                    .body(Body::from(r#"{"tenant_id":"pid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Gate B3 (security review V3a, issue #979): drives this handler and
    /// the real `identity/os_ec2/create_credential.rego` decision through
    /// the authorized/unauthorized/delegated-allowed/delegated-escape/
    /// restricted-app-cred matrix via a real `opa run` subprocess, covering
    /// both the OSSA-2026-015 delegation boundary and the OSSA-2026-005 /
    /// CVE-2026-33551 restricted-application-credential block. Requires
    /// `opa` on `PATH`.
    mod real_policy_decision {
        use openstack_keystone_core::auth::ValidatedSecurityContext;

        use super::*;
        use crate::api::tests::get_state_with_real_policy;
        use crate::api::tests::real_policy_fixtures::{app_cred_vsc, member_vsc};
        use crate::provider::ProviderBuilder;

        fn allowing_provider() -> ProviderBuilder {
            let mut credential_mock = MockCredentialProvider::default();
            credential_mock
                .expect_create_credential()
                .returning(|_, rec| {
                    Ok(CredentialBuilder::default()
                        .id("cred_id")
                        .blob(rec.blob.clone())
                        .r#type("ec2")
                        .user_id(rec.user_id.clone().unwrap_or_default())
                        .project_id(rec.project_id.clone().unwrap_or_default())
                        .build()
                        .unwrap())
                });
            Provider::mocked_builder().mock_credential(credential_mock)
        }

        async fn create_request(
            vsc: ValidatedSecurityContext,
            path_user_id: &str,
            tenant_id: Option<&str>,
            provider_builder: ProviderBuilder,
        ) -> StatusCode {
            let (state, _opa_guard) = get_state_with_real_policy(provider_builder).await;
            let mut api = openapi_router()
                .layer(TraceLayer::new_for_http())
                .with_state(state);

            let body = match tenant_id {
                Some(tenant_id) => format!(r#"{{"tenant_id":"{tenant_id}"}}"#),
                None => "{}".to_string(),
            };

            api.as_service()
                .oneshot(
                    Request::builder()
                        .uri(format!("/{path_user_id}/credentials/OS-EC2"))
                        .extension(vsc)
                        .header("Content-Type", "application/json")
                        .method("POST")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }

        #[tokio::test]
        async fn authorized_member_creating_own_ec2_credential_is_allowed() {
            let status = create_request(
                member_vsc("u1", "p1", &["member"]),
                "u1",
                Some("p1"),
                allowing_provider(),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
        }

        #[tokio::test]
        async fn creating_ec2_credential_for_another_user_is_denied() {
            let status = create_request(
                member_vsc("u1", "p1", &["member"]),
                "u2",
                Some("p1"),
                Provider::mocked_builder(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }

        /// OSSA-2026-005 / CVE-2026-33551: a restricted application
        /// credential must never be usable to mint an EC2 credential, even
        /// for itself bound to its own delegation project.
        #[tokio::test]
        async fn restricted_app_cred_creating_ec2_credential_is_denied() {
            let status = create_request(
                app_cred_vsc("u1", "p1", false),
                "u1",
                Some("p1"),
                Provider::mocked_builder(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }

        /// An unrestricted application credential may mint an EC2 credential
        /// bound to its own delegation project.
        #[tokio::test]
        async fn unrestricted_app_cred_creating_ec2_credential_bound_to_own_project_is_allowed() {
            let status = create_request(
                app_cred_vsc("u1", "p1", true),
                "u1",
                Some("p1"),
                allowing_provider(),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
        }

        /// OSSA-2026-015: an unrestricted application credential must still
        /// be denied from minting an EC2 credential that escapes its own
        /// delegation project.
        #[tokio::test]
        async fn unrestricted_app_cred_creating_ec2_credential_escaping_own_project_is_denied() {
            let status = create_request(
                app_cred_vsc("u1", "p1", true),
                "u1",
                Some("p2"),
                Provider::mocked_builder(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
    }
}
