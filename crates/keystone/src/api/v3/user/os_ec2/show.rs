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
//! # Get a single OS-EC2 credential by plaintext access key

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use openstack_keystone_core_types::credential::Credential as CoreCredential;

use super::types::Ec2CredentialResponse;
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::{ExecutionContext, ValidatedSecurityContext};

/// Get a single EC2 credential. The `credential_id` path segment is the
/// **plaintext access key** (ADR 0019 §2, "Plaintext ID Lookup"), hashed
/// (`SHA-256`) server-side to locate the record.
#[utoipa::path(
    get,
    path = "/{user_id}/credentials/OS-EC2/{credential_id}",
    description = "Get an EC2 credential by plaintext access key (OS-EC2 legacy API)",
    responses(
        (status = OK, description = "EC2 credential object", body = Ec2CredentialResponse),
        (status = 404, description = "EC2 credential not found"),
    ),
    tag="OS-EC2"
)]
#[tracing::instrument(name = "api::os_ec2_show", level = "debug", skip(state))]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path((user_id, credential_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = lookup(&state, &user_auth, &user_id, &credential_id).await?;

    state
        .policy_enforcer
        .enforce(
            "identity/os_ec2/read_credential",
            &user_auth,
            serde_json::Value::Null,
            Some(json!({
                "user_id": &user_id,
                "credential": current.as_ref().map(super::ec2_credential_policy_input),
            })),
        )
        .await?;

    match current {
        Some(current) => Ok((
            StatusCode::OK,
            Json(Ec2CredentialResponse {
                credential: super::to_ec2_credential(current)?,
            }),
        )
            .into_response()),
        _ => Err(KeystoneApiError::NotFound {
            resource: "ec2_credential".into(),
            identifier: credential_id,
        }),
    }
}

/// Resolve the plaintext access key to a stored credential, scoped to the
/// path `user_id` — a match owned by a different user is treated as absent.
pub(super) async fn lookup(
    state: &ServiceState,
    user_auth: &ValidatedSecurityContext,
    user_id: &str,
    access: &str,
) -> Result<Option<CoreCredential>, KeystoneApiError> {
    let found = state
        .provider
        .get_credential_provider()
        .get_credential_by_ec2_access(&ExecutionContext::from_auth(state, user_auth), access)
        .await?;

    Ok(found.filter(|c| c.user_id == user_id))
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

    use openstack_keystone_core_types::credential::CredentialBuilder;

    use super::super::openapi_router;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::api::v3::user::os_ec2::types::Ec2CredentialResponse;
    use crate::credential::MockCredentialProvider;
    use crate::provider::Provider;

    /// Gate B2 (issue #978): `identity/os_ec2/read_credential.rego`
    /// documents `input.existing = {"user_id": ..., "credential": ...}` for
    /// a show request -- a legitimate multi-key exception to the single
    /// resource-key convention (ADR 0002), but the raw stored `Credential`
    /// (with its decrypted `blob`) must never be embedded directly.
    #[tokio::test]
    async fn test_show_policy_input_contract() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_get_credential_by_ec2_access()
            .returning(|_, _| {
                Ok(Some(
                    CredentialBuilder::default()
                        .id("cred_id")
                        .blob(r#"{"access":"AKIA123","secret":"s3cr3t"}"#)
                        .r#type("ec2")
                        .user_id("foo")
                        .project_id("pid")
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
                    .uri("/foo/credentials/OS-EC2/AKIA123")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/os_ec2/read_credential");
        assert_eq!(calls[0].target, serde_json::Value::Null);
        policy_contract::assert_existing_presence(&calls[0].existing, true);
        let existing = calls[0].existing.as_ref().unwrap();
        policy_contract::assert_object_keys(existing, &["user_id", "credential"]);
        policy_contract::assert_no_secrets(existing);
    }

    #[tokio::test]
    async fn test_show_found() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_get_credential_by_ec2_access()
            .withf(|_, access: &'_ str| access == "AKIA123")
            .returning(|_, _| {
                Ok(Some(
                    CredentialBuilder::default()
                        .id("cred_id")
                        .blob(r#"{"access":"AKIA123","secret":"s3cr3t"}"#)
                        .r#type("ec2")
                        .user_id("foo")
                        .project_id("pid")
                        .build()
                        .unwrap(),
                ))
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
                    .uri("/foo/credentials/OS-EC2/AKIA123")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: Ec2CredentialResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.credential.access, "AKIA123");
    }

    #[tokio::test]
    async fn test_show_wrong_user_not_found() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_get_credential_by_ec2_access()
            .returning(|_, _| {
                Ok(Some(
                    CredentialBuilder::default()
                        .id("cred_id")
                        .blob(r#"{"access":"AKIA123","secret":"s3cr3t"}"#)
                        .r#type("ec2")
                        .user_id("someone_else")
                        .project_id("pid")
                        .build()
                        .unwrap(),
                ))
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
                    .uri("/foo/credentials/OS-EC2/AKIA123")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_show_not_found_not_allowed() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_get_credential_by_ec2_access()
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
                    .uri("/foo/credentials/OS-EC2/AKIA123")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
