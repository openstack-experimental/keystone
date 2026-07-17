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
//! # Delete an OS-EC2 credential by plaintext access key

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

/// Delete an EC2 credential. The `credential_id` path segment is the
/// **plaintext access key** (ADR 0019 §2, "Plaintext ID Lookup").
#[utoipa::path(
    delete,
    path = "/{user_id}/credentials/OS-EC2/{credential_id}",
    description = "Delete an EC2 credential by plaintext access key (OS-EC2 legacy API)",
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "EC2 credential not found"),
    ),
    tag="OS-EC2"
)]
#[tracing::instrument(name = "api::os_ec2_delete", level = "debug", skip(state))]
pub(super) async fn delete(
    Auth(user_auth): Auth,
    Path((user_id, credential_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = super::show::lookup(&state, &user_auth, &user_id, &credential_id).await?;

    state
        .policy_enforcer
        .enforce(
            "identity/os_ec2/delete_credential",
            &user_auth,
            serde_json::Value::Null,
            Some(json!({
                "user_id": &user_id,
                "credential": current.as_ref().map(super::ec2_credential_policy_input),
            })),
        )
        .await?;

    match current {
        Some(current) => {
            state
                .provider
                .get_credential_provider()
                .delete_credential(
                    &ExecutionContext::from_auth(&state, &user_auth),
                    &current.id,
                )
                .await?;
            Ok((StatusCode::NO_CONTENT).into_response())
        }
        _ => Err(KeystoneApiError::NotFound {
            resource: "ec2_credential".into(),
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

    /// Gate B2 (issue #978): mirrors `show`'s contract test for delete --
    /// same documented multi-key shape, same blob-leak risk.
    #[tokio::test]
    async fn test_delete_policy_input_contract() {
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
        credential_mock
            .expect_delete_credential()
            .returning(|_, _| Ok(()));

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
                    .method("DELETE")
                    .uri("/foo/credentials/OS-EC2/AKIA123")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/os_ec2/delete_credential");
        assert_eq!(calls[0].target, serde_json::Value::Null);
        policy_contract::assert_existing_presence(&calls[0].existing, true);
        let existing = calls[0].existing.as_ref().unwrap();
        policy_contract::assert_object_keys(existing, &["user_id", "credential"]);
        policy_contract::assert_no_secrets(existing);
    }

    #[tokio::test]
    async fn test_delete_found() {
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
        credential_mock
            .expect_delete_credential()
            .withf(|_, id: &'_ str| id == "cred_id")
            .returning(|_, _| Ok(()));

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
                    .method("DELETE")
                    .uri("/foo/credentials/OS-EC2/AKIA123")
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
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_get_credential_by_ec2_access()
            .returning(|_, _| Ok(None));

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
                    .method("DELETE")
                    .uri("/foo/credentials/OS-EC2/AKIA123")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
