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
//! Test credential creation (ADR 0019 §1, §2).

use eyre::Result;
use sha2::{Digest, Sha256};
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::credential::*;

use crate::credential::get_state;
use crate::{create_domain, create_project, create_user};

fn ec2_id(access: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(access.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
#[traced_test]
async fn test_create_ec2_computes_sha256_id() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;

    let cred = state
        .provider
        .get_credential_provider()
        .create_credential(
            &ExecutionContext::internal(&state),
            CredentialCreate {
                blob: r#"{"access":"AKIAIOSFODNN7EXAMPLE","secret":"wJalrXUtnFEMI"}"#.into(),
                r#type: "ec2".into(),
                project_id: Some(project.id.clone()),
                user_id: Some(user.id.clone()),
                ..Default::default()
            },
        )
        .await?;

    assert_eq!(
        cred.id,
        ec2_id("AKIAIOSFODNN7EXAMPLE"),
        "id is SHA-256(access)"
    );
    assert_eq!(cred.user_id, user.id);
    assert_eq!(cred.project_id, Some(project.id.clone()));
    assert_eq!(cred.r#type, "ec2");
    assert_eq!(
        cred.blob, r#"{"access":"AKIAIOSFODNN7EXAMPLE","secret":"wJalrXUtnFEMI"}"#,
        "blob round-trips as plaintext JSON string"
    );

    // Cleanup (create_credential returns a plain Credential, not a guard).
    state
        .provider
        .get_credential_provider()
        .delete_credential(&ExecutionContext::internal(&state), &cred.id)
        .await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_ec2_requires_project_id() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;

    let err = state
        .provider
        .get_credential_provider()
        .create_credential(
            &ExecutionContext::internal(&state),
            CredentialCreate {
                blob: r#"{"access":"AKIAIOSFODNN7EXAMPLE","secret":"s"}"#.into(),
                r#type: "ec2".into(),
                project_id: None,
                user_id: Some(user.id.clone()),
                ..Default::default()
            },
        )
        .await
        .expect_err("ec2 credential without project_id must be rejected");

    assert!(matches!(err, CredentialProviderError::MissingProjectId));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_totp_generates_uuid_id() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;

    let cred = state
        .provider
        .get_credential_provider()
        .create_credential(
            &ExecutionContext::internal(&state),
            CredentialCreate {
                blob: r#"{"seed":"JBSWY3DPEHPK3PXP","digits":6,"period":30}"#.into(),
                r#type: "totp".into(),
                user_id: Some(user.id.clone()),
                ..Default::default()
            },
        )
        .await?;

    assert!(
        Uuid::parse_str(&cred.id).is_ok(),
        "non-ec2 credential id is a random UUID, got {}",
        cred.id
    );
    assert_eq!(cred.project_id, None);

    state
        .provider
        .get_credential_provider()
        .delete_credential(&ExecutionContext::internal(&state), &cred.id)
        .await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_custom_type_with_extra() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;

    let mut extra = std::collections::HashMap::new();
    extra.insert(
        "note".to_string(),
        serde_json::json!("third-party integration"),
    );

    let cred = state
        .provider
        .get_credential_provider()
        .create_credential(
            &ExecutionContext::internal(&state),
            CredentialCreate {
                blob: r#"{"anything":"goes"}"#.into(),
                r#type: "my-custom-type".into(),
                user_id: Some(user.id.clone()),
                extra: Some(extra.clone()),
                ..Default::default()
            },
        )
        .await?;

    assert_eq!(cred.r#type, "my-custom-type");
    assert_eq!(cred.extra, Some(extra), "extra JSON round-trips");

    state
        .provider
        .get_credential_provider()
        .delete_credential(&ExecutionContext::internal(&state), &cred.id)
        .await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_requires_user_id_without_security_context() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    let err = state
        .provider
        .get_credential_provider()
        .create_credential(
            &ExecutionContext::internal(&state),
            CredentialCreate {
                blob: r#"{"seed":"JBSWY3DPEHPK3PXP"}"#.into(),
                r#type: "totp".into(),
                user_id: None,
                ..Default::default()
            },
        )
        .await
        .expect_err("internal calls have no security context to default user_id from");

    assert!(matches!(err, CredentialProviderError::MissingUserId));
    Ok(())
}
