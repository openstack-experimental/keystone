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
//! Test credential update: blob re-encryption and the immutable-field
//! guardrails from ADR 0019 §2 (CVE-2020-12691).

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::credential::*;

use crate::credential::{create_credential, get_state};
use crate::{create_domain, create_project, create_user};

#[tokio::test]
#[traced_test]
async fn test_update_blob_re_encrypts_and_persists() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;

    let created = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"access":"AKIAIOSFODNN7EXAMPLE","secret":"old-secret"}"#.into(),
            r#type: "ec2".into(),
            project_id: Some(project.id.clone()),
            user_id: Some(user.id.clone()),
            ..Default::default()
        },
    )
    .await?;

    let updated = state
        .provider
        .get_credential_provider()
        .update_credential(
            &ExecutionContext::internal(&state),
            &created.id,
            CredentialUpdate {
                blob: Some(r#"{"access":"AKIAIOSFODNN7EXAMPLE","secret":"new-secret"}"#.into()),
                ..Default::default()
            },
        )
        .await?;

    assert_eq!(
        updated.blob,
        r#"{"access":"AKIAIOSFODNN7EXAMPLE","secret":"new-secret"}"#
    );

    // Re-fetch to confirm the new blob was actually persisted (re-encrypted
    // and decrypted back), not just returned from the update call.
    let fetched = state
        .provider
        .get_credential_provider()
        .get_credential(&ExecutionContext::internal(&state), &created.id)
        .await?
        .expect("credential still exists");
    assert_eq!(fetched.blob, updated.blob);

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_rejects_change_to_ec2_access() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;

    let created = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"access":"AKIAIOSFODNN7EXAMPLE","secret":"s"}"#.into(),
            r#type: "ec2".into(),
            project_id: Some(project.id.clone()),
            user_id: Some(user.id.clone()),
            ..Default::default()
        },
    )
    .await?;

    let err = state
        .provider
        .get_credential_provider()
        .update_credential(
            &ExecutionContext::internal(&state),
            &created.id,
            CredentialUpdate {
                // Changing `access` would desynchronize the record from its
                // SHA-256-derived id — must be rejected.
                blob: Some(r#"{"access":"AKIADIFFERENTKEY0000","secret":"s"}"#.into()),
                ..Default::default()
            },
        )
        .await
        .expect_err("changing the EC2 access key via update must be rejected");

    assert!(matches!(err, CredentialProviderError::ImmutableField(f) if f == "access"));

    // Original blob must be untouched.
    let fetched = state
        .provider
        .get_credential_provider()
        .get_credential(&ExecutionContext::internal(&state), &created.id)
        .await?
        .expect("credential still exists");
    assert_eq!(fetched.blob, created.blob);

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_project_id() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project_a = create_project!(state, domain.id.clone())?;
    let project_b = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;

    let created = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"access":"AKIAIOSFODNN7EXAMPLE","secret":"s"}"#.into(),
            r#type: "ec2".into(),
            project_id: Some(project_a.id.clone()),
            user_id: Some(user.id.clone()),
            ..Default::default()
        },
    )
    .await?;

    let updated = state
        .provider
        .get_credential_provider()
        .update_credential(
            &ExecutionContext::internal(&state),
            &created.id,
            CredentialUpdate {
                project_id: Some(project_b.id.clone()),
                ..Default::default()
            },
        )
        .await?;

    assert_eq!(updated.project_id, Some(project_b.id.clone()));

    Ok(())
}
