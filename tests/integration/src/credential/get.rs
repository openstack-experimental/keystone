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
//! Test credential retrieval, including the EC2 plaintext-access-key lookup
//! used by the OS-EC2 legacy endpoints and `/v3/ec2tokens` (ADR 0019 §3, §5).

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::credential::*;

use crate::credential::{create_credential, get_state};
use crate::{create_domain, create_project, create_user};

#[tokio::test]
#[traced_test]
async fn test_get_found() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;

    let created = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"seed":"JBSWY3DPEHPK3PXP"}"#.into(),
            r#type: "totp".into(),
            user_id: Some(user.id.clone()),
            ..Default::default()
        },
    )
    .await?;

    let fetched = state
        .provider
        .get_credential_provider()
        .get_credential(&ExecutionContext::internal(&state), &created.id)
        .await?
        .expect("credential is found");

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.blob, created.blob);
    assert_eq!(fetched.user_id, created.user_id);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_get_not_found() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    let fetched = state
        .provider
        .get_credential_provider()
        .get_credential(&ExecutionContext::internal(&state), "does-not-exist")
        .await?;

    assert!(fetched.is_none());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_get_by_ec2_access() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;

    let created = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"access":"AKIAIOSFODNN7EXAMPLE","secret":"wJalrXUtnFEMI"}"#.into(),
            r#type: "ec2".into(),
            project_id: Some(project.id.clone()),
            user_id: Some(user.id.clone()),
            ..Default::default()
        },
    )
    .await?;

    let fetched = state
        .provider
        .get_credential_provider()
        .get_credential_by_ec2_access(&ExecutionContext::internal(&state), "AKIAIOSFODNN7EXAMPLE")
        .await?
        .expect("credential is found by plaintext access key");

    assert_eq!(fetched.id, created.id);

    let missing = state
        .provider
        .get_credential_provider()
        .get_credential_by_ec2_access(&ExecutionContext::internal(&state), "NOT-A-REAL-KEY")
        .await?;
    assert!(missing.is_none());
    Ok(())
}
