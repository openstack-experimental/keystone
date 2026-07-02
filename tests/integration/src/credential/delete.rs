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
//! Test credential deletion, including the identity-lifecycle cascade
//! helpers (ADR 0019 §3): `delete_credentials_for_user` and
//! `delete_credentials_for_project`.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::credential::*;

use crate::credential::{create_credential, get_state};
use crate::{create_domain, create_project, create_user};

#[tokio::test]
#[traced_test]
async fn test_delete_by_id() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;

    let created = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"seed":"AAAA"}"#.into(),
            r#type: "totp".into(),
            user_id: Some(user.id.clone()),
            ..Default::default()
        },
    )
    .await?;
    let id = created.id.clone();
    // Detach the auto-cleanup guard since we're explicitly testing deletion.
    std::mem::forget(created);

    state
        .provider
        .get_credential_provider()
        .delete_credential(&ExecutionContext::internal(&state), &id)
        .await?;

    let fetched = state
        .provider
        .get_credential_provider()
        .get_credential(&ExecutionContext::internal(&state), &id)
        .await?;
    assert!(fetched.is_none(), "credential is gone after delete");

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_delete_credentials_for_user() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user_a = create_user!(state, domain.id.clone())?;
    let user_b = create_user!(state, domain.id.clone())?;

    let a1 = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"seed":"AAAA"}"#.into(),
            r#type: "totp".into(),
            user_id: Some(user_a.id.clone()),
            ..Default::default()
        },
    )
    .await?;
    let a2 = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"x":"y"}"#.into(),
            r#type: "custom".into(),
            user_id: Some(user_a.id.clone()),
            ..Default::default()
        },
    )
    .await?;
    let b1 = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"seed":"BBBB"}"#.into(),
            r#type: "totp".into(),
            user_id: Some(user_b.id.clone()),
            ..Default::default()
        },
    )
    .await?;
    let (a1_id, a2_id, b1_id) = (a1.id.clone(), a2.id.clone(), b1.id.clone());
    std::mem::forget(a1);
    std::mem::forget(a2);

    state
        .provider
        .get_credential_provider()
        .delete_credentials_for_user(&ExecutionContext::internal(&state), &user_a.id)
        .await?;

    let provider = state.provider.get_credential_provider();
    assert!(
        provider
            .get_credential(&ExecutionContext::internal(&state), &a1_id)
            .await?
            .is_none(),
        "user_a's totp credential was cascade-deleted"
    );
    assert!(
        provider
            .get_credential(&ExecutionContext::internal(&state), &a2_id)
            .await?
            .is_none(),
        "user_a's custom credential was cascade-deleted"
    );
    assert!(
        provider
            .get_credential(&ExecutionContext::internal(&state), &b1_id)
            .await?
            .is_some(),
        "user_b's credential is untouched"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_delete_credentials_for_project() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project_a = create_project!(state, domain.id.clone())?;
    let project_b = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;

    let ec2_a = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"access":"AKIAPROJECTA00000000","secret":"s"}"#.into(),
            r#type: "ec2".into(),
            project_id: Some(project_a.id.clone()),
            user_id: Some(user.id.clone()),
            ..Default::default()
        },
    )
    .await?;
    let ec2_b = create_credential(
        &state,
        CredentialCreate {
            blob: r#"{"access":"AKIAPROJECTB00000000","secret":"s"}"#.into(),
            r#type: "ec2".into(),
            project_id: Some(project_b.id.clone()),
            user_id: Some(user.id.clone()),
            ..Default::default()
        },
    )
    .await?;
    let (a_id, b_id) = (ec2_a.id.clone(), ec2_b.id.clone());
    std::mem::forget(ec2_a);

    state
        .provider
        .get_credential_provider()
        .delete_credentials_for_project(&ExecutionContext::internal(&state), &project_a.id)
        .await?;

    let provider = state.provider.get_credential_provider();
    assert!(
        provider
            .get_credential(&ExecutionContext::internal(&state), &a_id)
            .await?
            .is_none(),
        "project_a's ec2 credential was cascade-deleted"
    );
    assert!(
        provider
            .get_credential(&ExecutionContext::internal(&state), &b_id)
            .await?
            .is_some(),
        "project_b's ec2 credential is untouched"
    );

    // Cleanup remaining fixture.
    state
        .provider
        .get_credential_provider()
        .delete_credential(&ExecutionContext::internal(&state), &b_id)
        .await?;

    Ok(())
}
