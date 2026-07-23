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
//! Test trust creation.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::trust::TrustProviderError;
use openstack_keystone_core_types::role::RoleRef;
use openstack_keystone_core_types::trust::TrustCreateBuilder;

use crate::assignment::grant_role_to_user_on_project;
use crate::common::get_state;
use crate::trust::create_trust;
use crate::{create_domain, create_project, create_role, create_user};

#[traced_test]
#[tokio::test]
async fn test_create_unscoped() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let trustor = create_user!(state, domain.id.clone())?;
    let trustee = create_user!(state, domain.id.clone())?;

    let trust = create_trust(
        &state,
        TrustCreateBuilder::default()
            .trustor_user_id(trustor.id.clone())
            .trustee_user_id(trustee.id.clone())
            .impersonation(false)
            .build()?,
    )
    .await?;

    // An ID is generated when none is provided.
    assert!(!trust.id.is_empty());
    assert_eq!(trust.trustor_user_id, trustor.id);
    assert_eq!(trust.trustee_user_id, trustee.id);
    assert!(trust.project_id.is_none());
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_with_granted_roles() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let trustor = create_user!(state, domain.id.clone())?;
    let trustee = create_user!(state, domain.id.clone())?;
    let role = create_role!(state)?;

    grant_role_to_user_on_project(
        &state,
        trustor.id.clone(),
        project.id.clone(),
        role.id.clone(),
    )
    .await?;

    let trust = create_trust(
        &state,
        TrustCreateBuilder::default()
            .trustor_user_id(trustor.id.clone())
            .trustee_user_id(trustee.id.clone())
            .project_id(project.id.clone())
            .impersonation(false)
            .roles(vec![RoleRef {
                id: role.id.clone(),
                name: None,
                domain_id: None,
            }])
            .build()?,
    )
    .await?;

    assert_eq!(trust.project_id.as_deref(), Some(project.id.as_str()));
    let trust_role_ids: Vec<&str> = trust
        .roles
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    assert!(trust_role_ids.contains(&role.id.as_str()));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_role_not_granted() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let trustor = create_user!(state, domain.id.clone())?;
    let trustee = create_user!(state, domain.id.clone())?;
    let role = create_role!(state)?;

    // The trustor never received this role on the project.
    let result = state
        .provider
        .get_trust_provider()
        .create_trust(
            &ExecutionContext::internal(&state),
            TrustCreateBuilder::default()
                .trustor_user_id(trustor.id.clone())
                .trustee_user_id(trustee.id.clone())
                .project_id(project.id.clone())
                .impersonation(false)
                .roles(vec![RoleRef {
                    id: role.id.clone(),
                    name: None,
                    domain_id: None,
                }])
                .build()?,
        )
        .await;

    match result {
        Err(TrustProviderError::RoleNotGranted { role_id }) => {
            assert_eq!(role_id, role.id);
        }
        other => panic!("expected RoleNotGranted, got {:?}", other),
    }
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_project_without_roles_invalid() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let trustor = create_user!(state, domain.id.clone())?;
    let trustee = create_user!(state, domain.id.clone())?;

    let result = state
        .provider
        .get_trust_provider()
        .create_trust(
            &ExecutionContext::internal(&state),
            TrustCreateBuilder::default()
                .trustor_user_id(trustor.id.clone())
                .trustee_user_id(trustee.id.clone())
                .project_id(project.id.clone())
                .impersonation(false)
                .build()?,
        )
        .await;

    assert!(matches!(
        result,
        Err(TrustProviderError::ProjectRolesPairingInvalid)
    ));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_roles_without_project_invalid() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let trustor = create_user!(state, domain.id.clone())?;
    let trustee = create_user!(state, domain.id.clone())?;
    let role = create_role!(state)?;

    let result = state
        .provider
        .get_trust_provider()
        .create_trust(
            &ExecutionContext::internal(&state),
            TrustCreateBuilder::default()
                .trustor_user_id(trustor.id.clone())
                .trustee_user_id(trustee.id.clone())
                .impersonation(false)
                .roles(vec![RoleRef {
                    id: role.id.clone(),
                    name: None,
                    domain_id: None,
                }])
                .build()?,
        )
        .await;

    assert!(matches!(
        result,
        Err(TrustProviderError::ProjectRolesPairingInvalid)
    ));
    Ok(())
}
