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

//! Test role assignment revocation.

use eyre::Result;
use std::ops::Deref;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone::application_credential::ApplicationCredentialApi;
use openstack_keystone::assignment::AssignmentApi;
use openstack_keystone::auth::*;
use openstack_keystone::token::{TokenApi, TokenProviderError};
use openstack_keystone_core_types::application_credential::*;
use openstack_keystone_core_types::assignment::*;
use openstack_keystone_core_types::resource::*;
use openstack_keystone_core_types::role::*;

use crate::assignment::{check_grant, grant_role_to_user_on_project};
use crate::common::get_state;
use crate::{create_domain, create_project, create_role, create_user};

#[traced_test]
#[tokio::test]
async fn test_revoke_user_project_grant() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let role_a = create_role!(state)?;
    let role_b = create_role!(state)?;
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role_a.id).await?;
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role_b.id).await?;

    let assignment = AssignmentBuilder::default()
        .actor_id(user.id.clone())
        .target_id(project.id.clone())
        .role_id(role_b.id.clone())
        .r#type(AssignmentType::UserProject)
        .build()?;

    assert!(
        check_grant(&state, &assignment).await?,
        "Grant should exist"
    );

    // Revoke the grant
    state
        .provider
        .get_assignment_provider()
        .revoke_grant(&state, assignment.clone())
        .await?;

    // Verify grant no longer exists
    assert!(
        !check_grant(&state, &assignment).await?,
        "Grant should not exist after revocation"
    );

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_revoke_user_project_grant_auth_impact() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    // Create two roles: one that will be granted and revoked, and another to
    // confirm that revocation is specific
    let role_a = create_role!(state)?;
    let role_b = create_role!(state)?;
    // Grant first role that will be revoked
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role_a.id).await?;
    // Grant second role that will remain unaffected
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role_b.id).await?;

    let assignment_a = AssignmentBuilder::default()
        .actor_id(user.id.clone())
        .target_id(project.id.clone())
        .role_id(role_a.id.clone())
        .r#type(AssignmentType::UserProject)
        .build()?;
    let assignment_b = AssignmentBuilder::default()
        .actor_id(user.id.clone())
        .target_id(project.id.clone())
        .role_id(role_b.id.clone())
        .r#type(AssignmentType::UserProject)
        .build()?;

    assert!(
        check_grant(&state, &assignment_a).await?,
        "Grant should exist"
    );
    assert!(
        check_grant(&state, &assignment_b).await?,
        "Grant should exist"
    );

    // Create application credential and issue a token BEFORE revocation
    let cred: ApplicationCredentialCreateResponse = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &state,
            ApplicationCredentialCreate {
                access_rules: None,
                name: Uuid::new_v4().to_string(),
                project_id: project.id.clone(),
                roles: vec![RoleRef::from(role_a.deref()), RoleRef::from(role_b.deref())],
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    let authz = AuthzInfo::Project(
        ProjectBuilder::default()
            .id(cred.project_id.clone())
            .name(project.id.clone())
            .domain_id(project.domain_id.clone())
            .enabled(true)
            .build()?,
    );

    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::ApplicationCredential(
            cred.clone().into(),
        ))
        .principal(PrincipalInfo {
            domain_id: Some(user.domain_id.clone()),
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user.id.clone())
                    .user(user.clone())
                    .build()?,
            ),
        })
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(auth).unwrap();
    let pre_revoke_token = state
        .provider
        .get_token_provider()
        .issue_token(&ctx, &authz.clone())?;
    let pre_revoke_encoded = state
        .provider
        .get_token_provider()
        .encode_token(&pre_revoke_token)?;

    // Sanity check: token is valid before revocation
    assert!(
        state
            .provider
            .get_token_provider()
            .validate_token(&state, &pre_revoke_encoded, None, None)
            .await
            .is_ok(),
        "Token should be valid before revocation"
    );

    // --- Revoke the grant ---
    state
        .provider
        .get_assignment_provider()
        .revoke_grant(&state, assignment_a.clone())
        .await?;
    // CHECK 1: listing roles no longer returns the revoked role
    assert!(
        !check_grant(&state, &assignment_a).await?,
        "Grant should not exist after revocation"
    );

    // CHECK 2: existing auth (issued before revocation) is no longer accepted
    assert!(
        matches!(
            state
                .provider
                .get_token_provider()
                .validate_token(&state, &pre_revoke_encoded, None, None)
                .await,
            Err(TokenProviderError::TokenRevoked)
        ),
        "Pre-revocation token should fail validation after grant is revoked"
    );

    // CHECK 3: new auth does not obtain the role
    // token revocation is working with a seconds precision we need to wait for a
    // new second before granting new token to prevent it being also eventually
    // revoked
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let post_revoke_token = state
        .provider
        .get_token_provider()
        .issue_token(&ctx, &authz)?;
    let post_revoke_encoded = state
        .provider
        .get_token_provider()
        .encode_token(&post_revoke_token)?;

    let validated = state
        .provider
        .get_token_provider()
        .validate_token(&state, &post_revoke_encoded, None, None)
        .await?;

    let roles = validated
        .effective_roles()
        .expect("Token should have effective roles");

    assert!(roles.iter().any(|r| r.id == role_b.id));
    assert!(!roles.iter().any(|r| r.id == role_a.id));
    Ok(())
}
