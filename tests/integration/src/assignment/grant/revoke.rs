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

use super::get_state;
use crate::common::{create_role, create_user};
use eyre::Result;
use openstack_keystone::application_credential::ApplicationCredentialApi;
use openstack_keystone::application_credential::types::*;
use openstack_keystone::assignment::{AssignmentApi, types::*};
use openstack_keystone::auth::*;
use openstack_keystone::keystone::ServiceState;
use openstack_keystone::resource::types::ProjectBuilder;
use openstack_keystone::role::types::*;
use openstack_keystone::token::{TokenApi, TokenProviderError};
use tracing_test::traced_test;
use uuid::Uuid;
async fn grant_exists(
    state: &ServiceState,
    user_id: &str,
    target_id: &str,
    role_id: &str,
    is_project: bool,
) -> Result<bool> {
    // Build the query parameters based on whether it's project or domain
    let params = if is_project {
        RoleAssignmentListParametersBuilder::default()
            .user_id(user_id)
            .role_id(role_id)
            .project_id(target_id)
            .effective(false)
            .build()?
    } else {
        RoleAssignmentListParametersBuilder::default()
            .user_id(user_id)
            .role_id(role_id)
            .domain_id(target_id)
            .effective(false)
            .build()?
    };

    let assignments = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(state, &params)
        .await?;

    Ok(assignments.iter().any(|a| {
        a.role_id == role_id && a.actor_id == user_id && a.target_id == target_id && !a.inherited
    }))
}

#[traced_test]
#[tokio::test]
async fn test_revoke_user_project_grant() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    create_role(&state, "role_revoke_1").await?;

    // Create a direct grant
    let grant = state
        .provider
        .get_assignment_provider()
        .create_grant(
            &state,
            AssignmentCreate::user_project("user_a", "project_a", "role_revoke_1", false),
        )
        .await?;

    // Verify grant exists
    assert!(
        grant_exists(&state, "user_a", "project_a", "role_revoke_1", true).await?,
        "Grant should exist after creation"
    );

    // Revoke the grant
    state
        .provider
        .get_assignment_provider()
        .revoke_grant(&state, grant)
        .await?;

    // Verify grant no longer exists
    assert!(
        !grant_exists(&state, "user_a", "project_a", "role_revoke_1", true).await?,
        "Grant should not exist after revocation"
    );

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_revoke_user_project_grant_auth_impact() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    let user = create_user(&state, Some("user_a")).await?;
    create_role(&state, "role_revoke_auth").await?;

    // Grant role to user on project
    let grant = state
        .provider
        .get_assignment_provider()
        .create_grant(
            &state,
            AssignmentCreate::user_project(&user.id, "project_a", "role_revoke_auth", false),
        )
        .await?;

    assert!(
        grant_exists(&state, &user.id, "project_a", "role_revoke_auth", true).await?,
        "Grant should exist after creation"
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
                project_id: "project_a".into(),
                roles: vec![Role {
                    id: "role_revoke_auth".into(),
                    name: "role_revoke_auth".into(),
                    ..Default::default()
                }],
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    let authz = AuthzInfo::Project(
        ProjectBuilder::default()
            .id(cred.project_id.clone())
            .name("project_a")
            .domain_id("domain_a")
            .enabled(true)
            .build()?,
    );

    let pre_revoke_token = state.provider.get_token_provider().issue_token(
        AuthenticatedInfoBuilder::default()
            .application_credential(cred.clone())
            .user_id(user.id.clone())
            .user(user.clone())
            .methods(vec!["application_credential".into()])
            .build()?,
        authz.clone(),
        None,
    )?;
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
        .revoke_grant(&state, grant)
        .await?;

    // CHECK 1: listing roles no longer returns the revoked role
    assert!(
        !grant_exists(&state, &user.id, "project_a", "role_revoke_auth", true).await?,
        "Grant should not exist after revocation"
    );

    // CHECK 2: new auth does not obtain the role
    let post_revoke_token = state.provider.get_token_provider().issue_token(
        AuthenticatedInfoBuilder::default()
            .application_credential(cred.clone())
            .user_id(user.id.clone())
            .user(user.clone())
            .methods(vec!["application_credential".into()])
            .build()?,
        authz,
        None,
    )?;
    let post_revoke_encoded = state
        .provider
        .get_token_provider()
        .encode_token(&post_revoke_token)?;

    assert!(
        matches!(
            state
                .provider
                .get_token_provider()
                .validate_token(&state, &post_revoke_encoded, None, None)
                .await,
            Err(TokenProviderError::ActorHasNoRolesOnTarget)
        ),
        "New token after revocation should fail validation"
    );

    // CHECK 3: existing auth (issued before revocation) is no longer accepted
    assert!(
        matches!(
            state
                .provider
                .get_token_provider()
                .validate_token(&state, &pre_revoke_encoded, None, None)
                .await,
            Err(TokenProviderError::ActorHasNoRolesOnTarget)
        ),
        "Pre-revocation token should fail validation after grant is revoked"
    );

    Ok(())
}
