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
use tracing_test::traced_test;

use super::get_state;
use crate::common::create_role;
use openstack_keystone::assignment::{AssignmentApi, types::*};
use openstack_keystone::keystone::ServiceState;

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
    let state = get_state().await?;
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
