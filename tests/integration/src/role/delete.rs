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
//! Test role delete.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::role::{RoleOptionsBuilder, RoleUpdateBuilder};

use crate::assignment::{check_grant, grant_role_to_user_on_project};
use crate::common::get_state;
use crate::{create_domain, create_project, create_role, create_user};
use openstack_keystone_core_types::assignment::{Assignment, AssignmentBuilder, AssignmentType};

#[traced_test]
#[tokio::test]
async fn test_delete() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let role = create_role!(state)?;

    state
        .provider
        .get_role_provider()
        .delete_role(&ExecutionContext::internal(&state), &role.id)
        .await?;
    assert!(
        state
            .provider
            .get_role_provider()
            .get_role(&ExecutionContext::internal(&state), &role.id)
            .await?
            .is_none()
    );
    Ok(())
}

/// Deleting a role revokes the assignments of the role.
#[traced_test]
#[tokio::test]
async fn test_delete_revokes_assignments() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;
    let project = create_project!(state, domain.id.clone())?;
    let role = create_role!(state)?;
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role.id).await?;
    let grant: Assignment = AssignmentBuilder::default()
        .actor_id(user.id.clone())
        .role_id(role.id.clone())
        .target_id(project.id.clone())
        .r#type(AssignmentType::UserProject)
        .build()?;
    assert!(check_grant(&state, &grant).await?);

    state
        .provider
        .get_role_provider()
        .delete_role(&ExecutionContext::internal(&state), &role.id)
        .await?;

    assert!(!check_grant(&state, &grant).await?);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_delete_blocked_when_immutable() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let role = create_role!(state)?;

    state
        .provider
        .get_role_provider()
        .update_role(
            &ExecutionContext::internal(&state),
            &role.id,
            RoleUpdateBuilder::default()
                .options(RoleOptionsBuilder::default().immutable(true).build()?)
                .build()?,
        )
        .await?;

    let result = state
        .provider
        .get_role_provider()
        .delete_role(&ExecutionContext::internal(&state), &role.id)
        .await;
    assert!(result.is_err(), "delete of an immutable role is rejected");

    state
        .provider
        .get_role_provider()
        .update_role(
            &ExecutionContext::internal(&state),
            &role.id,
            RoleUpdateBuilder::default()
                .options(RoleOptionsBuilder::default().immutable(false).build()?)
                .build()?,
        )
        .await?;

    state
        .provider
        .get_role_provider()
        .delete_role(&ExecutionContext::internal(&state), &role.id)
        .await?;
    assert!(
        state
            .provider
            .get_role_provider()
            .get_role(&ExecutionContext::internal(&state), &role.id)
            .await?
            .is_none()
    );
    Ok(())
}
