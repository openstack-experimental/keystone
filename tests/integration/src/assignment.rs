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
use eyre::Result;
use std::sync::Arc;

use openstack_keystone::assignment::AssignmentApi;
use openstack_keystone::keystone::Service;
use openstack_keystone_core_types::assignment::*;

mod grant;

pub async fn grant_role_to_user_on_project<U: Into<String>, P: Into<String>, R: Into<String>>(
    state: &Arc<Service>,
    user: U,
    project: P,
    role: R,
) -> Result<()> {
    state
        .provider
        .get_assignment_provider()
        .create_grant(
            state,
            AssignmentCreate::user_project(user, project, role, false),
        )
        .await?;
    Ok(())
}

pub async fn check_grant(state: &Arc<Service>, assignment: &Assignment) -> Result<bool> {
    let mut params = RoleAssignmentListParametersBuilder::default();
    params.role_id(assignment.role_id.clone());
    match assignment.r#type {
        AssignmentType::GroupDomain => {
            params.domain_id(assignment.target_id.clone());
            params.group_id(assignment.actor_id.clone());
        }
        AssignmentType::GroupProject => {
            params.project_id(assignment.target_id.clone());
            params.group_id(assignment.actor_id.clone());
        }
        AssignmentType::GroupSystem => {
            params.system_id(assignment.target_id.clone());
            params.group_id(assignment.actor_id.clone());
        }
        AssignmentType::UserDomain => {
            params.domain_id(assignment.target_id.clone());
            params.user_id(assignment.actor_id.clone());
        }
        AssignmentType::UserProject => {
            params.project_id(assignment.target_id.clone());
            params.user_id(assignment.actor_id.clone());
        }
        AssignmentType::UserSystem => {
            params.system_id(assignment.target_id.clone());
            params.user_id(assignment.actor_id.clone());
        }
    }
    let assignments = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(state, &params.build()?)
        .await?;
    Ok(!assignments.is_empty())
}
