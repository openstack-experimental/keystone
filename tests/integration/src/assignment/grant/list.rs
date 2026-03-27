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
//! Test role assignments.

use eyre::Result;
use std::collections::BTreeSet;
use tracing_test::traced_test;

use openstack_keystone::assignment::AssignmentApi;
use openstack_keystone::identity::IdentityApi;
use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core_types::assignment::*;

use crate::common::get_state;
use crate::{create_domain, create_group, create_project, create_role, create_user};

async fn list_grants(
    state: &ServiceState,
    params: &RoleAssignmentListParameters,
) -> Result<BTreeSet<String>> {
    Ok(state
        .provider
        .get_assignment_provider()
        .list_role_assignments(state, params)
        .await?
        .into_iter()
        .map(|grant| grant.role_id)
        .collect())
}

#[traced_test]
#[tokio::test]
async fn test_list_user_roles() -> Result<()> {
    let (state, _) = get_state().await?;

    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let project_a1 = create_project!(state, domain.id.clone(), project.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let group = create_group!(state, domain.id.clone())?;
    let role_a = create_role!(state)?;
    let role_b = create_role!(state)?;
    let role_c = create_role!(state)?;
    let role_d = create_role!(state)?;
    let role_ga = create_role!(state)?;
    let role_gb = create_role!(state)?;
    let role_gc = create_role!(state)?;
    let role_gd = create_role!(state)?;

    state
        .provider
        .get_identity_provider()
        .add_user_to_group(&state, &user.id, &group.id)
        .await?;
    for assignment in [
        AssignmentCreate::user_domain(&user.id, &domain.id, &role_a.id, false),
        AssignmentCreate::group_domain(&group.id, &domain.id, &role_ga.id, false),
        AssignmentCreate::user_domain(&user.id, &domain.id, &role_b.id, true),
        AssignmentCreate::group_domain(&group.id, &domain.id, &role_gb.id, true),
        AssignmentCreate::user_project(&user.id, &project.id, &role_c.id, false),
        AssignmentCreate::group_project(&group.id, &project.id, &role_gc.id, false),
        AssignmentCreate::user_project(&user.id, &project.id, &role_d.id, true),
        AssignmentCreate::group_project(&group.id, &project.id, &role_gd.id, true),
    ] {
        state
            .provider
            .get_assignment_provider()
            .create_grant(&state, assignment)
            .await?;
    }

    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id(user.id.clone())
                .domain_id(domain.id.clone())
                .build()?,
        )
        .await?,
        BTreeSet::from([role_a.id.clone()]),
        "user has only role_a on the domain"
    );
    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id(user.id.clone())
                .domain_id(domain.id.clone())
                .effective(true)
                .build()?,
        )
        .await?,
        BTreeSet::from([role_a.id.clone(), role_ga.id.clone()]),
        "user has role_a, role_ga on the domain"
    );
    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .group_id(group.id.clone())
                .domain_id(domain.id.clone())
                .effective(true)
                .build()?,
        )
        .await?,
        BTreeSet::from([role_a.id.clone(), role_ga.id.clone()]),
        "group has role_ga on the domain"
    );
    //    Ok(())
    //}
    //
    //#[tokio::test]
    //async fn test_list_user_tl_project() -> Result<()> {
    //    let (state, _) = get_state().await?;
    //    init_data(&state).await?;

    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id(user.id.clone())
                .project_id(project.id.clone())
                .effective(false)
                .build()?,
        )
        .await?,
        BTreeSet::from([role_b.id.clone(), role_c.id.clone()]),
        "user has role_b [{}] inherited from the domain and direct role_c [{}] on the TL project (direct)",
        role_b.id.clone(),
        role_c.id.clone()
    );
    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id(user.id.clone())
                .project_id(project.id.clone())
                .effective(true)
                .build()?,
        )
        .await?,
        BTreeSet::from([
            role_b.id.clone(),
            role_c.id.clone(),
            role_gb.id.clone(),
            role_gc.id.clone()
        ]),
        "user has role_b inherited from the domain on the TL project (effective)"
    );
    //    Ok(())
    //}
    //
    //#[tokio::test]
    //async fn test_list_user_sub_project() -> Result<()> {
    //    let (state, _) = get_state().await?;
    //    init_data(&state).await?;

    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id(user.id.clone())
                .project_id(project_a1.id.clone())
                .effective(false)
                .build()?,
        )
        .await?,
        BTreeSet::from([role_b.id.clone(), role_d.id.clone()]),
        "user has only inherited roles on the subproject (effective)"
    );
    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id(user.id.clone())
                .project_id(project_a1.id.clone())
                .effective(true)
                .build()?,
        )
        .await?,
        BTreeSet::from([
            role_b.id.clone(),
            role_d.id.clone(),
            role_gb.id.clone(),
            role_gd.id.clone()
        ]),
        "user has only inherited roles and groups expanded on the subproject (effective)"
    );
    Ok(())
}
