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

use openstack_keystone::assignment::{AssignmentApi, types::*};
use openstack_keystone::identity::IdentityApi;
use openstack_keystone::keystone::ServiceState;

use super::get_state;
use crate::common::{create_group, create_role, create_user};

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

async fn init_data(state: &ServiceState) -> Result<()> {
    create_user(&state, Some("user_a")).await?;
    create_group(&state, Some("group_a")).await?;
    state
        .provider
        .get_identity_provider()
        .add_user_to_group(state, "user_a", "group_a")
        .await?;
    for role in [
        "role_a", "role_b", "role_c", "role_d", "role_ga", "role_gb", "role_gc", "role_gd",
    ] {
        create_role(state, role).await?;
    }
    for assignment in [
        Assignment::user_domain("user_a", "domain_a", "role_a", false),
        Assignment::group_domain("group_a", "domain_a", "role_ga", false),
        Assignment::user_domain("user_a", "domain_a", "role_b", true),
        Assignment::group_domain("group_a", "domain_a", "role_gb", true),
        Assignment::user_project("user_a", "project_a", "role_c", false),
        Assignment::group_project("group_a", "project_a", "role_gc", false),
        Assignment::user_project("user_a", "project_a", "role_d", true),
        Assignment::group_project("group_a", "project_a", "role_gd", true),
    ] {
        state
            .provider
            .get_assignment_provider()
            .create_grant(state, assignment)
            .await?;
    }
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_user_domain() -> Result<()> {
    let state = get_state().await?;
    init_data(&state).await?;

    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id("user_a")
                .domain_id("domain_a")
                .build()?,
        )
        .await?,
        BTreeSet::from(["role_a".into()]),
        "user has only role_a on the domain"
    );
    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id("user_a")
                .domain_id("domain_a")
                .effective(true)
                .build()?,
        )
        .await?,
        BTreeSet::from(["role_a".into(), "role_ga".into()]),
        "user has role_a, role_ga on the domain"
    );
    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .group_id("group_a")
                .domain_id("domain_a")
                .effective(true)
                .build()?,
        )
        .await?,
        BTreeSet::from(["role_a".into(), "role_ga".into()]),
        "group has role_ga on the domain"
    );
    Ok(())
}

#[tokio::test]
async fn test_list_user_tl_project() -> Result<()> {
    let state = get_state().await?;
    init_data(&state).await?;

    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id("user_a")
                .project_id("project_a")
                .effective(false)
                .build()?,
        )
        .await?,
        BTreeSet::from(["role_b".into(), "role_c".into()]),
        "user has role_b inherited from the domain and direct role_c on the TL project (direct)"
    );
    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id("user_a")
                .project_id("project_a")
                .effective(true)
                .build()?,
        )
        .await?,
        BTreeSet::from([
            "role_b".into(),
            "role_c".into(),
            "role_gb".into(),
            "role_gc".into()
        ]),
        "user has role_b inherited from the domain on the TL project (effective)"
    );
    Ok(())
}

#[tokio::test]
async fn test_list_user_sub_project() -> Result<()> {
    let state = get_state().await?;
    init_data(&state).await?;

    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id("user_a")
                .project_id("project_a_1")
                .effective(false)
                .build()?,
        )
        .await?,
        BTreeSet::from(["role_b".into(), "role_d".into()]),
        "user has only inherited roles on the subproject (effective)"
    );
    assert_eq!(
        list_grants(
            &state,
            &RoleAssignmentListParametersBuilder::default()
                .user_id("user_a")
                .project_id("project_a_1")
                .effective(true)
                .build()?,
        )
        .await?,
        BTreeSet::from([
            "role_b".into(),
            "role_d".into(),
            "role_gb".into(),
            "role_gd".into()
        ]),
        "user has only inherited roles and groups expanded on the subproject (effective)"
    );
    Ok(())
}
