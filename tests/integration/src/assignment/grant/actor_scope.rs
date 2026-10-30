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
//! Test the grant lifecycle (create, check, list, revoke) for the
//! `domain/user`, `domain/group` and `project/group` actor/target combinations
//! served by the `/domains/{id}/users/{id}/roles*`,
//! `/domains/{id}/groups/{id}/roles*` and `/projects/{id}/groups/{id}/roles*`
//! API endpoints.

use eyre::Result;
use std::collections::BTreeSet;
use tracing_test::traced_test;

use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::assignment::*;

use crate::assignment::check_grant;
use crate::common::get_state;
use crate::{create_domain, create_group, create_project, create_role, create_user};

async fn list_roles(
    state: &ServiceState,
    params: &RoleAssignmentListParameters,
) -> Result<BTreeSet<String>> {
    Ok(state
        .provider
        .get_assignment_provider()
        .list_role_assignments(&ExecutionContext::internal(state), params)
        .await?
        .into_iter()
        .map(|grant| grant.role_id)
        .collect())
}

fn assignment(
    r#type: AssignmentType,
    actor_id: &str,
    target_id: &str,
    role_id: &str,
) -> Result<Assignment> {
    Ok(AssignmentBuilder::default()
        .actor_id(actor_id)
        .target_id(target_id)
        .role_id(role_id)
        .r#type(r#type)
        .inherited(false)
        .build()?)
}

/// Run the whole lifecycle for one actor/target combination.
async fn lifecycle(
    state: &ServiceState,
    r#type: AssignmentType,
    create: fn(&str, &str, &str) -> AssignmentCreate,
    params: fn(&str, &str) -> RoleAssignmentListParameters,
    actor_id: &str,
    target_id: &str,
    other_actor_id: &str,
) -> Result<()> {
    let role_a = create_role!(state)?;
    let role_b = create_role!(state)?;
    let provider = state.provider.get_assignment_provider();
    let exec = ExecutionContext::internal(state);

    let grant_a = assignment(r#type.clone(), actor_id, target_id, &role_a.id)?;
    let grant_b = assignment(r#type.clone(), actor_id, target_id, &role_b.id)?;
    assert!(!check_grant(state, &grant_a).await?, "no grant yet");

    provider
        .create_grant(&exec, create(actor_id, target_id, &role_a.id))
        .await?;
    provider
        .create_grant(&exec, create(actor_id, target_id, &role_b.id))
        .await?;
    assert!(check_grant(state, &grant_a).await?);
    assert!(check_grant(state, &grant_b).await?);

    // Another actor on the same target must not be affected.
    assert!(
        list_roles(state, &params(other_actor_id, target_id))
            .await?
            .is_empty()
    );

    // Listing is non-effective and scoped to actor and target.
    let mut query = params(actor_id, target_id);
    query.effective = Some(false);
    assert_eq!(
        list_roles(state, &query).await?,
        BTreeSet::from([role_a.id.clone(), role_b.id.clone()])
    );

    // Revoke is specific to the revoked role only.
    provider.revoke_grant(&exec, grant_a.clone()).await?;
    assert!(!check_grant(state, &grant_a).await?);
    assert!(check_grant(state, &grant_b).await?);
    assert_eq!(
        list_roles(state, &query).await?,
        BTreeSet::from([role_b.id.clone()])
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_domain_user_grant_lifecycle() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;
    let other = create_user!(state, domain.id.clone())?;

    lifecycle(
        &state,
        AssignmentType::UserDomain,
        |a, t, r| AssignmentCreate::user_domain(a, t, r, false),
        |a, t| RoleAssignmentListParameters {
            user_id: Some(a.into()),
            domain_id: Some(t.into()),
            ..Default::default()
        },
        &user.id,
        &domain.id,
        &other.id,
    )
    .await
}

#[traced_test]
#[tokio::test]
async fn test_domain_group_grant_lifecycle() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let group = create_group!(state, domain.id.clone())?;
    let other = create_group!(state, domain.id.clone())?;

    lifecycle(
        &state,
        AssignmentType::GroupDomain,
        |a, t, r| AssignmentCreate::group_domain(a, t, r, false),
        |a, t| RoleAssignmentListParameters {
            group_id: Some(a.into()),
            domain_id: Some(t.into()),
            ..Default::default()
        },
        &group.id,
        &domain.id,
        &other.id,
    )
    .await
}

#[traced_test]
#[tokio::test]
async fn test_project_group_grant_lifecycle() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let group = create_group!(state, domain.id.clone())?;
    let other = create_group!(state, domain.id.clone())?;

    lifecycle(
        &state,
        AssignmentType::GroupProject,
        |a, t, r| AssignmentCreate::group_project(a, t, r, false),
        |a, t| RoleAssignmentListParameters {
            group_id: Some(a.into()),
            project_id: Some(t.into()),
            ..Default::default()
        },
        &group.id,
        &project.id,
        &other.id,
    )
    .await
}

/// A domain grant must not leak into the listing of a project (and vice
/// versa) even when the actor is the same.
#[traced_test]
#[tokio::test]
async fn test_group_domain_and_project_grants_are_isolated() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let group = create_group!(state, domain.id.clone())?;
    let role_d = create_role!(state)?;
    let role_p = create_role!(state)?;
    let provider = state.provider.get_assignment_provider();
    let exec = ExecutionContext::internal(&state);

    provider
        .create_grant(
            &exec,
            AssignmentCreate::group_domain(&group.id, &domain.id, &role_d.id, false),
        )
        .await?;
    provider
        .create_grant(
            &exec,
            AssignmentCreate::group_project(&group.id, &project.id, &role_p.id, false),
        )
        .await?;

    assert_eq!(
        list_roles(
            &state,
            &RoleAssignmentListParameters {
                group_id: Some(group.id.clone()),
                domain_id: Some(domain.id.clone()),
                effective: Some(false),
                ..Default::default()
            }
        )
        .await?,
        BTreeSet::from([role_d.id.clone()])
    );
    assert_eq!(
        list_roles(
            &state,
            &RoleAssignmentListParameters {
                group_id: Some(group.id.clone()),
                project_id: Some(project.id.clone()),
                effective: Some(false),
                ..Default::default()
            }
        )
        .await?,
        BTreeSet::from([role_p.id.clone()])
    );
    Ok(())
}
