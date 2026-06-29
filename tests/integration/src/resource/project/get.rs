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
//! Test project get.

use eyre::Result;
use tracing_test::traced_test;

use crate::common::get_state;
use crate::create_domain;
use crate::create_project;
use openstack_keystone_core::auth::ExecutionContext;

#[traced_test]
#[tokio::test]
async fn test_get_project() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;

    let res = state
        .provider
        .get_resource_provider()
        .get_project(&ExecutionContext::internal(&state), &project.id)
        .await?
        .expect("project should be there");
    assert_eq!(res.id, project.id);
    assert_eq!(res.name, project.name);
    assert_eq!(res.domain_id, project.domain_id);
    assert_eq!(res.enabled, project.enabled);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_project_missing() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    assert!(
        state
            .provider
            .get_resource_provider()
            .get_project(
                &ExecutionContext::internal(&state),
                &uuid::Uuid::new_v4().to_string()
            )
            .await?
            .is_none()
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_project_by_name() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;

    let res = state
        .provider
        .get_resource_provider()
        .get_project_by_name(
            &ExecutionContext::internal(&state),
            &project.name,
            &domain.id,
        )
        .await?
        .expect("project found by name");
    assert_eq!(res.id, project.id);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_project_by_name_missing() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    let res = state
        .provider
        .get_resource_provider()
        .get_project_by_name(
            &ExecutionContext::internal(&state),
            "no-such-project",
            &domain.id,
        )
        .await?;
    assert!(res.is_none(), "an unknown project name returns None");
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_project_parents() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let parent = create_project!(state, domain.id.clone())?;
    let child = create_project!(state, domain.id.clone(), parent.id.clone())?;

    let parents = state
        .provider
        .get_resource_provider()
        .get_project_parents(&ExecutionContext::internal(&state), &child.id)
        .await?
        .expect("parents returned");
    assert!(
        parents.iter().any(|p| p.id == parent.id),
        "the parent project is in the chain"
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_project_parents_multi_level() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let grandparent = create_project!(state, domain.id.clone())?;
    let parent = create_project!(state, domain.id.clone(), grandparent.id.clone())?;
    let child = create_project!(state, domain.id.clone(), parent.id.clone())?;

    let parents = state
        .provider
        .get_resource_provider()
        .get_project_parents(&ExecutionContext::internal(&state), &child.id)
        .await?
        .expect("parents returned");
    assert!(
        parents.iter().any(|p| p.id == parent.id),
        "the parent project is in the ancestor chain"
    );
    assert!(
        parents.iter().any(|p| p.id == grandparent.id),
        "the grandparent project is in the ancestor chain"
    );
    Ok(())
}
