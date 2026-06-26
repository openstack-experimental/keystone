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
//! Test project list.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::resource::*;

use crate::common::get_state;
use crate::create_domain;
use crate::create_project;

#[traced_test]
#[tokio::test]
async fn test_list() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let project2 = create_project!(state, domain.id.clone())?;

    let res = state
        .provider
        .get_resource_provider()
        .list_projects(
            &ExecutionContext::internal(&state),
            &ProjectListParameters::default(),
        )
        .await?;
    assert!(res.contains(&project.resource));
    assert!(res.contains(&project2.resource));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_by_id() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let project2 = create_project!(state, domain.id.clone())?;

    let res = state
        .provider
        .get_resource_provider()
        .list_projects(
            &ExecutionContext::internal(&state),
            &ProjectListParameters {
                ids: Some(std::collections::HashSet::from_iter(vec![
                    project.id.clone(),
                ])),
                ..Default::default()
            },
        )
        .await?;
    assert!(res.contains(&project.resource));
    assert!(!res.contains(&project2.resource));
    Ok(())
}
