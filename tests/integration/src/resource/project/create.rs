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
//! Test project creation.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::resource::ProjectCreateBuilder;

use crate::common::get_state;
use crate::create_domain;
use crate::create_project;

#[traced_test]
#[tokio::test]
async fn test_create() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;

    assert!(!project.name.is_empty());
    assert_eq!(project.domain_id, domain.id);
    assert!(project.enabled);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_invalid_name_too_long() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    let result = state
        .provider
        .get_resource_provider()
        .create_project(
            &ExecutionContext::internal(&state),
            ProjectCreateBuilder::default()
                .name("x".repeat(256))
                .domain_id(domain.id.clone())
                .build()?,
        )
        .await;
    assert!(
        result.is_err(),
        "creating a project with an over-length name is rejected"
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_invalid_empty_name() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    let result = state
        .provider
        .get_resource_provider()
        .create_project(
            &ExecutionContext::internal(&state),
            ProjectCreateBuilder::default()
                .name("")
                .domain_id(domain.id.clone())
                .build()?,
        )
        .await;
    assert!(
        result.is_err(),
        "creating a project with an empty name is rejected"
    );
    Ok(())
}
