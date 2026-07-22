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
//! Test project update.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::resource::ProjectUpdateBuilder;

use crate::common::get_state;
use crate::{create_domain, create_project};

#[traced_test]
#[tokio::test]
async fn test_update() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, &domain.id)?;

    let updated = state
        .provider
        .get_resource_provider()
        .update_project(
            &ExecutionContext::internal(&state),
            &project.id,
            ProjectUpdateBuilder::default()
                .name("updated_name")
                .enabled(false)
                .build()?,
        )
        .await?;

    assert_eq!(updated.name, "updated_name");
    assert!(!updated.enabled);

    let fetched = state
        .provider
        .get_resource_provider()
        .get_project(&ExecutionContext::internal(&state), &project.id)
        .await?
        .expect("project should still exist");
    assert_eq!(fetched.name, "updated_name");
    assert!(!fetched.enabled);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_not_found() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    let result = state
        .provider
        .get_resource_provider()
        .update_project(
            &ExecutionContext::internal(&state),
            "missing_project_id",
            ProjectUpdateBuilder::default().name("new_name").build()?,
        )
        .await;

    assert!(result.is_err());

    Ok(())
}
