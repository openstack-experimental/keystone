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
use std::sync::Arc;

use eyre::Result;
use uuid::Uuid;

use openstack_keystone_api_types::v3::project::*;
use openstack_sdk::AsyncOpenStack;

use test_api::guard::ResourceGuard;
use test_api::resource::domain::*;
use test_api::resource::project::*;
use test_api::resource::*;

#[tokio::test]
async fn test_project_create() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&test_client).await?;
    let project = create_project(
        &test_client,
        ProjectCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;
    assert!(!project.id.is_empty(), "project id should not be empty");
    assert!(project.enabled, "project should be enabled by default");
    assert_eq!(project.domain_id, domain.id);
    project.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_project_show() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&test_client).await?;
    let project = create_project(
        &test_client,
        ProjectCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;
    let shown = get_project(&test_client, &project.id).await?;
    assert_eq!(shown.id, project.id);
    assert_eq!(shown.name, project.name);
    assert_eq!(shown.domain_id, domain.id);
    project.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_project_list() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&test_client).await?;
    let project = create_project(
        &test_client,
        ProjectCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;
    let params = ProjectListRequest {
        domain_id: Some(domain.id.clone()),
        ids: Some(project.id.clone()),
        name: None,
    };
    let projects = list_projects(&test_client, params).await?;
    assert!(
        !projects.is_empty(),
        "project list should contain the created project"
    );
    assert_eq!(projects[0].id, project.id);
    project.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_project_update() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&test_client).await?;
    let project = create_project(
        &test_client,
        ProjectCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;
    let updated = update_project(
        &test_client,
        &project.id,
        ProjectUpdateBuilder::default()
            .name("updated_name")
            .enabled(false)
            .build()?,
    )
    .await?;
    assert_eq!(updated.name, "updated_name");
    assert!(!updated.enabled);

    let shown = get_project(&test_client, &project.id).await?;
    assert_eq!(shown.name, "updated_name");
    assert!(!shown.enabled);

    project.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_project_delete() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&test_client).await?;
    let project = create_project(
        &test_client,
        ProjectCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;
    delete_project(&test_client, &project.id).await?;
    let result = get_project(&test_client, &project.id).await;
    assert!(result.is_err(), "project should be deleted");
    domain.delete().await?;
    Ok(())
}
