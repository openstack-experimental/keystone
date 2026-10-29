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
async fn test_project_show_and_list_have_same_shape() -> Result<()> {
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
    let expected_link = format!("/v3/projects/{}", project.id);
    assert_eq!(
        project.links.as_ref().map(|l| l.self_link.as_str()),
        Some(expected_link.as_str())
    );
    let shown = get_project(&test_client, &project.id).await?;
    let listed = list_projects(
        &test_client,
        ProjectListRequest {
            domain_id: Some(domain.id.clone()),
            ids: Some(project.id.clone()),
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0], shown);
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
        ..Default::default()
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
async fn test_project_create_immutable_option() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&test_client).await?;
    let project = create_project(
        &test_client,
        ProjectCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .domain_id(domain.id.clone())
            .options(ProjectOptionsBuilder::default().immutable(true).build()?)
            .build()?,
    )
    .await?;
    assert_eq!(
        project.options.as_ref().and_then(|o| o.immutable),
        Some(true)
    );

    let shown = get_project(&test_client, &project.id).await?;
    assert_eq!(shown.options.as_ref().and_then(|o| o.immutable), Some(true));

    // Clear immutable so the guard-driven cleanup does not fail.
    update_project(
        &test_client,
        &project.id,
        ProjectUpdateBuilder::default()
            .options(ProjectOptionsBuilder::default().immutable(false).build()?)
            .build()?,
    )
    .await?;

    project.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_project_update_blocked_when_immutable() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&test_client).await?;
    let project = create_project(
        &test_client,
        ProjectCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .domain_id(domain.id.clone())
            .options(ProjectOptionsBuilder::default().immutable(true).build()?)
            .build()?,
    )
    .await?;

    let result = update_project(
        &test_client,
        &project.id,
        ProjectUpdateBuilder::default()
            .name("updated_name")
            .build()?,
    )
    .await;
    assert!(
        result.is_err(),
        "update of an immutable project is rejected"
    );

    update_project(
        &test_client,
        &project.id,
        ProjectUpdateBuilder::default()
            .options(ProjectOptionsBuilder::default().immutable(false).build()?)
            .build()?,
    )
    .await?;

    project.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_project_delete_blocked_when_immutable() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&test_client).await?;
    let project = create_project(
        &test_client,
        ProjectCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .domain_id(domain.id.clone())
            .options(ProjectOptionsBuilder::default().immutable(true).build()?)
            .build()?,
    )
    .await?;

    let result = delete_project(&test_client, &project.id).await;
    assert!(
        result.is_err(),
        "delete of an immutable project is rejected"
    );

    update_project(
        &test_client,
        &project.id,
        ProjectUpdateBuilder::default()
            .options(ProjectOptionsBuilder::default().immutable(false).build()?)
            .build()?,
    )
    .await?;

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

/// `GET /v3/projects?enabled=<bool>` returns only projects with a matching
/// flag.
#[tokio::test]
async fn test_project_list_filter_by_enabled() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&test_client).await?;
    let enabled_item = create_project(
        &test_client,
        ProjectCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(true)
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;
    let disabled_item = create_project(
        &test_client,
        ProjectCreateBuilder::default()
            .name(Uuid::new_v4().to_string())
            .enabled(false)
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;

    // Tempest sends Python-style capitalised booleans, so cover both
    // spellings.
    for (query, want_enabled) in [
        ("true", true),
        ("false", false),
        ("True", true),
        ("False", false),
    ] {
        let items = list_projects(
            &test_client,
            ProjectListRequest {
                domain_id: Some(domain.id.clone()),
                enabled: Some(query.to_string()),
                ..Default::default()
            },
        )
        .await?;
        assert!(
            items.iter().all(|i| i.enabled == want_enabled),
            "enabled={query}: every returned project must be enabled={want_enabled}"
        );
        let ids: Vec<&str> = items.iter().map(|i| i.id.as_str()).collect();
        let (present, absent) = if want_enabled {
            (&enabled_item.id, &disabled_item.id)
        } else {
            (&disabled_item.id, &enabled_item.id)
        };
        assert!(ids.contains(&present.as_str()), "enabled={query}");
        assert!(!ids.contains(&absent.as_str()), "enabled={query}");
    }

    enabled_item.delete().await?;
    disabled_item.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_project_create_name_too_long() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&test_client).await?;
    let res = create_project(
        &test_client,
        ProjectCreateBuilder::default()
            .name("a".repeat(65))
            .enabled(true)
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await;
    domain.delete().await?;
    test_api::asserts::assert_status(
        res.map(|p| p.id.clone()),
        http::StatusCode::BAD_REQUEST,
        "project name longer than 64 characters must be rejected",
    );
    Ok(())
}

fn hierarchy_ids(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|x| x["project"]["id"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn test_project_show_hierarchy() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&test_client).await?;
    let create = |name: String, parent: Option<String>| {
        let mut builder = ProjectCreateBuilder::default();
        builder
            .name(name)
            .enabled(true)
            .domain_id(domain.id.clone());
        if let Some(parent) = parent {
            builder.parent_id(parent);
        }
        builder.build()
    };
    let root = create_project(
        &test_client,
        create(Uuid::new_v4().to_string(), Some(domain.id.clone()))?,
    )
    .await?;
    let child = create_project(
        &test_client,
        create(Uuid::new_v4().to_string(), Some(root.id.clone()))?,
    )
    .await?;
    let sibling = create_project(
        &test_client,
        create(Uuid::new_v4().to_string(), Some(root.id.clone()))?,
    )
    .await?;
    let grandchild = create_project(
        &test_client,
        create(Uuid::new_v4().to_string(), Some(child.id.clone()))?,
    )
    .await?;

    // Without the flags no hierarchy members are present.
    let plain =
        get_project_hierarchy(&test_client, &child.id, ProjectHierarchyQuery::default()).await?;
    assert_eq!(plain["id"], child.id.as_str());
    assert!(plain.get("parents").is_none());
    assert!(plain.get("subtree").is_none());

    // parents_as_list: closest parent first, no descendants.
    let shown = get_project_hierarchy(
        &test_client,
        &child.id,
        ProjectHierarchyQuery {
            parents_as_list: true,
            ..Default::default()
        },
    )
    .await?;
    let parents = hierarchy_ids(&shown["parents"]);
    assert_eq!(parents.first(), Some(&root.id));
    assert!(!parents.contains(&grandchild.id));
    assert!(shown.get("subtree").is_none());

    // parents_as_ids: nested object keyed by the parent IDs.
    let shown = get_project_hierarchy(
        &test_client,
        &grandchild.id,
        ProjectHierarchyQuery {
            parents_as_ids: true,
            ..Default::default()
        },
    )
    .await?;
    assert!(
        shown["parents"]
            .get(&child.id)
            .and_then(|x| x.get(&root.id))
            .is_some(),
        "unexpected parents: {}",
        shown["parents"]
    );

    // subtree_as_list: breadth first.
    let shown = get_project_hierarchy(
        &test_client,
        &root.id,
        ProjectHierarchyQuery {
            subtree_as_list: true,
            ..Default::default()
        },
    )
    .await?;
    let subtree = hierarchy_ids(&shown["subtree"]);
    assert_eq!(subtree.len(), 3, "{subtree:?}");
    let pos = |id: &str| subtree.iter().position(|x| x == id);
    assert!(pos(&child.id) < pos(&grandchild.id));
    assert!(pos(&sibling.id).is_some());
    assert!(shown.get("parents").is_none());

    // subtree_as_ids: nested object with `null` leaves.
    let shown = get_project_hierarchy(
        &test_client,
        &root.id,
        ProjectHierarchyQuery {
            subtree_as_ids: true,
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(
        shown["subtree"],
        serde_json::json!({
            child.id.as_str(): {grandchild.id.as_str(): null},
            sibling.id.as_str(): null,
        })
    );

    // A leaf project has an empty subtree.
    let shown = get_project_hierarchy(
        &test_client,
        &grandchild.id,
        ProjectHierarchyQuery {
            subtree_as_list: true,
            ..Default::default()
        },
    )
    .await?;
    assert!(hierarchy_ids(&shown["subtree"]).is_empty());

    grandchild.delete().await?;
    sibling.delete().await?;
    child.delete().await?;
    root.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_project_show_hierarchy_conflicting_params() -> Result<()> {
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
    for query in [
        ProjectHierarchyQuery {
            parents_as_list: true,
            parents_as_ids: true,
            ..Default::default()
        },
        ProjectHierarchyQuery {
            subtree_as_list: true,
            subtree_as_ids: true,
            ..Default::default()
        },
    ] {
        test_api::asserts::assert_status(
            get_project_hierarchy(&test_client, &project.id, query).await,
            http::StatusCode::BAD_REQUEST,
            "mutually exclusive hierarchy parameters must be rejected",
        );
    }
    project.delete().await?;
    domain.delete().await?;
    Ok(())
}
