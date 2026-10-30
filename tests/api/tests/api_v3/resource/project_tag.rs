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
//! Project tags API tests.

use std::sync::Arc;

use eyre::Result;
use http::StatusCode;
use uuid::Uuid;

use openstack_keystone_api_types::v3::project::*;
use openstack_sdk::AsyncOpenStack;

use test_api::asserts::{assert_forbidden, assert_raw_requests_unauthorized, assert_status};
use test_api::common::get_system_scope_session;
use test_api::fixtures::ProjectScopedUser;
use test_api::guard::ResourceGuard;
use test_api::resource::domain::*;
use test_api::resource::project::*;
use test_api::resource::project_tag::*;
use test_api::resource::*;

fn tags(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

fn project_create(domain_id: &str, tags: Vec<String>) -> Result<ProjectCreate> {
    Ok(ProjectCreateBuilder::default()
        .name(Uuid::new_v4().to_string())
        .enabled(true)
        .domain_id(domain_id)
        .tags(tags)
        .build()?)
}

#[tokio::test]
async fn test_project_tags_lifecycle() -> Result<()> {
    let client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&client).await?;
    let project = create_project(&client, project_create(&domain.id, Vec::new())?).await?;

    assert!(list_project_tags(&client, &project.id).await?.is_empty());

    add_project_tag(&client, &project.id, "b").await?;
    add_project_tag(&client, &project.id, "b").await?; // idempotent
    add_project_tag(&client, &project.id, "a").await?;
    assert_eq!(
        list_project_tags(&client, &project.id).await?,
        tags(&["a", "b"])
    );
    check_project_tag(&client, &project.id, "a").await?;

    // tags are part of the project representation
    assert_eq!(
        get_project(&client, &project.id).await?.tags,
        tags(&["a", "b"])
    );

    assert_eq!(
        replace_project_tags(&client, &project.id, tags(&["z", "c"])).await?,
        tags(&["c", "z"])
    );

    delete_project_tag(&client, &project.id, "c").await?;
    assert_status(
        delete_project_tag(&client, &project.id, "c").await,
        StatusCode::NOT_FOUND,
        "removing an absent tag must be 404",
    );
    assert_status(
        check_project_tag(&client, &project.id, "c").await,
        StatusCode::NOT_FOUND,
        "an absent tag must be 404",
    );
    assert_eq!(list_project_tags(&client, &project.id).await?, tags(&["z"]));

    delete_project_tags(&client, &project.id).await?;
    assert!(list_project_tags(&client, &project.id).await?.is_empty());

    project.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_project_tags_on_create_and_update() -> Result<()> {
    let client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&client).await?;
    let project = create_project(&client, project_create(&domain.id, tags(&["y", "x"]))?).await?;
    assert_eq!(project.tags, tags(&["x", "y"]));

    // not part of the update: untouched
    let updated = update_project(
        &client,
        &project.id,
        ProjectUpdateBuilder::default().name("renamed").build()?,
    )
    .await?;
    assert_eq!(updated.tags, tags(&["x", "y"]));

    let updated = update_project(
        &client,
        &project.id,
        ProjectUpdateBuilder::default()
            .tags(tags(&["only"]))
            .build()?,
    )
    .await?;
    assert_eq!(updated.tags, tags(&["only"]));

    project.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_project_tags_invalid() -> Result<()> {
    let client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&client).await?;
    let project = create_project(&client, project_create(&domain.id, Vec::new())?).await?;

    for bad in [tags(&["a,b"]), tags(&[""]), tags(&["dup", "dup"])] {
        assert_status(
            replace_project_tags(&client, &project.id, bad).await,
            StatusCode::BAD_REQUEST,
            "invalid tags must be rejected",
        );
    }
    assert_status(
        replace_project_tags(&client, &project.id, tags(&["Foo", "foo"])).await,
        StatusCode::BAD_REQUEST,
        "tags differing only by case must be rejected",
    );
    add_project_tag(&client, &project.id, "Foo").await?;
    assert_status(
        add_project_tag(&client, &project.id, "foo").await,
        StatusCode::CONFLICT,
        "a case variant of an existing tag must conflict",
    );
    assert_status(
        delete_project_tag(&client, &project.id, "foo").await,
        StatusCode::NOT_FOUND,
        "tags are removed by their exact spelling",
    );
    delete_project_tags(&client, &project.id).await?;
    let too_many: Vec<String> = (0..81).map(|i| format!("t{i}")).collect();
    assert_status(
        replace_project_tags(&client, &project.id, too_many).await,
        StatusCode::BAD_REQUEST,
        "more than 80 tags must be rejected",
    );
    assert_status(
        add_project_tag(&client, &project.id, &"a".repeat(256)).await,
        StatusCode::BAD_REQUEST,
        "an over-long tag must be rejected",
    );
    assert!(list_project_tags(&client, &project.id).await?.is_empty());

    assert_status(
        list_project_tags(&client, "missing-project").await,
        StatusCode::NOT_FOUND,
        "tags of a missing project must be 404",
    );

    project.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_project_list_tag_filters() -> Result<()> {
    let client = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    let domain = create_test_domain(&client).await?;
    // p1: a,b   p2: b,c   p3: no tags
    let p1 = create_project(&client, project_create(&domain.id, tags(&["a", "b"]))?).await?;
    let p2 = create_project(&client, project_create(&domain.id, tags(&["b", "c"]))?).await?;
    let p3 = create_project(&client, project_create(&domain.id, Vec::new())?).await?;

    let ids = |filters: ProjectTagFilters| {
        let client = client.clone();
        let domain_id = domain.id.clone();
        async move {
            let mut ids: Vec<String> = list_projects_by_tags(
                &client,
                ProjectTagFilters {
                    domain_id: Some(domain_id),
                    ..filters
                },
            )
            .await?
            .into_iter()
            .map(|p| p.id)
            .collect();
            ids.sort();
            Ok::<_, eyre::Report>(ids)
        }
    };
    let sorted = |mut v: Vec<&String>| {
        v.sort();
        v.into_iter().cloned().collect::<Vec<_>>()
    };

    assert_eq!(
        ids(ProjectTagFilters {
            tags: Some("b".into()),
            ..Default::default()
        })
        .await?,
        sorted(vec![&p1.id, &p2.id])
    );
    assert_eq!(
        ids(ProjectTagFilters {
            tags: Some("a,b".into()),
            ..Default::default()
        })
        .await?,
        vec![p1.id.clone()]
    );
    assert_eq!(
        ids(ProjectTagFilters {
            tags_any: Some("a,c".into()),
            ..Default::default()
        })
        .await?,
        sorted(vec![&p1.id, &p2.id])
    );
    assert_eq!(
        ids(ProjectTagFilters {
            not_tags: Some("a,b".into()),
            ..Default::default()
        })
        .await?,
        sorted(vec![&p2.id, &p3.id])
    );
    assert_eq!(
        ids(ProjectTagFilters {
            not_tags_any: Some("a,c".into()),
            ..Default::default()
        })
        .await?,
        vec![p3.id.clone()]
    );
    assert_eq!(
        ids(ProjectTagFilters {
            tags: Some("b".into()),
            not_tags_any: Some("a".into()),
            ..Default::default()
        })
        .await?,
        vec![p2.id.clone()]
    );

    // empty tag in a filter is rejected
    assert_status(
        list_projects_by_tags(
            &client,
            ProjectTagFilters {
                tags: Some("a,,b".into()),
                ..Default::default()
            },
        )
        .await,
        StatusCode::BAD_REQUEST,
        "empty tag in the filter must be rejected",
    );

    // too many tags in a filter is rejected
    let many = (0..81)
        .map(|i| format!("t{i}"))
        .collect::<Vec<_>>()
        .join(",");
    assert_status(
        list_projects_by_tags(
            &client,
            ProjectTagFilters {
                not_tags: Some(many),
                ..Default::default()
            },
        )
        .await,
        StatusCode::BAD_REQUEST,
        "more than 80 tags in the filter must be rejected",
    );

    p1.delete().await?;
    p2.delete().await?;
    p3.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_project_tags_forbidden_project_scoped_manager() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let manager = ProjectScopedUser::provision(&admin, "default", "manager").await?;
    let project_id = manager.project.id.clone();

    // Reading the tags of the own project is allowed.
    let read = list_project_tags(&manager.session, &project_id).await;
    let results = [
        replace_project_tags(&manager.session, &project_id, tags(&["a"]))
            .await
            .map(|_| ()),
        add_project_tag(&manager.session, &project_id, "a").await,
        delete_project_tag(&manager.session, &project_id, "a").await,
        delete_project_tags(&manager.session, &project_id).await,
    ];
    manager.cleanup().await?;
    assert!(
        read.is_ok(),
        "a project-scoped user may list the tags of the own project"
    );
    for result in results {
        assert_forbidden(
            result,
            "a project-scoped manager must not manage tags without domain scope",
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_project_tags_reject_missing_token() -> Result<()> {
    use test_api::asserts::RawUnauthorizedRequest;
    let requests = [
        (http::Method::GET, "v3/projects/p/tags", None),
        (
            http::Method::PUT,
            "v3/projects/p/tags",
            Some(serde_json::json!({"tags": ["a"]})),
        ),
        (http::Method::DELETE, "v3/projects/p/tags", None),
        (http::Method::GET, "v3/projects/p/tags/a", None),
        (http::Method::PUT, "v3/projects/p/tags/a", None),
        (http::Method::DELETE, "v3/projects/p/tags/a", None),
    ]
    .map(|(method, path, body)| RawUnauthorizedRequest {
        method,
        path,
        body,
        message: "unauthenticated requests must not access project tags",
    });
    assert_raw_requests_unauthorized(requests, None).await
}
