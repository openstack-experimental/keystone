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
//! Test project tags.

use eyre::Result;
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::resource::{
    MAX_PROJECT_TAG_LENGTH, MAX_PROJECT_TAGS, ProjectCreateBuilder, ProjectListParametersBuilder,
    ProjectUpdateBuilder, ResourceProviderError,
};

use crate::common::get_state;
use crate::{create_domain, create_project};

#[traced_test]
#[tokio::test]
async fn test_tags_lifecycle() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let ctx = ExecutionContext::internal(&state);
    let domain = create_domain!(state)?;
    let project = create_project!(state, &domain.id)?;
    let provider = state.provider.get_resource_provider();

    assert!(
        provider
            .list_project_tags(&ctx, &project.id)
            .await?
            .is_empty()
    );

    provider.create_project_tag(&ctx, &project.id, "b").await?;
    // adding the same tag again is a no-op
    provider.create_project_tag(&ctx, &project.id, "b").await?;
    provider.create_project_tag(&ctx, &project.id, "a").await?;
    assert_eq!(
        provider.list_project_tags(&ctx, &project.id).await?,
        vec!["a".to_string(), "b".to_string()]
    );

    // tags are part of the project object
    let fetched = provider
        .get_project(&ctx, &project.id)
        .await?
        .expect("project exists");
    assert_eq!(fetched.tags, vec!["a".to_string(), "b".to_string()]);

    let replaced = provider
        .replace_project_tags(&ctx, &project.id, vec!["z".into(), "c".into()])
        .await?;
    assert_eq!(replaced, vec!["c".to_string(), "z".to_string()]);

    provider.delete_project_tag(&ctx, &project.id, "c").await?;
    let err = provider
        .delete_project_tag(&ctx, &project.id, "c")
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ResourceProviderError::ProjectTagNotFound { .. }
    ));
    assert_eq!(
        provider.list_project_tags(&ctx, &project.id).await?,
        vec!["z".to_string()]
    );

    provider
        .replace_project_tags(&ctx, &project.id, Vec::new())
        .await?;
    assert!(
        provider
            .list_project_tags(&ctx, &project.id)
            .await?
            .is_empty()
    );

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_tags_on_create_and_update() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let ctx = ExecutionContext::internal(&state);
    let domain = create_domain!(state)?;
    let provider = state.provider.get_resource_provider();

    let project = provider
        .create_project(
            &ctx,
            ProjectCreateBuilder::default()
                .name(uuid::Uuid::new_v4().simple().to_string())
                .domain_id(domain.id.clone())
                .tags(vec!["y".to_string(), "x".to_string()])
                .build()?,
        )
        .await?;
    assert_eq!(project.tags, vec!["x".to_string(), "y".to_string()]);

    // tags untouched when not part of the update
    let updated = provider
        .update_project(
            &ctx,
            &project.id,
            ProjectUpdateBuilder::default().name("renamed").build()?,
        )
        .await?;
    assert_eq!(updated.tags, vec!["x".to_string(), "y".to_string()]);

    let updated = provider
        .update_project(
            &ctx,
            &project.id,
            ProjectUpdateBuilder::default()
                .tags(vec!["only".to_string()])
                .build()?,
        )
        .await?;
    assert_eq!(updated.tags, vec!["only".to_string()]);

    let listed = provider
        .list_projects(
            &ctx,
            &openstack_keystone_core_types::resource::ProjectListParametersBuilder::default()
                .domain_id(Some(domain.id.clone()))
                .build()?,
        )
        .await?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].tags, vec!["only".to_string()]);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_tags_invalid() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let ctx = ExecutionContext::internal(&state);
    let domain = create_domain!(state)?;
    let project = create_project!(state, &domain.id)?;
    let provider = state.provider.get_resource_provider();

    for tags in [
        vec!["a/b".to_string()],
        vec!["a,b".to_string()],
        vec![String::new()],
        vec!["dup".to_string(), "dup".to_string()],
    ] {
        assert!(
            provider
                .replace_project_tags(&ctx, &project.id, tags)
                .await
                .is_err()
        );
    }

    let err = provider
        .list_project_tags(&ctx, "missing")
        .await
        .unwrap_err();
    assert!(matches!(err, ResourceProviderError::ProjectNotFound(_)));

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_tags_missing_project() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let ctx = ExecutionContext::internal(&state);
    let provider = state.provider.get_resource_provider();

    assert!(matches!(
        provider
            .replace_project_tags(&ctx, "missing", vec!["a".into()])
            .await
            .unwrap_err(),
        ResourceProviderError::ProjectNotFound(_)
    ));
    assert!(matches!(
        provider
            .create_project_tag(&ctx, "missing", "a")
            .await
            .unwrap_err(),
        ResourceProviderError::ProjectNotFound(_)
    ));
    assert!(matches!(
        provider
            .delete_project_tag(&ctx, "missing", "a")
            .await
            .unwrap_err(),
        ResourceProviderError::ProjectNotFound(_)
    ));

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_tags_limits() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let ctx = ExecutionContext::internal(&state);
    let domain = create_domain!(state)?;
    let project = create_project!(state, &domain.id)?;
    let provider = state.provider.get_resource_provider();

    let max: Vec<String> = (0..MAX_PROJECT_TAGS).map(|i| format!("t{i}")).collect();
    assert_eq!(
        provider
            .replace_project_tags(&ctx, &project.id, max.clone())
            .await?
            .len(),
        MAX_PROJECT_TAGS
    );

    // one more is rejected and the existing set is left intact
    let mut too_many = max;
    too_many.push("extra".into());
    assert!(
        provider
            .replace_project_tags(&ctx, &project.id, too_many)
            .await
            .is_err()
    );
    assert_eq!(
        provider.list_project_tags(&ctx, &project.id).await?.len(),
        MAX_PROJECT_TAGS
    );

    // adding a new tag one by one cannot exceed the limit either, while
    // re-adding an existing tag stays a no-op
    provider.create_project_tag(&ctx, &project.id, "t0").await?;
    assert!(
        provider
            .create_project_tag(&ctx, &project.id, "extra")
            .await
            .is_err()
    );
    assert_eq!(
        provider.list_project_tags(&ctx, &project.id).await?.len(),
        MAX_PROJECT_TAGS
    );

    // the tag length boundary
    provider
        .replace_project_tags(&ctx, &project.id, vec!["a".repeat(MAX_PROJECT_TAG_LENGTH)])
        .await?;
    assert!(
        provider
            .replace_project_tags(
                &ctx,
                &project.id,
                vec!["a".repeat(MAX_PROJECT_TAG_LENGTH + 1)],
            )
            .await
            .is_err()
    );

    // a single invalid tag is rejected
    for tag in ["a/b", "a,b", ""] {
        assert!(
            provider
                .create_project_tag(&ctx, &project.id, tag)
                .await
                .is_err()
        );
    }

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_tags_isolated_between_projects() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let ctx = ExecutionContext::internal(&state);
    let domain = create_domain!(state)?;
    let parent = create_project!(state, &domain.id)?;
    let child = create_project!(state, &domain.id, &parent.id)?;
    let other = create_project!(state, &domain.id)?;
    let provider = state.provider.get_resource_provider();

    provider
        .replace_project_tags(&ctx, &parent.id, vec!["p".into(), "shared".into()])
        .await?;
    provider
        .replace_project_tags(&ctx, &child.id, vec!["c".into(), "shared".into()])
        .await?;

    // no inheritance from the parent and no leakage to unrelated projects
    assert_eq!(
        provider.list_project_tags(&ctx, &child.id).await?,
        vec!["c".to_string(), "shared".to_string()]
    );
    assert!(
        provider
            .list_project_tags(&ctx, &other.id)
            .await?
            .is_empty()
    );

    // removing a tag only affects the targeted project
    provider
        .delete_project_tag(&ctx, &child.id, "shared")
        .await?;
    assert_eq!(
        provider.list_project_tags(&ctx, &parent.id).await?,
        vec!["p".to_string(), "shared".to_string()]
    );

    // list returns the tags of each project
    let listed = provider
        .list_projects(
            &ctx,
            &ProjectListParametersBuilder::default()
                .domain_id(Some(domain.id.clone()))
                .build()?,
        )
        .await?;
    assert_eq!(listed.len(), 3);
    for p in listed {
        let expected = if p.id == parent.id {
            vec!["p".to_string(), "shared".to_string()]
        } else if p.id == child.id {
            vec!["c".to_string()]
        } else {
            Vec::new()
        };
        assert_eq!(p.tags, expected);
    }

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_tags_removed_with_project() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let ctx = ExecutionContext::internal(&state);
    let domain = create_domain!(state)?;
    let project = create_project!(state, &domain.id)?;
    let provider = state.provider.get_resource_provider();

    provider
        .replace_project_tags(&ctx, &project.id, vec!["a".into(), "b".into()])
        .await?;
    provider.delete_project(&ctx, &project.id).await?;

    let db = state.db.connection();
    let backend = db.get_database_backend();
    // MySQL uses `?` placeholders, Postgres and SQLite accept `$1`.
    let sql = match backend {
        DatabaseBackend::MySql => "SELECT COUNT(*) AS cnt FROM project_tag WHERE project_id = ?",
        _ => "SELECT COUNT(*) AS cnt FROM project_tag WHERE project_id = $1",
    };
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            backend,
            sql,
            [project.id.clone().into()],
        ))
        .await?
        .expect("count row");
    assert_eq!(row.try_get::<i64>("", "cnt")?, 0);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_tags_list_filters() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let ctx = ExecutionContext::internal(&state);
    let domain = create_domain!(state)?;
    let provider = state.provider.get_resource_provider();

    // p1: a,b   p2: b,c   p3: no tags
    let p1 = create_project!(state, &domain.id)?;
    let p2 = create_project!(state, &domain.id)?;
    let p3 = create_project!(state, &domain.id)?;
    provider
        .replace_project_tags(&ctx, &p1.id, vec!["a".into(), "b".into()])
        .await?;
    provider
        .replace_project_tags(&ctx, &p2.id, vec!["b".into(), "c".into()])
        .await?;

    let list = |tags: Option<&[&str]>,
                tags_any: Option<&[&str]>,
                not_tags: Option<&[&str]>,
                not_tags_any: Option<&[&str]>| {
        let to_set = |v: Option<&[&str]>| v.map(|v| v.iter().map(|s| s.to_string()).collect());
        ProjectListParametersBuilder::default()
            .domain_id(Some(domain.id.clone()))
            .tags(to_set(tags))
            .tags_any(to_set(tags_any))
            .not_tags(to_set(not_tags))
            .not_tags_any(to_set(not_tags_any))
            .build()
    };
    let ids = |params| {
        let ctx = &ctx;
        async move {
            let mut ids: Vec<String> = provider
                .list_projects(ctx, &params)
                .await?
                .into_iter()
                .map(|p| p.id)
                .collect();
            ids.sort();
            Ok::<_, eyre::Report>(ids)
        }
    };
    let sorted = |mut v: Vec<&str>| {
        v.sort();
        v.into_iter().map(String::from).collect::<Vec<_>>()
    };

    // tags: all of
    assert_eq!(
        ids(list(Some(&["b"]), None, None, None)?).await?,
        sorted(vec![&p1.id, &p2.id])
    );
    assert_eq!(
        ids(list(Some(&["a", "b"]), None, None, None)?).await?,
        vec![p1.id.clone()]
    );
    assert!(
        ids(list(Some(&["a", "c"]), None, None, None)?)
            .await?
            .is_empty()
    );

    // tags-any: at least one of
    assert_eq!(
        ids(list(None, Some(&["a", "c"]), None, None)?).await?,
        sorted(vec![&p1.id, &p2.id])
    );

    // not-tags: not carrying all of
    assert_eq!(
        ids(list(None, None, Some(&["a", "b"]), None)?).await?,
        sorted(vec![&p2.id, &p3.id])
    );

    // not-tags-any: carrying none of
    assert_eq!(
        ids(list(None, None, None, Some(&["a", "c"]))?).await?,
        vec![p3.id.clone()]
    );

    // filters combine: has b but not a
    assert_eq!(
        ids(list(Some(&["b"]), None, None, Some(&["a"]))?).await?,
        vec![p2.id.clone()]
    );

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_tags_case_insensitive_uniqueness() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let ctx = ExecutionContext::internal(&state);
    let domain = create_domain!(state)?;
    let project = create_project!(state, &domain.id)?;
    let provider = state.provider.get_resource_provider();

    // the outcome must not depend on the collation of the database
    assert!(
        provider
            .replace_project_tags(&ctx, &project.id, vec!["Foo".into(), "foo".into()])
            .await
            .is_err()
    );

    provider
        .create_project_tag(&ctx, &project.id, "Foo")
        .await?;
    // the exact tag is a no-op, a case variant conflicts
    provider
        .create_project_tag(&ctx, &project.id, "Foo")
        .await?;
    assert!(matches!(
        provider
            .create_project_tag(&ctx, &project.id, "foo")
            .await
            .unwrap_err(),
        ResourceProviderError::Conflict(_)
    ));
    assert_eq!(
        provider.list_project_tags(&ctx, &project.id).await?,
        vec!["Foo".to_string()]
    );

    // deleting requires the exact spelling
    assert!(matches!(
        provider
            .delete_project_tag(&ctx, &project.id, "foo")
            .await
            .unwrap_err(),
        ResourceProviderError::ProjectTagNotFound { .. }
    ));
    assert_eq!(
        provider.list_project_tags(&ctx, &project.id).await?,
        vec!["Foo".to_string()]
    );
    provider
        .delete_project_tag(&ctx, &project.id, "Foo")
        .await?;

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_tags_list_filters_ignore_case() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let ctx = ExecutionContext::internal(&state);
    let domain = create_domain!(state)?;
    let project = create_project!(state, &domain.id)?;
    let provider = state.provider.get_resource_provider();
    provider
        .replace_project_tags(&ctx, &project.id, vec!["Prod".into()])
        .await?;

    let list = |tags: &[&str], any: bool| {
        let set = Some(tags.iter().map(|s| s.to_string()).collect());
        let mut builder = ProjectListParametersBuilder::default();
        builder.domain_id(Some(domain.id.clone()));
        if any {
            builder.tags_any(set);
        } else {
            builder.not_tags_any(set);
        }
        builder.build()
    };
    assert_eq!(
        provider
            .list_projects(&ctx, &list(&["pROD"], true)?)
            .await?
            .len(),
        1
    );
    assert!(
        provider
            .list_projects(&ctx, &list(&["pROD"], false)?)
            .await?
            .is_empty()
    );

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_tags_of_project_parents() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let ctx = ExecutionContext::internal(&state);
    let domain = create_domain!(state)?;
    let parent = create_project!(state, &domain.id)?;
    let child = create_project!(state, &domain.id, &parent.id)?;
    let provider = state.provider.get_resource_provider();
    provider
        .replace_project_tags(&ctx, &parent.id, vec!["p".into()])
        .await?;

    let parents = provider
        .get_project_parents(&ctx, &child.id)
        .await?
        .expect("project exists");
    let found = parents
        .iter()
        .find(|p| p.id == parent.id)
        .expect("parent is listed");
    assert_eq!(found.tags, vec!["p".to_string()]);

    Ok(())
}
