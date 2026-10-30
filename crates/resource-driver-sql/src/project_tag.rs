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

//! # Project tags
use sea_orm::ConnectionTrait;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::resource::ResourceProviderError;
use openstack_keystone_core_types::resource::MAX_PROJECT_TAGS;

use crate::entity::{
    prelude::{Project as DbProject, ProjectTag as DbProjectTag},
    project as db_project, project_tag as db_project_tag,
};

/// List tags of a project (or domain) without checking the project exists.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The project ID.
///
/// # Returns
/// The tags sorted alphabetically.
pub async fn list_by_project_id<C, S>(
    db: &C,
    project_id: S,
) -> Result<Vec<String>, ResourceProviderError>
where
    C: ConnectionTrait,
    S: AsRef<str>,
{
    Ok(DbProjectTag::find()
        .filter(db_project_tag::Column::ProjectId.eq(project_id.as_ref()))
        .order_by_asc(db_project_tag::Column::Name)
        .all(db)
        .await
        .context("fetching tags of the project")?
        .into_iter()
        .map(|row| row.name)
        .collect())
}

/// Ensure the project exists.
///
/// # Returns
/// `ProjectNotFound` when there is no project (not a domain) with the ID.
pub async fn ensure_project_exists<C>(db: &C, project_id: &str) -> Result<(), ResourceProviderError>
where
    C: ConnectionTrait,
{
    DbProject::find_by_id(project_id)
        .filter(db_project::Column::IsDomain.eq(false))
        .one(db)
        .await
        .context("checking the project exists")?
        .ok_or_else(|| ResourceProviderError::ProjectNotFound(project_id.to_string()))?;
    Ok(())
}

/// Replace all tags of a project.
///
/// Callers that need atomicity must pass a transaction.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The project ID.
/// - `tags`: The new set of tags.
pub async fn replace<C>(
    db: &C,
    project_id: &str,
    tags: &[String],
) -> Result<(), ResourceProviderError>
where
    C: ConnectionTrait,
{
    DbProjectTag::delete_many()
        .filter(db_project_tag::Column::ProjectId.eq(project_id))
        .exec(db)
        .await
        .context("deleting tags of the project")?;
    insert_all(db, project_id, tags).await
}

/// Insert the tags of a project without touching the existing ones.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The project ID.
/// - `tags`: The tags to insert. The caller guarantees they are valid and
///   unique.
pub async fn insert_all<C>(
    db: &C,
    project_id: &str,
    tags: &[String],
) -> Result<(), ResourceProviderError>
where
    C: ConnectionTrait,
{
    if !tags.is_empty() {
        DbProjectTag::insert_many(tags.iter().map(|name| db_project_tag::ActiveModel {
            project_id: Set(project_id.to_string()),
            name: Set(name.clone()),
        }))
        .exec(db)
        .await
        .context("persisting tags of the project")?;
    }
    Ok(())
}

/// Add a single tag to a project. Adding an existing tag is a no-op.
///
/// The existing tags (at most [`MAX_PROJECT_TAGS`]) are compared in the
/// application with exact and case-insensitive matching, so the result does
/// not depend on the collation of the database column.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The project ID.
/// - `tag`: The tag to add.
///
/// # Returns
/// - `Conflict` when the project carries a tag that differs only by case.
/// - A `Validation` error when the tag is new and the project already carries
///   [`MAX_PROJECT_TAGS`] tags.
///
/// Callers that need the limit to be race-free must pass a transaction.
pub async fn create<C>(db: &C, project_id: &str, tag: &str) -> Result<(), ResourceProviderError>
where
    C: ConnectionTrait,
{
    let existing = list_by_project_id(db, project_id).await?;
    if existing.iter().any(|t| t == tag) {
        return Ok(());
    }
    let lowered = tag.to_lowercase();
    if let Some(similar) = existing.iter().find(|t| t.to_lowercase() == lowered) {
        return Err(ResourceProviderError::Conflict(format!(
            "the project already has the tag `{similar}` that differs only by case"
        )));
    }
    if existing.len() >= MAX_PROJECT_TAGS {
        let mut errors = validator::ValidationErrors::new();
        errors.add("tag", validator::ValidationError::new("project_tag_count"));
        return Err(errors.into());
    }
    // A concurrent request adding the same tag is not an error.
    DbProjectTag::insert(db_project_tag::ActiveModel {
        project_id: Set(project_id.to_string()),
        name: Set(tag.to_string()),
    })
    .on_conflict_do_nothing_on([
        db_project_tag::Column::ProjectId,
        db_project_tag::Column::Name,
    ])
    .exec(db)
    .await
    .context("persisting the tag of the project")?;
    Ok(())
}

/// Delete a single tag from a project.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The project ID.
/// - `tag`: The tag to delete.
///
/// # Returns
/// `ProjectTagNotFound` when the project does not carry the tag.
pub async fn delete<C>(db: &C, project_id: &str, tag: &str) -> Result<(), ResourceProviderError>
where
    C: ConnectionTrait,
{
    // Match the tag exactly in the application: a case-insensitive column
    // collation would otherwise delete `Foo` when asked to delete `foo`.
    if !list_by_project_id(db, project_id)
        .await?
        .iter()
        .any(|t| t == tag)
    {
        return Err(ResourceProviderError::ProjectTagNotFound {
            project_id: project_id.to_string(),
            tag: tag.to_string(),
        });
    }
    DbProjectTag::delete_by_id((project_id.to_string(), tag.to_string()))
        .exec(db)
        .await
        .context("deleting the tag of the project")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    use super::*;

    fn tag(project_id: &str, name: &str) -> db_project_tag::Model {
        db_project_tag::Model {
            project_id: project_id.into(),
            name: name.into(),
        }
    }

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![tag("1", "a"), tag("1", "b")]])
            .into_connection();
        assert_eq!(
            list_by_project_id(&db, "1").await.unwrap(),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[tokio::test]
    async fn test_replace() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .append_query_results([vec![tag("1", "a"), tag("1", "b")]])
            .into_connection();
        replace(&db, "1", &["a".to_string(), "b".to_string()])
            .await
            .unwrap();
        let log = db.into_transaction_log();
        assert_eq!(log.len(), 2, "delete followed by insert: {log:?}");
    }

    #[tokio::test]
    async fn test_replace_empty_only_deletes() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();
        replace(&db, "1", &[]).await.unwrap();
        assert_eq!(db.into_transaction_log().len(), 1);
    }

    #[tokio::test]
    async fn test_create_existing_is_noop() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![tag("1", "a")]])
            .into_connection();
        create(&db, "1", "a").await.unwrap();
        assert_eq!(db.into_transaction_log().len(), 1, "only the lookup runs");
    }

    #[tokio::test]
    async fn test_delete_missing() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_project_tag::Model>::new()])
            .into_connection();
        assert!(matches!(
            delete(&db, "1", "a").await,
            Err(ResourceProviderError::ProjectTagNotFound { .. })
        ));
    }

    #[tokio::test]
    async fn test_delete_requires_exact_match() {
        // A case-insensitive column collation finds `Foo` for `foo`; the
        // tag must not be deleted then.
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![tag("1", "Foo")]])
            .into_connection();
        assert!(matches!(
            delete(&db, "1", "foo").await,
            Err(ResourceProviderError::ProjectTagNotFound { .. })
        ));
        assert_eq!(db.into_transaction_log().len(), 1, "only the lookup runs");
    }

    #[tokio::test]
    async fn test_create_case_variant_conflicts() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![tag("1", "Foo")]])
            .into_connection();
        assert!(matches!(
            create(&db, "1", "foo").await,
            Err(ResourceProviderError::Conflict(_))
        ));
        assert_eq!(db.into_transaction_log().len(), 1, "only the lookup runs");
    }

    #[tokio::test]
    async fn test_create_over_limit() {
        let existing: Vec<_> = (0..MAX_PROJECT_TAGS)
            .map(|i| tag("1", &format!("t{i}")))
            .collect();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([existing])
            .into_connection();
        assert!(matches!(
            create(&db, "1", "extra").await,
            Err(ResourceProviderError::Validation { .. })
        ));
    }
}
