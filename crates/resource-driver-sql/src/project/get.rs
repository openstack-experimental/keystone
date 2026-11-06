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

use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::{DatabaseConnection, FromQueryResult};

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::resource::ResourceProviderError;
use openstack_keystone_core_types::resource::{Project, ProjectRef};

use crate::entity::{prelude::Project as DbProject, project as db_project};

/// Get a project by its ID.
///
/// # Parameters
/// - `db`: Database connection.
/// - `id`: ID of the project.
///
/// # Returns
/// A `Result` containing an `Option` with the `Project` if found, or an
/// `Error`.
pub async fn get_project<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Project>, ResourceProviderError> {
    let project_select =
        DbProject::find_by_id(id.as_ref()).filter(db_project::Column::IsDomain.eq(false));

    // The options and tags are keyed by the same ID: no need to wait for the
    // project.
    let (project_entry, options, tags) = tokio::join!(
        project_select.one(db),
        crate::project_option::list_by_project_id(db, id.as_ref()),
        crate::project_tag::list_by_project_id(db, id.as_ref())
    );
    match project_entry.context("fetching project by id")? {
        Some(model) => {
            let mut project: Project = model.try_into()?;
            project.options = options?;
            project.tags = tags?;
            Ok(Some(project))
        }
        None => Ok(None),
    }
}

/// The columns of the project row read for [`ProjectRef`]: `extra` and
/// `description` are left out.
#[derive(Debug, FromQueryResult)]
struct ProjectRefRow {
    id: String,
    name: String,
    domain_id: String,
    enabled: Option<bool>,
    parent_id: Option<String>,
    is_domain: bool,
}

/// Get the short representation of a project by its ID.
///
/// A single query on the project row: the options and tags are not loaded.
/// Like [`get_project`] it matches projects only, not the domain's own
/// `is_domain` entry.
///
/// # Parameters
/// - `db`: Database connection.
/// - `id`: ID of the project.
///
/// # Returns
/// A `Result` containing an `Option` with the `ProjectRef` if found, or an
/// `Error`.
pub async fn get_project_ref<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<ProjectRef>, ResourceProviderError> {
    let row = DbProject::find_by_id(id.as_ref())
        .filter(db_project::Column::IsDomain.eq(false))
        .select_only()
        .columns([
            db_project::Column::Id,
            db_project::Column::Name,
            db_project::Column::DomainId,
            db_project::Column::Enabled,
            db_project::Column::ParentId,
            db_project::Column::IsDomain,
        ])
        .into_model::<ProjectRefRow>()
        .one(db)
        .await
        .context("fetching the short project by id")?;
    Ok(row.map(|row| ProjectRef {
        domain_id: row.domain_id,
        // python keystone defaults to project/domain being enabled when the
        // column is unset.
        enabled: row.enabled.unwrap_or(true),
        id: row.id,
        is_domain: row.is_domain,
        name: row.name,
        parent_id: row.parent_id,
    }))
}

/// Get the ID of the domain a project belongs to.
///
/// Reads the single `domain_id` column; the project options are not loaded.
/// Like [`get_project`] it matches projects only, not the domain's own
/// `is_domain` entry.
///
/// # Parameters
/// - `db`: Database connection.
/// - `id`: ID of the project.
///
/// # Returns
/// A `Result` containing an `Option` with the domain ID if the project exists,
/// or an `Error`.
pub async fn get_project_domain_id<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<String>, ResourceProviderError> {
    Ok(DbProject::find_by_id(id.as_ref())
        .filter(db_project::Column::IsDomain.eq(false))
        .select_only()
        .column(db_project::Column::DomainId)
        .into_tuple::<String>()
        .one(db)
        .await
        .context("fetching the domain of the project")?)
}

/// Get a project by its name and domain ID.
///
/// # Parameters
/// - `db`: Database connection.
/// - `name`: Name of the project.
/// - `domain_id`: ID of the domain.
///
/// # Returns
/// A `Result` containing an `Option` with the `Project` if found, or an
/// `Error`.
pub async fn get_project_by_name<N: AsRef<str>, D: AsRef<str>>(
    db: &DatabaseConnection,
    name: N,
    domain_id: D,
) -> Result<Option<Project>, ResourceProviderError> {
    let project_select = DbProject::find()
        .filter(db_project::Column::IsDomain.eq(false))
        .filter(db_project::Column::Name.eq(name.as_ref()))
        .filter(db_project::Column::DomainId.eq(domain_id.as_ref()));

    let project_entry: Option<db_project::Model> = project_select
        .one(db)
        .await
        .context("fetching project by name and domain")?;
    match project_entry {
        Some(model) => {
            let mut project: Project = model.try_into()?;
            project.options = crate::project_option::list_by_project_id(db, &project.id).await?;
            project.tags = crate::project_tag::list_by_project_id(db, &project.id).await?;
            Ok(Some(project))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sea_orm::{DatabaseBackend, IntoMockRow, MockDatabase};

    use super::*;
    use crate::entity::project_option;
    use crate::project::tests::get_project_mock;

    #[tokio::test]
    async fn test_get_project_merges_options() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_project_mock("1")]])
            .append_query_results([vec![project_option::Model {
                project_id: "1".into(),
                option_id: "IMMU".into(),
                option_value: Some("true".into()),
            }]])
            .append_query_results([vec![crate::entity::project_tag::Model {
                project_id: "1".into(),
                name: "a".into(),
            }]])
            .into_connection();

        let project = get_project(&db, "1").await.unwrap().unwrap();
        assert_eq!(project.options.immutable, Some(true));
        assert_eq!(project.tags, vec!["a".to_string()]);
    }

    #[tokio::test]
    async fn test_get_project_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_project::Model>::new()])
            .into_connection();

        assert!(get_project(&db, "missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_get_project_ref_is_a_single_query() {
        let row = BTreeMap::from([
            ("id", "1".into()),
            ("name", "p1".into()),
            ("domain_id", "d1".into()),
            ("enabled", sea_orm::Value::Bool(None)),
            ("parent_id", sea_orm::Value::String(None)),
            ("is_domain", false.into()),
        ])
        .into_mock_row();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![row]])
            .into_connection();

        let project = get_project_ref(&db, "1").await.unwrap().unwrap();

        assert_eq!("1", project.id);
        assert_eq!("p1", project.name);
        assert_eq!("d1", project.domain_id);
        // An unset column means enabled, like for the full project.
        assert!(project.enabled);
        assert_eq!(None, project.parent_id);
        // Neither the options nor the tags are queried.
        assert_eq!(1, db.into_transaction_log().len());
    }

    #[tokio::test]
    async fn test_get_project_ref_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_project::Model>::new()])
            .into_connection();

        assert!(get_project_ref(&db, "missing").await.unwrap().is_none());
    }
}
