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

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::resource::ResourceProviderError;
use openstack_keystone_core_types::resource::Project;

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

    let project_entry: Option<db_project::Model> = project_select
        .one(db)
        .await
        .context("fetching project by id")?;
    match project_entry {
        Some(model) => {
            let mut project: Project = model.try_into()?;
            project.options = crate::project_option::list_by_project_id(db, &project.id).await?;
            Ok(Some(project))
        }
        None => Ok(None),
    }
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
            Ok(Some(project))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

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
            .into_connection();

        let project = get_project(&db, "1").await.unwrap().unwrap();
        assert_eq!(project.options.immutable, Some(true));
    }

    #[tokio::test]
    async fn test_get_project_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_project::Model>::new()])
            .into_connection();

        assert!(get_project(&db, "missing").await.unwrap().is_none());
    }
}
