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
//! # Update Project

use sea_orm::ConnectionTrait;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::resource::ResourceProviderError;
use openstack_keystone_core_types::resource::{Project, ProjectUpdate};

use crate::entity::{prelude::Project as DbProject, project as db_project};

/// Update an existing project.
///
/// Only the fields set in `project` are changed; the rest are left as-is.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The ID of the project to update.
/// - `project`: The fields to change.
///
/// # Returns
/// A `Result` containing the updated `Project`, or an `Error` (including
/// `ProjectNotFound` if no project with that ID exists).
pub async fn update<C>(
    db: &C,
    project_id: &str,
    project: ProjectUpdate,
) -> Result<Project, ResourceProviderError>
where
    C: ConnectionTrait,
{
    let existing = DbProject::find_by_id(project_id)
        .filter(db_project::Column::IsDomain.eq(false))
        .one(db)
        .await
        .context("fetching project for update")?
        .ok_or_else(|| ResourceProviderError::ProjectNotFound(project_id.to_string()))?;

    let mut update_model: db_project::ActiveModel = existing.into();

    if let Some(name) = project.name {
        update_model.name = Set(name);
    }
    if let Some(enabled) = project.enabled {
        update_model.enabled = Set(Some(enabled));
    }
    if let Some(description) = project.description {
        update_model.description = Set(description);
    }
    if !project.extra.is_empty() {
        update_model.extra = Set(Some(serde_json::to_string(&project.extra)?));
    }

    update_model
        .update(db)
        .await
        .context("updating project")?
        .try_into()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::super::tests::get_project_mock;
    use super::*;

    #[tokio::test]
    async fn test_update() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_project_mock("1")], vec![get_project_mock("1")]])
            .into_connection();

        let req = ProjectUpdate {
            name: Some("new_name".into()),
            enabled: Some(false),
            description: None,
            extra: Default::default(),
        };
        let result = update(&db, "1", req).await.unwrap();
        assert_eq!(result, get_project_mock("1").try_into().unwrap());
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_project::Model>::new()])
            .into_connection();

        let req = ProjectUpdate {
            name: Some("new_name".into()),
            enabled: None,
            description: None,
            extra: Default::default(),
        };
        let result = update(&db, "missing", req).await;
        assert!(matches!(
            result,
            Err(ResourceProviderError::ProjectNotFound(_))
        ));
    }
}
