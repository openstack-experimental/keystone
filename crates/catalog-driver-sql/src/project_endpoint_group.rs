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
//! # Project ↔ endpoint group associations (OS-EP-FILTER)

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::catalog::EndpointGroup;

use crate::entity::{
    endpoint_group as db_endpoint_group,
    prelude::{EndpointGroup as DbEndpointGroup, ProjectEndpointGroup as DbProjectEndpointGroup},
    project_endpoint_group as db_project_endpoint_group,
};

/// Associates an endpoint group with a project.
///
/// The operation is idempotent: associating an already-associated endpoint
/// group is a no-op.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The ID of the project.
/// - `endpoint_group_id`: The ID of the endpoint group.
///
/// # Returns
/// A `Result` indicating success or an `Error`.
pub async fn add<P: AsRef<str>, G: AsRef<str>>(
    db: &DatabaseConnection,
    project_id: P,
    endpoint_group_id: G,
) -> Result<(), CatalogProviderError> {
    if check(db, project_id.as_ref(), endpoint_group_id.as_ref()).await? {
        return Ok(());
    }
    db_project_endpoint_group::ActiveModel {
        endpoint_group_id: Set(endpoint_group_id.as_ref().to_string()),
        project_id: Set(project_id.as_ref().to_string()),
    }
    .insert(db)
    .await
    .context("associating endpoint group with project")?;
    Ok(())
}

/// Checks whether an endpoint group is associated with a project.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The ID of the project.
/// - `endpoint_group_id`: The ID of the endpoint group.
///
/// # Returns
/// A `Result` containing `true` when the association exists.
pub async fn check<P: AsRef<str>, G: AsRef<str>>(
    db: &DatabaseConnection,
    project_id: P,
    endpoint_group_id: G,
) -> Result<bool, CatalogProviderError> {
    Ok(DbProjectEndpointGroup::find_by_id((
        endpoint_group_id.as_ref().to_string(),
        project_id.as_ref().to_string(),
    ))
    .one(db)
    .await
    .context("checking project-endpoint-group association")?
    .is_some())
}

/// Removes the association between an endpoint group and a project.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The ID of the project.
/// - `endpoint_group_id`: The ID of the endpoint group.
///
/// # Returns
/// A `Result` indicating success or an `Error`.
pub async fn remove<P: AsRef<str>, G: AsRef<str>>(
    db: &DatabaseConnection,
    project_id: P,
    endpoint_group_id: G,
) -> Result<(), CatalogProviderError> {
    DbProjectEndpointGroup::delete_by_id((
        endpoint_group_id.as_ref().to_string(),
        project_id.as_ref().to_string(),
    ))
    .exec(db)
    .await
    .context("removing project-endpoint-group association")?;
    Ok(())
}

/// Lists the endpoint groups associated with a project.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The ID of the project.
///
/// # Returns
/// A `Result` containing a vector of `EndpointGroup`s associated with the
/// project.
pub async fn list_endpoint_groups<P: AsRef<str>>(
    db: &DatabaseConnection,
    project_id: P,
) -> Result<Vec<EndpointGroup>, CatalogProviderError> {
    let group_ids: Vec<String> = DbProjectEndpointGroup::find()
        .filter(db_project_endpoint_group::Column::ProjectId.eq(project_id.as_ref()))
        .all(db)
        .await
        .context("listing project-endpoint-group associations")?
        .into_iter()
        .map(|peg| peg.endpoint_group_id)
        .collect();

    if group_ids.is_empty() {
        return Ok(Vec::new());
    }

    DbEndpointGroup::find()
        .filter(db_endpoint_group::Column::Id.is_in(group_ids))
        .all(db)
        .await
        .context("fetching endpoint groups for project")?
        .into_iter()
        .map(TryInto::<EndpointGroup>::try_into)
        .collect()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    use super::*;

    #[tokio::test]
    async fn test_check_true() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_project_endpoint_group::Model {
                endpoint_group_id: "g1".into(),
                project_id: "p1".into(),
            }]])
            .into_connection();
        assert!(check(&db, "p1", "g1").await.unwrap());
    }

    #[tokio::test]
    async fn test_check_false() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_project_endpoint_group::Model>::new()])
            .into_connection();
        assert!(!check(&db, "p1", "g1").await.unwrap());
    }

    #[tokio::test]
    async fn test_remove() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();
        remove(&db, "p1", "g1").await.unwrap();
    }

    #[tokio::test]
    async fn test_list_endpoint_groups_empty() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_project_endpoint_group::Model>::new()])
            .into_connection();
        assert!(list_endpoint_groups(&db, "p1").await.unwrap().is_empty());
    }
}
