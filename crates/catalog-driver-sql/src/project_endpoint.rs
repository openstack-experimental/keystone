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
//! # Project ↔ endpoint associations (OS-EP-FILTER)

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::catalog::Endpoint;

use crate::entity::{
    endpoint as db_endpoint,
    prelude::{Endpoint as DbEndpoint, ProjectEndpoint as DbProjectEndpoint},
    project_endpoint as db_project_endpoint,
};

/// Associates an endpoint with a project.
///
/// The operation is idempotent: associating an already-associated endpoint is a
/// no-op.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The ID of the project.
/// - `endpoint_id`: The ID of the endpoint.
///
/// # Returns
/// A `Result` indicating success or an `Error`.
pub async fn add<P: AsRef<str>, E: AsRef<str>>(
    db: &DatabaseConnection,
    project_id: P,
    endpoint_id: E,
) -> Result<(), CatalogProviderError> {
    if check(db, project_id.as_ref(), endpoint_id.as_ref()).await? {
        return Ok(());
    }
    db_project_endpoint::ActiveModel {
        endpoint_id: Set(endpoint_id.as_ref().to_string()),
        project_id: Set(project_id.as_ref().to_string()),
    }
    .insert(db)
    .await
    .context("associating endpoint with project")?;
    Ok(())
}

/// Checks whether an endpoint is associated with a project.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The ID of the project.
/// - `endpoint_id`: The ID of the endpoint.
///
/// # Returns
/// A `Result` containing `true` when the association exists.
pub async fn check<P: AsRef<str>, E: AsRef<str>>(
    db: &DatabaseConnection,
    project_id: P,
    endpoint_id: E,
) -> Result<bool, CatalogProviderError> {
    Ok(DbProjectEndpoint::find_by_id((
        endpoint_id.as_ref().to_string(),
        project_id.as_ref().to_string(),
    ))
    .one(db)
    .await
    .context("checking project-endpoint association")?
    .is_some())
}

/// Removes the association between an endpoint and a project.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The ID of the project.
/// - `endpoint_id`: The ID of the endpoint.
///
/// # Returns
/// A `Result` indicating success or an `Error`.
pub async fn remove<P: AsRef<str>, E: AsRef<str>>(
    db: &DatabaseConnection,
    project_id: P,
    endpoint_id: E,
) -> Result<(), CatalogProviderError> {
    DbProjectEndpoint::delete_by_id((
        endpoint_id.as_ref().to_string(),
        project_id.as_ref().to_string(),
    ))
    .exec(db)
    .await
    .context("removing project-endpoint association")?;
    Ok(())
}

/// Lists the endpoints associated with a project.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The ID of the project.
///
/// # Returns
/// A `Result` containing a vector of `Endpoint`s associated with the project.
pub async fn list_endpoints<P: AsRef<str>>(
    db: &DatabaseConnection,
    project_id: P,
) -> Result<Vec<Endpoint>, CatalogProviderError> {
    let endpoint_ids: Vec<String> = DbProjectEndpoint::find()
        .filter(db_project_endpoint::Column::ProjectId.eq(project_id.as_ref()))
        .all(db)
        .await
        .context("listing project-endpoint associations")?
        .into_iter()
        .map(|pe| pe.endpoint_id)
        .collect();

    if endpoint_ids.is_empty() {
        return Ok(Vec::new());
    }

    DbEndpoint::find()
        .filter(db_endpoint::Column::Id.is_in(endpoint_ids))
        .all(db)
        .await
        .context("fetching endpoints for project")?
        .into_iter()
        .map(TryInto::<Endpoint>::try_into)
        .collect()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    use super::*;

    #[tokio::test]
    async fn test_check_true() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_project_endpoint::Model {
                endpoint_id: "e1".into(),
                project_id: "p1".into(),
            }]])
            .into_connection();
        assert!(check(&db, "p1", "e1").await.unwrap());
    }

    #[tokio::test]
    async fn test_check_false() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_project_endpoint::Model>::new()])
            .into_connection();
        assert!(!check(&db, "p1", "e1").await.unwrap());
    }

    #[tokio::test]
    async fn test_remove() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();
        remove(&db, "p1", "e1").await.unwrap();
    }

    #[tokio::test]
    async fn test_list_endpoints_empty() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_project_endpoint::Model>::new()])
            .into_connection();
        assert!(list_endpoints(&db, "p1").await.unwrap().is_empty());
    }
}
