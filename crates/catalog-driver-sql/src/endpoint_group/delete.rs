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
//! # Delete Endpoint Group

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::error::DbContextExt;

use crate::entity::prelude::EndpointGroup as DbEndpointGroup;

/// Deletes an existing endpoint group.
///
/// # Parameters
/// - `db`: The database connection.
/// - `id`: The endpoint group ID.
///
/// # Returns
/// A `Result` indicating success or an `Error`.
pub async fn delete<S: AsRef<str>>(
    db: &DatabaseConnection,
    id: S,
) -> Result<(), CatalogProviderError> {
    DbEndpointGroup::delete_by_id(id.as_ref())
        .exec(db)
        .await
        .context("deleting endpoint group")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    use super::*;

    #[tokio::test]
    async fn test_delete() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        delete(&db, "eg-1").await.unwrap();
    }
}
