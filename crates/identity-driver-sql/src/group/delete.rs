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

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::identity::IdentityProviderError;

use crate::entity::prelude::Group as DbGroup;

/// Deletes a group by its ID.
///
/// # Parameters
/// - `db`: The database connection.
/// - `group_id`: The ID of the group to delete.
///
/// # Returns
/// A `Result` indicating success or an `Error`.
#[tracing::instrument(skip_all)]
pub async fn delete<S: AsRef<str>>(
    db: &DatabaseConnection,
    group_id: S,
) -> Result<(), IdentityProviderError> {
    let res = DbGroup::delete_by_id(group_id.as_ref())
        .exec(db)
        .await
        .context("removing group record")?;
    if res.rows_affected == 1 {
        Ok(())
    } else {
        Err(IdentityProviderError::GroupNotFound(
            group_id.as_ref().to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_delete() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        delete(&db, "id").await.unwrap();
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "group" WHERE "group"."id" = $1"#,
                ["id".into()]
            ),]
        );
    }
}
