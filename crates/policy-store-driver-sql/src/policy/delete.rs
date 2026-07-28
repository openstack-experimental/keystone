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
//! # Delete policy

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::policy_store::PolicyStoreProviderError;

use crate::entity::prelude::Policy as DbPolicy;

/// Deletes a policy by ID.
///
/// # Parameters
/// - `db`: The database connection.
/// - `id`: The ID of the policy to delete.
///
/// # Returns
/// A `Result` indicating success, or `PolicyNotFound` when no row matched.
pub async fn delete<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<(), PolicyStoreProviderError> {
    let res = DbPolicy::delete_by_id(id.as_ref())
        .exec(db)
        .await
        .context("deleting policy")?;

    if res.rows_affected == 0 {
        return Err(PolicyStoreProviderError::PolicyNotFound(
            id.as_ref().to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_delete() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            }])
            .into_connection();

        assert!(delete(&db, "1").await.is_ok());

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "policy" WHERE "policy"."id" = $1"#,
                ["1".into()]
            )]
        );
    }

    #[tokio::test]
    async fn test_delete_missing_is_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            }])
            .into_connection();

        assert!(matches!(
            delete(&db, "missing").await,
            Err(PolicyStoreProviderError::PolicyNotFound(_))
        ));
    }
}
