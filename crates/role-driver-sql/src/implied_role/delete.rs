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
use openstack_keystone_core::role::RoleProviderError;

use crate::entity::prelude::ImpliedRole;

/// Delete a role imply rule.
///
/// # Parameters
/// - `db`: The database connection.
/// - `prior_role_id`: The ID of the prior role.
/// - `implied_role_id`: The ID of the implied role.
///
/// # Returns
/// A `Result` indicating success or an `Error`.
pub async fn delete(
    db: &DatabaseConnection,
    prior_role_id: &str,
    implied_role_id: &str,
) -> Result<(), RoleProviderError> {
    ImpliedRole::delete_by_id((prior_role_id.into(), implied_role_id.into()))
        .exec(db)
        .await
        .context("deleting role imply rule")?;
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
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        delete(&db, "admin", "member").await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "implied_role" WHERE "implied_role"."prior_role_id" = $1 AND "implied_role"."implied_role_id" = $2"#,
                ["admin".into(), "member".into()]
            )]
        );
    }
}
