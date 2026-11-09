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
use openstack_keystone_core::identity::IdentityProviderError;

use crate::entity::{
    expiring_user_group_membership, prelude::ExpiringUserGroupMembership,
    prelude::Group as DbGroup, prelude::UserGroupMembership, user_group_membership,
};

/// Deletes a group by its ID.
///
/// The user<->group membership rows (direct and expiring) reference the group
/// without a cascading foreign key, so they are removed in the same
/// transaction before the group record itself (python-keystone drops them the
/// same way).
///
/// # Parameters
/// - `db`: The database connection.
/// - `group_id`: The ID of the group to delete.
///
/// # Returns
/// A `Result` indicating success or an `Error`.
pub async fn delete<S: AsRef<str>>(
    db: &DatabaseConnection,
    group_id: S,
) -> Result<(), IdentityProviderError> {
    let txn = db
        .begin()
        .await
        .context("starting group deletion transaction")?;
    UserGroupMembership::delete_many()
        .filter(user_group_membership::Column::GroupId.eq(group_id.as_ref()))
        .exec(&txn)
        .await
        .context("removing group memberships")?;
    ExpiringUserGroupMembership::delete_many()
        .filter(expiring_user_group_membership::Column::GroupId.eq(group_id.as_ref()))
        .exec(&txn)
        .await
        .context("removing expiring group memberships")?;
    let res = DbGroup::delete_by_id(group_id.as_ref())
        .exec(&txn)
        .await
        .context("removing group record")?;
    if res.rows_affected != 1 {
        // Nothing was deleted: do not commit side effects on an error path.
        txn.rollback()
            .await
            .context("rolling back group deletion transaction")?;
        return Err(IdentityProviderError::GroupNotFound(
            group_id.as_ref().to_string(),
        ));
    }
    txn.commit()
        .await
        .context("committing group deletion transaction")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Statement, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_delete() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([
                MockExecResult {
                    rows_affected: 2,
                    ..Default::default()
                },
                MockExecResult {
                    rows_affected: 0,
                    ..Default::default()
                },
                MockExecResult {
                    rows_affected: 1,
                    ..Default::default()
                },
            ])
            .into_connection();

        delete(&db, "id").await.unwrap();
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::many([
                Statement::from_string(DatabaseBackend::Postgres, "BEGIN"),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "user_group_membership" WHERE "user_group_membership"."group_id" = $1"#,
                    ["id".into()]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "expiring_user_group_membership" WHERE "expiring_user_group_membership"."group_id" = $1"#,
                    ["id".into()]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "group" WHERE "group"."id" = $1"#,
                    ["id".into()]
                ),
                Statement::from_string(DatabaseBackend::Postgres, "COMMIT"),
            ])]
        );
    }

    #[tokio::test]
    async fn test_delete_not_found_rolls_back() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([
                MockExecResult {
                    rows_affected: 0,
                    ..Default::default()
                },
                MockExecResult {
                    rows_affected: 0,
                    ..Default::default()
                },
                MockExecResult {
                    rows_affected: 0,
                    ..Default::default()
                },
            ])
            .into_connection();

        assert!(matches!(
            delete(&db, "id").await,
            Err(IdentityProviderError::GroupNotFound(_))
        ));
        let log = db.into_transaction_log();
        let last = log[0].statements().last().map(|s| s.sql.clone());
        assert_eq!(last.as_deref(), Some("ROLLBACK"));
    }
}
