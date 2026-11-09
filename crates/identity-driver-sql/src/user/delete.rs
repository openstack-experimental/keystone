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
    expiring_user_group_membership, prelude::ExpiringUserGroupMembership, prelude::User as DbUser,
    prelude::UserGroupMembership, user_group_membership,
};

/// Delete a user by its ID.
///
/// The user<->group membership rows (direct and expiring) reference the user
/// without a cascading foreign key, so they are removed in the same
/// transaction before the user record itself (python-keystone drops them the
/// same way). The local, non-local, federated and password rows go with the
/// user through their own cascading foreign keys.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_id`: The user ID.
///
/// # Returns
/// A `Result` containing `()` if successful, or an `Error`.
pub async fn delete<U: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
) -> Result<(), IdentityProviderError> {
    let txn = db
        .begin()
        .await
        .context("starting user deletion transaction")?;
    UserGroupMembership::delete_many()
        .filter(user_group_membership::Column::UserId.eq(user_id.as_ref()))
        .exec(&txn)
        .await
        .context("removing user group memberships")?;
    ExpiringUserGroupMembership::delete_many()
        .filter(expiring_user_group_membership::Column::UserId.eq(user_id.as_ref()))
        .exec(&txn)
        .await
        .context("removing expiring user group memberships")?;
    let res = DbUser::delete_by_id(user_id.as_ref())
        .exec(&txn)
        .await
        .context("deleting the user record")?;
    if res.rows_affected != 1 {
        // Nothing was deleted: do not commit side effects on an error path.
        txn.rollback()
            .await
            .context("rolling back user deletion transaction")?;
        return Err(IdentityProviderError::UserNotFound(
            user_id.as_ref().to_string(),
        ));
    }
    txn.commit()
        .await
        .context("committing user deletion transaction")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Statement, Transaction};

    use super::*;

    fn exec(rows_affected: u64) -> MockExecResult {
        MockExecResult {
            rows_affected,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_delete() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([exec(2), exec(0), exec(1)])
            .into_connection();

        delete(&db, "id").await.unwrap();
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::many([
                Statement::from_string(DatabaseBackend::Postgres, "BEGIN"),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "user_group_membership" WHERE "user_group_membership"."user_id" = $1"#,
                    ["id".into()]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "expiring_user_group_membership" WHERE "expiring_user_group_membership"."user_id" = $1"#,
                    ["id".into()]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "user" WHERE "user"."id" = $1"#,
                    ["id".into()]
                ),
                Statement::from_string(DatabaseBackend::Postgres, "COMMIT"),
            ])]
        );
    }

    #[tokio::test]
    async fn test_delete_not_found_rolls_back() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([exec(0), exec(0), exec(0)])
            .into_connection();

        assert!(matches!(
            delete(&db, "id").await,
            Err(IdentityProviderError::UserNotFound(_))
        ));
        let log = db.into_transaction_log();
        let last = log[0].statements().last().map(|s| s.sql.clone());
        assert_eq!(last.as_deref(), Some("ROLLBACK"));
    }
}
