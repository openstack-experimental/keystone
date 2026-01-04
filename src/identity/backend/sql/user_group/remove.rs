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

use crate::db::entity::{
    expiring_user_group_membership,
    prelude::{ExpiringUserGroupMembership, UserGroupMembership},
    user_group_membership,
};
use crate::error::DbContextExt;
use crate::identity::backend::sql::IdentityDatabaseError;

/// Remove the user from the group.
pub async fn remove_user_from_group<U: AsRef<str>, G: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
    group_id: G,
) -> Result<(), IdentityDatabaseError> {
    UserGroupMembership::delete_by_id((user_id.as_ref().into(), group_id.as_ref().into()))
        .exec(db)
        .await
        .context("Deleting user<->group membership relation")?;

    Ok(())
}

/// Remove the user from multiple groups.
pub async fn remove_user_from_groups<I, U, G>(
    db: &DatabaseConnection,
    user_id: U,
    group_ids: I,
) -> Result<(), IdentityDatabaseError>
where
    I: IntoIterator<Item = G>,
    U: AsRef<str>,
    G: AsRef<str>,
{
    UserGroupMembership::delete_many()
        .filter(
            Condition::all()
                .add(user_group_membership::Column::UserId.eq(user_id.as_ref()))
                .add(
                    user_group_membership::Column::GroupId
                        .is_in(group_ids.into_iter().map(|grp| grp.as_ref().to_string())),
                ),
        )
        .exec(db)
        .await
        .context("Deleting user<->group membership relations")?;

    Ok(())
}

/// Remove the user from the group with expiration.
pub async fn remove_user_from_group_expiring<U: AsRef<str>, G: AsRef<str>, IDP: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
    group_id: G,
    idp_id: IDP,
) -> Result<(), IdentityDatabaseError> {
    ExpiringUserGroupMembership::delete_by_id((
        user_id.as_ref().into(),
        group_id.as_ref().into(),
        idp_id.as_ref().into(),
    ))
    .exec(db)
    .await
    .context("Deleting expiring user<->group membership relation")?;

    Ok(())
}

/// Remove the user from multiple groups.
pub async fn remove_user_from_groups_expiring<I, U, G, IDP>(
    db: &DatabaseConnection,
    user_id: U,
    group_ids: I,
    idp_id: IDP,
) -> Result<(), IdentityDatabaseError>
where
    I: IntoIterator<Item = G>,
    U: AsRef<str>,
    G: AsRef<str>,
    IDP: AsRef<str>,
{
    ExpiringUserGroupMembership::delete_many()
        .filter(
            Condition::all()
                .add(expiring_user_group_membership::Column::UserId.eq(user_id.as_ref()))
                .add(
                    expiring_user_group_membership::Column::GroupId
                        .is_in(group_ids.into_iter().map(|grp| grp.as_ref().to_string())),
                )
                .add(expiring_user_group_membership::Column::IdpId.eq(idp_id.as_ref())),
        )
        .exec(db)
        .await
        .context("Deleting user<->group membership relations")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_remove_single() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        remove_user_from_group(&db, "u1", "g1").await.unwrap();
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "user_group_membership" WHERE "user_group_membership"."user_id" = $1 AND "user_group_membership"."group_id" = $2"#,
                ["u1".into(), "g1".into(),]
            ),]
        );
    }

    #[tokio::test]
    async fn test_remove_from_groups() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        remove_user_from_groups(&db, "u1", vec!["g1", "g2", "g3"])
            .await
            .unwrap();
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "user_group_membership" WHERE "user_group_membership"."user_id" = $1 AND "user_group_membership"."group_id" IN ($2, $3, $4)"#,
                ["u1".into(), "g1".into(), "g2".into(), "g3".into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_remove_expiring_single() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        remove_user_from_group_expiring(&db, "u1", "g1", "idp_id")
            .await
            .unwrap();
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "expiring_user_group_membership" WHERE "expiring_user_group_membership"."user_id" = $1 AND "expiring_user_group_membership"."group_id" = $2 AND "expiring_user_group_membership"."idp_id" = $3"#,
                ["u1".into(), "g1".into(), "idp_id".into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_remove_expiring_from_groups() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        remove_user_from_groups_expiring(&db, "u1", vec!["g1", "g2", "g3"], "idp_id")
            .await
            .unwrap();
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "expiring_user_group_membership" WHERE "expiring_user_group_membership"."user_id" = $1 AND "expiring_user_group_membership"."group_id" IN ($2, $3, $4) AND "expiring_user_group_membership"."idp_id" = $5"#,
                [
                    "u1".into(),
                    "g1".into(),
                    "g2".into(),
                    "g3".into(),
                    "idp_id".into()
                ]
            ),]
        );
    }
}
