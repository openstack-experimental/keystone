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

use chrono::{DateTime, Utc};
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use std::collections::BTreeSet;
use tracing::debug;

use crate::db::entity::{
    expiring_user_group_membership,
    prelude::{ExpiringUserGroupMembership, UserGroupMembership},
    user_group_membership,
};
use crate::error::DbContextExt;
use crate::identity::backend::sql::IdentityDatabaseError;

use super::*;

/// Set user group memberships.
///
/// Add user to the groups it should be in and remove from the groups where the
/// user is currently member of, but should not be. This is only incremental
/// operation and is not deleting group membership where the user should stay.
pub async fn set_user_groups<I, U, G>(
    db: &DatabaseConnection,
    user_id: U,
    group_ids: I,
) -> Result<(), IdentityDatabaseError>
where
    I: IntoIterator<Item = G>,
    U: AsRef<str>,
    G: AsRef<str>,
{
    // Use BTreeSet to keep order for helping tests
    let expected_groups: BTreeSet<String> =
        BTreeSet::from_iter(group_ids.into_iter().map(|group| group.as_ref().into()));
    let current_groups: BTreeSet<String> = BTreeSet::from_iter(
        UserGroupMembership::find()
            .filter(user_group_membership::Column::UserId.eq(user_id.as_ref()))
            .all(db)
            .await
            .context("selecting group memberships of the user")?
            .into_iter()
            .map(|item| item.group_id),
    );

    let groups_to_remove: BTreeSet<String> = current_groups
        .iter()
        .filter(|&item| !expected_groups.contains(item))
        .cloned()
        .collect();

    let groups_to_add: BTreeSet<String> = expected_groups
        .iter()
        .filter(|&item| !current_groups.contains(item))
        .cloned()
        .collect();

    if !groups_to_remove.is_empty() {
        remove_user_from_groups(db, user_id.as_ref(), groups_to_remove).await?;
    }
    if !groups_to_add.is_empty() {
        add_users_to_groups(
            db,
            groups_to_add
                .into_iter()
                .map(|group| (user_id.as_ref(), group.clone())),
        )
        .await?;
    }

    Ok(())
}

/// Set expiring user group memberships.
///
/// Add user to the groups it should be in and remove from the groups where the
/// user is currently member of, but should not be. This is only incremental
/// operation and is not deleting group membership where the user should stay.
pub async fn set_user_groups_expiring<I, U, G, IDP>(
    db: &DatabaseConnection,
    user_id: U,
    group_ids: I,
    idp_id: IDP,
    last_verified: Option<&DateTime<Utc>>,
) -> Result<(), IdentityDatabaseError>
where
    I: IntoIterator<Item = G>,
    U: AsRef<str>,
    G: AsRef<str>,
    IDP: AsRef<str>,
{
    // Use BTreeSet to keep order for helping tests
    let expected_groups: BTreeSet<String> =
        BTreeSet::from_iter(group_ids.into_iter().map(|group| group.as_ref().into()));
    let current_groups: BTreeSet<String> = BTreeSet::from_iter(
        ExpiringUserGroupMembership::find()
            .filter(expiring_user_group_membership::Column::UserId.eq(user_id.as_ref()))
            .filter(expiring_user_group_membership::Column::IdpId.eq(idp_id.as_ref()))
            .all(db)
            .await
            .context("selecting expiring group memberships of the user")?
            .into_iter()
            .map(|item| item.group_id),
    );

    let groups_to_remove: BTreeSet<String> = current_groups
        .iter()
        .filter(|&item| !expected_groups.contains(item))
        .cloned()
        .collect();

    let groups_to_add: BTreeSet<String> = expected_groups
        .iter()
        .filter(|&item| !current_groups.contains(item))
        .cloned()
        .collect();

    if !groups_to_remove.is_empty() {
        debug!(
            "removing user {} from the following expiring groups {:?}",
            user_id.as_ref(),
            groups_to_remove
        );
        remove_user_from_groups_expiring(db, user_id.as_ref(), groups_to_remove, idp_id.as_ref())
            .await?;
    }
    if !groups_to_add.is_empty() {
        debug!(
            "adding user {} to the following expiring groups {:?}",
            user_id.as_ref(),
            groups_to_add
        );
        add_users_to_groups_expiring(
            db,
            groups_to_add
                .iter()
                //.cloned()
                .map(|group| (user_id.as_ref(), group.as_str())),
            idp_id.as_ref(),
            last_verified,
        )
        .await?;
    }
    ExpiringUserGroupMembership::update_many()
        .col_expr(
            expiring_user_group_membership::Column::LastVerified,
            last_verified.unwrap_or(&Utc::now()).naive_utc().into(),
        )
        .filter(expiring_user_group_membership::Column::UserId.eq(user_id.as_ref()))
        .filter(expiring_user_group_membership::Column::IdpId.eq(idp_id.as_ref()))
        .filter(
            expiring_user_group_membership::Column::GroupId
                .is_in(expected_groups.difference(&groups_to_add)),
        )
        .exec(db)
        .await
        .context("renewing expiring group memberships of the user")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::super::tests::{
        get_expiring_user_group_membership_mock, get_user_group_membership_mock,
    };
    use super::*;

    #[tokio::test]
    async fn test_add_and_remove() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_user_group_membership_mock("u1", "g1"),
                get_user_group_membership_mock("u1", "g2"),
                get_user_group_membership_mock("u1", "g3"),
                get_user_group_membership_mock("u1", "g4"),
            ]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        set_user_groups(&db, "u1", vec!["g2", "g4", "g5", "g0"])
            .await
            .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user_group_membership"."user_id", "user_group_membership"."group_id" FROM "user_group_membership" WHERE "user_group_membership"."user_id" = $1"#,
                    ["u1".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "user_group_membership" WHERE "user_group_membership"."user_id" = $1 AND "user_group_membership"."group_id" IN ($2, $3)"#,
                    ["u1".into(), "g1".into(), "g3".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "user_group_membership" ("user_id", "group_id") VALUES ($1, $2), ($3, $4) RETURNING "user_id", "group_id""#,
                    ["u1".into(), "g0".into(), "u1".into(), "g5".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_only_add() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_user_group_membership_mock("u1", "g1"),
                get_user_group_membership_mock("u1", "g2"),
                get_user_group_membership_mock("u1", "g3"),
                get_user_group_membership_mock("u1", "g4"),
            ]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        set_user_groups(&db, "u1", vec!["g1", "g2", "g3", "g4", "g5"])
            .await
            .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user_group_membership"."user_id", "user_group_membership"."group_id" FROM "user_group_membership" WHERE "user_group_membership"."user_id" = $1"#,
                    ["u1".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "user_group_membership" ("user_id", "group_id") VALUES ($1, $2) RETURNING "user_id", "group_id""#,
                    ["u1".into(), "g5".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_only_delete() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_user_group_membership_mock("u1", "g1"),
                get_user_group_membership_mock("u1", "g2"),
                get_user_group_membership_mock("u1", "g3"),
                get_user_group_membership_mock("u1", "g4"),
            ]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        set_user_groups(&db, "u1", vec!["g2", "g4"]).await.unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user_group_membership"."user_id", "user_group_membership"."group_id" FROM "user_group_membership" WHERE "user_group_membership"."user_id" = $1"#,
                    ["u1".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "user_group_membership" WHERE "user_group_membership"."user_id" = $1 AND "user_group_membership"."group_id" IN ($2, $3)"#,
                    ["u1".into(), "g1".into(), "g3".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_no_change() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_user_group_membership_mock("u1", "g1"),
                get_user_group_membership_mock("u1", "g2"),
                get_user_group_membership_mock("u1", "g3"),
                get_user_group_membership_mock("u1", "g4"),
            ]])
            .into_connection();

        set_user_groups(&db, "u1", vec!["g1", "g2", "g3", "g4"])
            .await
            .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "user_group_membership"."user_id", "user_group_membership"."group_id" FROM "user_group_membership" WHERE "user_group_membership"."user_id" = $1"#,
                ["u1".into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_expiring_add_and_remove() {
        let expiry = Utc::now();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_expiring_user_group_membership_mock("u1", "g1", expiry),
                get_expiring_user_group_membership_mock("u1", "g2", expiry),
                get_expiring_user_group_membership_mock("u1", "g3", expiry),
                get_expiring_user_group_membership_mock("u1", "g4", expiry),
            ]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();
        let last_verified = Utc::now();

        set_user_groups_expiring(
            &db,
            "u1",
            vec!["g2", "g4", "g5", "g0"],
            "idp_id",
            Some(&last_verified),
        )
        .await
        .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "expiring_user_group_membership"."user_id", "expiring_user_group_membership"."group_id", "expiring_user_group_membership"."idp_id", "expiring_user_group_membership"."last_verified" FROM "expiring_user_group_membership" WHERE "expiring_user_group_membership"."user_id" = $1 AND "expiring_user_group_membership"."idp_id" = $2"#,
                    ["u1".into(), "idp_id".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "expiring_user_group_membership" WHERE "expiring_user_group_membership"."user_id" = $1 AND "expiring_user_group_membership"."group_id" IN ($2, $3) AND "expiring_user_group_membership"."idp_id" = $4"#,
                    ["u1".into(), "g1".into(), "g3".into(), "idp_id".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "expiring_user_group_membership" ("user_id", "group_id", "idp_id", "last_verified") VALUES ($1, $2, $3, $4), ($5, $6, $7, $8) RETURNING "user_id", "group_id", "idp_id""#,
                    [
                        "u1".into(),
                        "g0".into(),
                        "idp_id".into(),
                        last_verified.naive_utc().into(),
                        "u1".into(),
                        "g5".into(),
                        "idp_id".into(),
                        last_verified.naive_utc().into(),
                    ]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"UPDATE "expiring_user_group_membership" SET "last_verified" = $1 WHERE "expiring_user_group_membership"."user_id" = $2 AND "expiring_user_group_membership"."idp_id" = $3 AND "expiring_user_group_membership"."group_id" IN ($4, $5)"#,
                    [
                        last_verified.naive_utc().into(),
                        "u1".into(),
                        "idp_id".into(),
                        "g2".into(),
                        "g4".into()
                    ]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_expiring_only_add() {
        let expiry = Utc::now();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_expiring_user_group_membership_mock("u1", "g1", expiry),
                get_expiring_user_group_membership_mock("u1", "g2", expiry),
                get_expiring_user_group_membership_mock("u1", "g3", expiry),
                get_expiring_user_group_membership_mock("u1", "g4", expiry),
            ]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();
        let last_verified = Utc::now();

        set_user_groups_expiring(
            &db,
            "u1",
            vec!["g1", "g2", "g3", "g4", "g5"],
            "idp_id",
            Some(&last_verified),
        )
        .await
        .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "expiring_user_group_membership"."user_id", "expiring_user_group_membership"."group_id", "expiring_user_group_membership"."idp_id", "expiring_user_group_membership"."last_verified" FROM "expiring_user_group_membership" WHERE "expiring_user_group_membership"."user_id" = $1 AND "expiring_user_group_membership"."idp_id" = $2"#,
                    ["u1".into(), "idp_id".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "expiring_user_group_membership" ("user_id", "group_id", "idp_id", "last_verified") VALUES ($1, $2, $3, $4) RETURNING "user_id", "group_id", "idp_id""#,
                    [
                        "u1".into(),
                        "g5".into(),
                        "idp_id".into(),
                        last_verified.naive_utc().into()
                    ]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"UPDATE "expiring_user_group_membership" SET "last_verified" = $1 WHERE "expiring_user_group_membership"."user_id" = $2 AND "expiring_user_group_membership"."idp_id" = $3 AND "expiring_user_group_membership"."group_id" IN ($4, $5, $6, $7)"#,
                    [
                        last_verified.naive_utc().into(),
                        "u1".into(),
                        "idp_id".into(),
                        "g1".into(),
                        "g2".into(),
                        "g3".into(),
                        "g4".into()
                    ]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_expiring_only_delete() {
        let expiry = Utc::now();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_expiring_user_group_membership_mock("u1", "g1", expiry),
                get_expiring_user_group_membership_mock("u1", "g2", expiry),
                get_expiring_user_group_membership_mock("u1", "g3", expiry),
                get_expiring_user_group_membership_mock("u1", "g4", expiry),
            ]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        let last_verified = Utc::now();
        set_user_groups_expiring(&db, "u1", vec!["g2", "g4"], "idp_id", Some(&last_verified))
            .await
            .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "expiring_user_group_membership"."user_id", "expiring_user_group_membership"."group_id", "expiring_user_group_membership"."idp_id", "expiring_user_group_membership"."last_verified" FROM "expiring_user_group_membership" WHERE "expiring_user_group_membership"."user_id" = $1 AND "expiring_user_group_membership"."idp_id" = $2"#,
                    ["u1".into(), "idp_id".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "expiring_user_group_membership" WHERE "expiring_user_group_membership"."user_id" = $1 AND "expiring_user_group_membership"."group_id" IN ($2, $3) AND "expiring_user_group_membership"."idp_id" = $4"#,
                    ["u1".into(), "g1".into(), "g3".into(), "idp_id".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"UPDATE "expiring_user_group_membership" SET "last_verified" = $1 WHERE "expiring_user_group_membership"."user_id" = $2 AND "expiring_user_group_membership"."idp_id" = $3 AND "expiring_user_group_membership"."group_id" IN ($4, $5)"#,
                    [
                        last_verified.naive_utc().into(),
                        "u1".into(),
                        "idp_id".into(),
                        "g2".into(),
                        "g4".into()
                    ]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_expiring_no_change() {
        let expiry = Utc::now();
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_expiring_user_group_membership_mock("u1", "g1", expiry),
                get_expiring_user_group_membership_mock("u1", "g2", expiry),
                get_expiring_user_group_membership_mock("u1", "g3", expiry),
                get_expiring_user_group_membership_mock("u1", "g4", expiry),
            ]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        let last_verified = Utc::now();
        set_user_groups_expiring(
            &db,
            "u1",
            vec!["g1", "g2", "g3", "g4"],
            "idp_id",
            Some(&last_verified),
        )
        .await
        .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "expiring_user_group_membership"."user_id", "expiring_user_group_membership"."group_id", "expiring_user_group_membership"."idp_id", "expiring_user_group_membership"."last_verified" FROM "expiring_user_group_membership" WHERE "expiring_user_group_membership"."user_id" = $1 AND "expiring_user_group_membership"."idp_id" = $2"#,
                    ["u1".into(), "idp_id".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"UPDATE "expiring_user_group_membership" SET "last_verified" = $1 WHERE "expiring_user_group_membership"."user_id" = $2 AND "expiring_user_group_membership"."idp_id" = $3 AND "expiring_user_group_membership"."group_id" IN ($4, $5, $6, $7)"#,
                    [
                        last_verified.naive_utc().into(),
                        "u1".into(),
                        "idp_id".into(),
                        "g1".into(),
                        "g2".into(),
                        "g3".into(),
                        "g4".into()
                    ]
                ),
            ]
        );
    }
}
