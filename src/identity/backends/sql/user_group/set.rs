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
use std::collections::BTreeSet;

use crate::db::entity::{prelude::UserGroupMembership, user_group_membership};
use crate::identity::backends::sql::{IdentityDatabaseError, db_err};

use super::{add_users_to_groups, remove_user_from_groups};

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
            .map_err(|e| db_err(e, "selecting group memberships of the user"))?
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

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::super::tests::get_user_group_mock;
    use super::*;

    #[tokio::test]
    async fn test_add_and_remove() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_user_group_mock("u1", "g1"),
                get_user_group_mock("u1", "g2"),
                get_user_group_mock("u1", "g3"),
                get_user_group_mock("u1", "g4"),
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
                get_user_group_mock("u1", "g1"),
                get_user_group_mock("u1", "g2"),
                get_user_group_mock("u1", "g3"),
                get_user_group_mock("u1", "g4"),
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
                get_user_group_mock("u1", "g1"),
                get_user_group_mock("u1", "g2"),
                get_user_group_mock("u1", "g3"),
                get_user_group_mock("u1", "g4"),
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
                get_user_group_mock("u1", "g1"),
                get_user_group_mock("u1", "g2"),
                get_user_group_mock("u1", "g3"),
                get_user_group_mock("u1", "g4"),
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
}
