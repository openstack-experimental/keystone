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

use crate::db::entity::{prelude::UserGroupMembership, user_group_membership};
use crate::identity::backends::sql::{IdentityDatabaseError, db_err};

/// Add the user to the single group.
pub async fn add_user_to_group<U: AsRef<str>, G: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
    group_id: G,
) -> Result<(), IdentityDatabaseError> {
    let entry = user_group_membership::ActiveModel {
        user_id: Set(user_id.as_ref().into()),
        group_id: Set(group_id.as_ref().into()),
    };

    entry
        .insert(db)
        .await
        .map_err(|e| db_err(e, "adding user to single group"))?;

    Ok(())
}

/// Add group user relations as specified by the tuples (user_id, group_id)
/// iterator.
pub async fn add_users_to_groups<I, U, G>(
    db: &DatabaseConnection,
    iter: I,
) -> Result<(), IdentityDatabaseError>
where
    I: IntoIterator<Item = (U, G)>,
    U: AsRef<str>,
    G: AsRef<str>,
{
    UserGroupMembership::insert_many(iter.into_iter().map(|(u, g)| {
        user_group_membership::ActiveModel {
            user_id: Set(u.as_ref().into()),
            group_id: Set(g.as_ref().into()),
        }
    }))
    .on_empty_do_nothing()
    .exec(db)
    .await
    .map_err(|e| db_err(e, "adding user to groups"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::super::tests::get_user_group_mock;
    use super::*;

    #[tokio::test]
    async fn test_create() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_user_group_mock("u1", "g1")]])
            .into_connection();

        assert!(add_user_to_group(&db, "u1", "g1").await.is_ok());
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "user_group_membership" ("user_id", "group_id") VALUES ($1, $2) RETURNING "user_id", "group_id""#,
                ["u1".into(), "g1".into(),]
            ),]
        );
    }
    #[tokio::test]
    async fn test_bulk() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        add_users_to_groups(&db, vec![("u1", "g1"), ("u1", "g2"), ("u2", "g2")])
            .await
            .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "user_group_membership" ("user_id", "group_id") VALUES ($1, $2), ($3, $4), ($5, $6) RETURNING "user_id", "group_id""#,
                [
                    "u1".into(),
                    "g1".into(),
                    "u1".into(),
                    "g2".into(),
                    "u2".into(),
                    "g2".into()
                ]
            ),]
        );
    }
}
