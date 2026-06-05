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

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::identity::IdentityProviderError;

use crate::entity::local_user as db_local_user;

/// Reset the failed authentication counters for a local user.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user`: The local user model.
///
/// # Returns
/// A `Result` containing the updated `db_local_user::Model` if successful, or
/// an `Error`.
#[tracing::instrument(skip_all)]
pub async fn reset_failed_auth(
    db: &DatabaseConnection,
    user: &db_local_user::Model,
) -> Result<db_local_user::Model, IdentityProviderError> {
    let mut update: db_local_user::ActiveModel = user.clone().into();
    update.failed_auth_count = Set(None);
    update.failed_auth_at = Set(None);
    Ok(update
        .update(db)
        .await
        .context("resetting local user failed auth counters")?)
}

/// Increase the failed authentication attempt for a local user.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user`: The local user model.
/// - `attempt_at`: The timestamp of the failed authentication attempt.
///
/// # Returns
/// A `Result` containing the updated `db_local_user::Model` if successful, or
/// an `Error`.
#[tracing::instrument(skip_all)]
pub async fn log_failed_auth(
    db: &DatabaseConnection,
    user: &db_local_user::Model,
    attempt_at: DateTime<Utc>,
) -> Result<db_local_user::Model, IdentityProviderError> {
    let mut update: db_local_user::ActiveModel = user.clone().into();
    update.failed_auth_count = Set(Some(user.failed_auth_count.unwrap_or_default() + 1));
    update.failed_auth_at = Set(Some(attempt_at.naive_utc()));
    Ok(update
        .update(db)
        .await
        .context("incrementing local user failed auth count")?)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::*;
    use crate::local_user::tests::get_local_user_mock;

    #[tokio::test]
    async fn test_log_failed_auth_from_zero() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_local_user_mock("user_id")]])
            .into_connection();
        let now = Utc::now();
        let user = get_local_user_mock("user_id");
        assert!(log_failed_auth(&db, &user, now).await.is_ok());

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"UPDATE "local_user" SET "failed_auth_count" = $1, "failed_auth_at" = $2 WHERE "local_user"."id" = $3 RETURNING "id", "user_id", "domain_id", "name", "failed_auth_count", "failed_auth_at""#,
                [Some(1i32).into(), Some(now.naive_utc()).into(), 1i32.into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_log_failed_auth_count_incremented() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_local_user::Model {
                id: 1,
                user_id: "user_id".into(),
                domain_id: "foo_domain".into(),
                name: "foo_domain".into(),
                failed_auth_count: Some(3),
                failed_auth_at: Some(Utc::now().naive_utc()),
            }]])
            .into_connection();
        let now = Utc::now();
        let user = db_local_user::Model {
            id: 1,
            user_id: "user_id".into(),
            domain_id: "foo_domain".into(),
            name: "foo_domain".into(),
            failed_auth_count: Some(3),
            failed_auth_at: Some(Utc::now().naive_utc()),
        };
        assert!(log_failed_auth(&db, &user, now).await.is_ok());

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"UPDATE "local_user" SET "failed_auth_count" = $1, "failed_auth_at" = $2 WHERE "local_user"."id" = $3 RETURNING "id", "user_id", "domain_id", "name", "failed_auth_count", "failed_auth_at""#,
                [Some(4i32).into(), Some(now.naive_utc()).into(), 1i32.into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_log_failed_auth_count_from_none() {
        let user = db_local_user::Model {
            id: 1,
            user_id: "user_id".into(),
            domain_id: "foo_domain".into(),
            name: "foo_domain".into(),
            failed_auth_count: None,
            failed_auth_at: None,
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![user.clone()]])
            .into_connection();
        let now = Utc::now();
        assert!(log_failed_auth(&db, &user, now).await.is_ok());

        // Checking transaction log - None + 1 should default to 0 + 1 = 1
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"UPDATE "local_user" SET "failed_auth_count" = $1, "failed_auth_at" = $2 WHERE "local_user"."id" = $3 RETURNING "id", "user_id", "domain_id", "name", "failed_auth_count", "failed_auth_at""#,
                [Some(1i32).into(), Some(now.naive_utc()).into(), 1i32.into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_reset_failed_auth() {
        let user = db_local_user::Model {
            id: 1,
            user_id: "user_id".into(),
            domain_id: "foo_domain".into(),
            name: "foo_domain".into(),
            failed_auth_count: Some(5),
            failed_auth_at: Some(Utc::now().naive_utc()),
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![user.clone()]])
            .into_connection();
        assert!(reset_failed_auth(&db, &user).await.is_ok());

        // Checking transaction log - both fields should be reset to None
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"UPDATE "local_user" SET "failed_auth_count" = $1, "failed_auth_at" = $2 WHERE "local_user"."id" = $3 RETURNING "id", "user_id", "domain_id", "name", "failed_auth_count", "failed_auth_at""#,
                [
                    None::<i32>.into(),
                    None::<chrono::NaiveDateTime>.into(),
                    1i32.into()
                ]
            ),]
        );
    }
}
