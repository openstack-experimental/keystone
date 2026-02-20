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
//! Set user properties.

use chrono::Utc;
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use crate::db::entity::user as db_user;
use crate::error::DbContextExt;
use crate::identity::IdentityProviderError;

/// Reset the `user.last_active_at` to the current date.
#[tracing::instrument(skip_all)]
pub async fn reset_last_active(
    db: &DatabaseConnection,
    user: &db_user::Model,
) -> Result<db_user::Model, IdentityProviderError> {
    let mut update: db_user::ActiveModel = user.clone().into();
    update.last_active_at = Set(Some(Utc::now().date_naive()));
    Ok(update
        .update(db)
        .await
        .context("resetting user's last_active_at")?)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_user_mock;
    use super::*;

    #[tokio::test]
    async fn test_reset_last_active() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_user_mock("user_id")]])
            .into_connection();
        assert!(
            reset_last_active(&db, &get_user_mock("user_id"))
                .await
                .is_ok()
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"UPDATE "user" SET "last_active_at" = $1 WHERE "user"."id" = $2 RETURNING "created_at", "default_project_id", "domain_id", "enabled", "extra", "id", "last_active_at""#,
                [Utc::now().date_naive().into(), "user_id".into()]
            ),]
        );
    }
}
