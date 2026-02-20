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

use sea_orm::ConnectionTrait;
use sea_orm::entity::*;

use crate::db::entity::prelude::UserOption as DbUserOption;
use crate::db::entity::user_option as db_user_option;
use crate::error::DbContextExt;
use crate::identity::{IdentityProviderError, types::UserOptions};

/// Persist user options.
#[tracing::instrument(skip_all)]
pub async fn create<C, U>(
    db: &C,
    user_id: U,
    opts: &UserOptions,
) -> Result<(), IdentityProviderError>
where
    C: ConnectionTrait,
    U: Into<String>,
{
    let rows: Vec<db_user_option::ActiveModel> = opts
        .to_model_iter(user_id)?
        .into_iter()
        .map(Into::<db_user_option::ActiveModel>::into)
        .collect();
    if !rows.is_empty() {
        DbUserOption::insert_many(rows)
            .exec(db)
            .await
            .context("inserting new user options")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
        create(&db, "1", &UserOptions::default()).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_issa() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();
        create(
            &db,
            "1",
            &UserOptions {
                is_service_account: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "user_option" ("user_id", "option_id", "option_value") VALUES ($1, $2, $3) RETURNING "user_id", "option_id""#,
                ["1".into(), "ISSA".into(), "true".into(),]
            ),]
        );
    }
}
