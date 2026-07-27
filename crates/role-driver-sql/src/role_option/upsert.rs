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
use sea_orm::sea_query::OnConflict;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::role::RoleProviderError;
use openstack_keystone_core_types::role::RoleOptions;

use crate::entity::prelude::RoleOption as DbRoleOption;
use crate::entity::role_option as db_role_option;
use crate::role_option::RoleOptionIntoModelIterator;

/// Upsert role options.
///
/// Used both on creation (no existing rows can conflict) and on update
/// (a previously-set option is overwritten in place), so the same conflict
/// resolution path serves both callers.
///
/// # Parameters
/// - `db`: The database connection.
/// - `role_id`: The role ID.
/// - `opts`: The resource options to persist.
///
/// # Returns
/// A `Result` containing `()` if successful, or an `Error`.
#[tracing::instrument(skip_all)]
pub async fn upsert<C, R>(db: &C, role_id: R, opts: &RoleOptions) -> Result<(), RoleProviderError>
where
    C: ConnectionTrait,
    R: Into<String>,
{
    let rows: Vec<db_role_option::ActiveModel> = opts
        .to_model_iter(role_id)
        .into_iter()
        .map(Into::<db_role_option::ActiveModel>::into)
        .collect();
    if !rows.is_empty() {
        DbRoleOption::insert_many(rows)
            .on_conflict(
                OnConflict::columns([
                    db_role_option::Column::RoleId,
                    db_role_option::Column::OptionId,
                ])
                .update_column(db_role_option::Column::OptionValue)
                .to_owned(),
            )
            .exec(db)
            .await
            .context("upserting role options")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_upsert_empty_is_noop() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
        upsert(&db, "1", &RoleOptions::default()).await.unwrap();
        assert_eq!(db.into_transaction_log(), []);
    }

    #[tokio::test]
    async fn test_upsert_immutable() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_role_option::Model {
                role_id: "1".into(),
                option_id: "IMMU".into(),
                option_value: Some("true".into()),
            }]])
            .into_connection();
        upsert(
            &db,
            "1",
            &RoleOptions {
                immutable: Some(true),
            },
        )
        .await
        .unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "role_option" ("role_id", "option_id", "option_value") VALUES ($1, $2, $3) ON CONFLICT ("role_id", "option_id") DO UPDATE SET "option_value" = "excluded"."option_value" RETURNING "role_id", "option_id""#,
                ["1".into(), "IMMU".into(), "true".into()]
            ),]
        );
    }
}
