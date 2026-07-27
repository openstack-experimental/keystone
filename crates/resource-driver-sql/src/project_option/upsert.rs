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
use openstack_keystone_core::resource::ResourceProviderError;
use openstack_keystone_core_types::resource::ProjectOptions;

use crate::entity::prelude::ProjectOption as DbProjectOption;
use crate::entity::project_option as db_project_option;
use crate::project_option::ProjectOptionIntoModelIterator;

/// Upsert project (or domain) options.
///
/// Used both on creation (no existing rows can conflict) and on update
/// (a previously-set option is overwritten in place), so the same conflict
/// resolution path serves both callers.
///
/// # Parameters
/// - `db`: The database connection.
/// - `project_id`: The project (or domain) ID.
/// - `opts`: The resource options to persist.
///
/// # Returns
/// A `Result` containing `()` if successful, or an `Error`.
#[tracing::instrument(skip_all)]
pub async fn upsert<C, P>(
    db: &C,
    project_id: P,
    opts: &ProjectOptions,
) -> Result<(), ResourceProviderError>
where
    C: ConnectionTrait,
    P: Into<String>,
{
    let rows: Vec<db_project_option::ActiveModel> = opts
        .to_model_iter(project_id)
        .into_iter()
        .map(Into::<db_project_option::ActiveModel>::into)
        .collect();
    if !rows.is_empty() {
        DbProjectOption::insert_many(rows)
            .on_conflict(
                OnConflict::columns([
                    db_project_option::Column::ProjectId,
                    db_project_option::Column::OptionId,
                ])
                .update_column(db_project_option::Column::OptionValue)
                .to_owned(),
            )
            .exec(db)
            .await
            .context("upserting project options")?;
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
        upsert(&db, "1", &ProjectOptions::default()).await.unwrap();
        assert_eq!(db.into_transaction_log(), []);
    }

    #[tokio::test]
    async fn test_upsert_immutable() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_project_option::Model {
                project_id: "1".into(),
                option_id: "IMMU".into(),
                option_value: Some("true".into()),
            }]])
            .into_connection();
        upsert(
            &db,
            "1",
            &ProjectOptions {
                immutable: Some(true),
            },
        )
        .await
        .unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "project_option" ("project_id", "option_id", "option_value") VALUES ($1, $2, $3) ON CONFLICT ("project_id", "option_id") DO UPDATE SET "option_value" = "excluded"."option_value" RETURNING "project_id", "option_id""#,
                ["1".into(), "IMMU".into(), "true".into()]
            ),]
        );
    }
}
