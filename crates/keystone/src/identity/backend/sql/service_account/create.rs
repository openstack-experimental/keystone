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
use sea_orm::TransactionTrait;
use sea_orm::entity::*;

use crate::config::Config;
use crate::error::DbContextExt;
use crate::identity::{
    IdentityProviderError,
    backend::sql::{nonlocal_user, user_option},
    types::*,
};

/// Create a service account.
///
/// Create a structure of the Keystone user representing the service account.
/// Comprise of:
///   - `user` table entry with no options.
///   - `nonlocal_user` table entry.
#[tracing::instrument(skip_all)]
pub async fn create(
    conf: &Config,
    db: &DatabaseConnection,
    sa: ServiceAccountCreate,
    created_at: Option<DateTime<Utc>>,
) -> Result<ServiceAccount, IdentityProviderError> {
    let txn = db
        .begin()
        .await
        .context("starting transaction for persisting service account")?;

    let main_entry = sa
        .to_user_active_model(conf, created_at)?
        .insert(&txn)
        .await
        .context("inserting main user for the service account entry")?;

    let nlu_entry = nonlocal_user::create(&txn, &main_entry, sa.name.clone()).await?;

    user_option::create(
        &txn,
        main_entry.id.clone(),
        &UserOptions {
            is_service_account: Some(true),
            ..Default::default()
        },
    )
    .await?;

    txn.commit()
        .await
        .context("committing the user creation transaction")?;

    Ok(ServiceAccount {
        domain_id: main_entry.domain_id,
        enabled: sa.enabled.unwrap_or(true),
        id: main_entry.id,
        name: nlu_entry.name,
    })
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Statement, Transaction};

    use super::*;
    use crate::db::entity::{nonlocal_user, user};

    #[tokio::test]
    async fn test_create() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![user::Model {
                id: "1".into(),
                domain_id: "did".into(),
                enabled: Some(true),
                ..Default::default()
            }]])
            .append_query_results([vec![nonlocal_user::Model {
                domain_id: "did".into(),
                name: "sa_foo".into(),
                user_id: "1".into(),
            }]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        let now = Utc::now();
        let req = ServiceAccountCreate {
            id: Some("1".into()),
            domain_id: "did".into(),
            name: "sa_foo".into(),
            enabled: Some(true),
        };
        assert_eq!(
            create(&Config::default(), &db, req, Some(now))
                .await
                .unwrap(),
            ServiceAccount {
                domain_id: "did".into(),
                enabled: true,
                id: "1".into(),
                name: "sa_foo".into()
            }
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::many(vec![
                Statement::from_string(DatabaseBackend::Postgres, r#"BEGIN"#,),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "user" ("created_at", "domain_id", "enabled", "extra", "id") VALUES ($1, $2, $3, $4, $5) RETURNING "created_at", "default_project_id", "domain_id", "enabled", "extra", "id", "last_active_at""#,
                    [
                        now.naive_utc().into(),
                        "did".into(),
                        true.into(),
                        "{}".into(),
                        "1".into(),
                    ]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "nonlocal_user" ("domain_id", "name", "user_id") VALUES ($1, $2, $3) RETURNING "domain_id", "name", "user_id""#,
                    ["did".into(), "sa_foo".into(), "1".into()]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "user_option" ("user_id", "option_id", "option_value") VALUES ($1, $2, $3) RETURNING "user_id", "option_id""#,
                    ["1".into(), "ISSA".into(), "true".into()]
                ),
                Statement::from_string(DatabaseBackend::Postgres, r#"COMMIT"#,)
            ]),]
        );
    }
}
