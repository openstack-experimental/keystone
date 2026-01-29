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
use uuid::Uuid;

use crate::db::entity::{nonlocal_user as db_nonlocal_user, user as db_user};
use crate::error::DbContextExt;
use crate::identity::backend::sql::IdentityDatabaseError;
use crate::identity::types::*;

/// Create the service account.
///
/// Create a structure of the Keystone user representing the service account. Comprise of:
///   - `user` table entry with no options.
///   - `nonlocal_user` table entry.
pub async fn create(
    db: &DatabaseConnection,
    sa: ServiceAccountCreate,
    create_date: Option<DateTime<Utc>>,
) -> Result<ServiceAccount, IdentityDatabaseError> {
    // Do a lot of stuff in a transaction

    let txn = db
        .begin()
        .await
        .context("starting transaction for persisting service account")?;

    let main_entry = db_user::ActiveModel {
        id: Set(sa.id.clone().unwrap_or(Uuid::new_v4().simple().to_string())),
        enabled: Set(sa.enabled),
        extra: NotSet,
        default_project_id: NotSet,
        last_active_at: NotSet,
        created_at: Set(Some(create_date.unwrap_or_else(Utc::now).naive_utc())),
        domain_id: Set(sa.domain_id.clone()),
    }
    .insert(&txn)
    .await
    .context("inserting main user for the service account entry")?;

    let nlu_entry = db_nonlocal_user::ActiveModel {
        domain_id: Set(sa.domain_id.clone()),
        name: Set(sa.name.clone()),
        user_id: Set(main_entry.id.clone()),
    }
    .insert(&txn)
    .await
    .context("inserting new nonlocal user record for the service account")?;

    let opts = get_user_options_db_entries(
        main_entry.id.clone(),
        UserOptions {
            is_service_account: Some(true),
            ..Default::default()
        },
    )?;



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
    use sea_orm::{DatabaseBackend, MockDatabase, Statement, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_create() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_user::Model {
                id: "1".into(),
                domain_id: "did".into(),
                enabled: Some(true),
                ..Default::default()
            }]])
            .append_query_results([
                vec![db_nonlocal_user::Model {
                    domain_id: "did".into(),
                    name: "sa_foo".into(),
                    user_id: "1".into(),
                }],
                vec![],
            ])
            .into_connection();

        let now = Utc::now();
        let req = ServiceAccountCreate {
            id: Some("1".into()),
            domain_id: "did".into(),
            name: "sa_foo".into(),
            enabled: Some(true),
        };
        assert_eq!(
            create(&db, req, Some(now)).await.unwrap(),
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
                    r#"INSERT INTO "user" ("id", "enabled", "created_at", "domain_id") VALUES ($1, $2, $3, $4) RETURNING "id", "extra", "enabled", "default_project_id", "created_at", "last_active_at", "domain_id""#,
                    [
                        "1".into(),
                        true.into(),
                        now.naive_utc().into(),
                        "did".into(),
                    ]
                ),
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"INSERT INTO "nonlocal_user" ("domain_id", "name", "user_id") VALUES ($1, $2, $3) RETURNING "domain_id", "name", "user_id""#,
                    ["did".into(), "sa_foo".into(), "1".into()]
                ),
                Statement::from_string(DatabaseBackend::Postgres, r#"COMMIT"#,)
            ]),]
        );
    }
}
