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

use crate::catalog::backend::error::CatalogDatabaseError;
use crate::catalog::types::*;
use crate::db::entity::{prelude::Service as DbService, service as db_service};
use crate::error::DbContextExt;

pub async fn list(
    db: &DatabaseConnection,
    params: &ServiceListParameters,
) -> Result<Vec<Service>, CatalogDatabaseError> {
    let mut select = DbService::find();

    if let Some(typ) = &params.r#type {
        select = select.filter(db_service::Column::Type.eq(typ));
    }

    select
        .all(db)
        .await
        .context("fetching services")?
        .into_iter()
        .map(TryInto::<Service>::try_into)
        .collect()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
    use serde_json::json;

    use super::super::tests::get_service_mock;
    use super::*;

    #[tokio::test]
    async fn test_list() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_service_mock("1".into())]])
            .append_query_results([vec![get_service_mock("1".into())]])
            .into_connection();
        assert!(list(&db, &ServiceListParameters::default()).await.is_ok());
        assert_eq!(
            list(
                &db,
                &ServiceListParameters {
                    r#type: Some("type".into()),
                    name: Some("service_name".into())
                }
            )
            .await
            .unwrap(),
            vec![Service {
                id: "1".into(),
                r#type: Some("type".into()),
                enabled: true,
                name: Some("srv".into()),
                extra: Some(json!({"name": "srv"})),
            }]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "service"."id", "service"."type", "service"."enabled", "service"."extra" FROM "service""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "service"."id", "service"."type", "service"."enabled", "service"."extra" FROM "service" WHERE "service"."type" = $1"#,
                    ["type".into()]
                ),
            ]
        );
    }
}
