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

use crate::catalog::{CatalogProviderError, types::Service};
use crate::db::entity::prelude::Service as DbService;
use crate::error::DbContextExt;

pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Service>, CatalogProviderError> {
    let select = DbService::find_by_id(id.as_ref());

    select
        .one(db)
        .await
        .context("fetching service by ID")?
        .map(TryInto::try_into)
        .transpose()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
    use serde_json::json;

    use super::super::tests::get_service_mock;
    use super::*;

    #[tokio::test]
    async fn test_get() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([
                // First query result - select user itself
                vec![get_service_mock("1".into())],
            ])
            .into_connection();
        assert_eq!(
            get(&db, "1").await.unwrap().unwrap(),
            Service {
                id: "1".into(),
                r#type: Some("type".into()),
                enabled: true,
                name: Some("srv".into()),
                extra: Some(json!({"name": "srv"})),
            }
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "service"."id", "service"."type", "service"."enabled", "service"."extra" FROM "service" WHERE "service"."id" = $1 LIMIT $2"#,
                ["1".into(), 1u64.into()]
            ),]
        );
    }
}
