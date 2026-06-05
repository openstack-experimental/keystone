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

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::catalog::Region;

use crate::entity::prelude::Region as DbRegion;

/// Gets a region by ID.
///
/// # Parameters
/// - `db`: The database connection.
/// - `id`: The ID of the region to retrieve.
///
/// # Returns
/// A `Result` containing an `Option` with the `Region` if found, or an `Error`.
pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Region>, CatalogProviderError> {
    DbRegion::find_by_id(id.as_ref())
        .one(db)
        .await
        .context("fetching region by ID")?
        .map(TryInto::try_into)
        .transpose()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
    use serde_json::json;

    use super::super::tests::get_region_mock;
    use super::*;

    #[tokio::test]
    async fn test_get() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_region_mock("1")]])
            .into_connection();
        assert_eq!(
            get(&db, "1").await.unwrap().unwrap(),
            Region {
                id: "1".into(),
                description: Some("region description".into()),
                parent_region_id: None,
                extra: Some(json!({"key": "value"})),
            }
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "region"."id", "region"."description", "region"."parent_region_id", "region"."extra" FROM "region" WHERE "region"."id" = $1 LIMIT $2"#,
                ["1".into(), 1u64.into()]
            ),]
        );
    }
}
