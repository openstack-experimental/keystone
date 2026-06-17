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

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::catalog::*;

use crate::entity::{prelude::Region as DbRegion, region as db_region};

/// Lists regions.
///
/// # Parameters
/// - `db`: The database connection.
/// - `params`: The parameters for listing regions.
///
/// # Returns
/// A `Result` containing a vector of `Region`s, or a `CatalogProviderError`.
pub async fn list(
    db: &DatabaseConnection,
    params: &RegionListParameters,
) -> Result<Vec<Region>, CatalogProviderError> {
    let mut select = DbRegion::find();

    if let Some(parent_region_id) = &params.parent_region_id {
        select = select.filter(db_region::Column::ParentRegionId.eq(parent_region_id));
    }

    select
        .all(db)
        .await
        .context("fetching regions")?
        .into_iter()
        .map(TryInto::<Region>::try_into)
        .collect()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
    use serde_json::json;

    use super::super::tests::get_region_mock;
    use super::*;

    #[tokio::test]
    async fn test_list() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_region_mock("1")]])
            .append_query_results([vec![get_region_mock("1")]])
            .into_connection();
        assert!(list(&db, &RegionListParameters::default()).await.is_ok());
        assert_eq!(
            list(
                &db,
                &RegionListParameters {
                    parent_region_id: Some("parent".into()),
                }
            )
            .await
            .unwrap(),
            vec![Region {
                id: "1".into(),
                description: Some("region description".into()),
                parent_region_id: None,
                extra: [("key".to_string(), json!("value"))].into(),
            }]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "region"."id", "region"."description", "region"."parent_region_id", "region"."extra" FROM "region""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "region"."id", "region"."description", "region"."parent_region_id", "region"."extra" FROM "region" WHERE "region"."parent_region_id" = $1"#,
                    ["parent".into()]
                ),
            ]
        );
    }
}
