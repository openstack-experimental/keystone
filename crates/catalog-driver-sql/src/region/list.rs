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
use sea_orm::{Cursor, SelectModel};

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::catalog::*;

use crate::entity::{prelude::Region as DbRegion, region as db_region};

/// Prepare the paginated query for listing regions.
///
/// # Parameters
/// - `params`: The parameters for listing regions.
///
/// # Returns
/// A `Result` containing a `Cursor` for the select model.
fn get_list_query(
    params: &RegionListParameters,
) -> Result<Cursor<SelectModel<db_region::Model>>, CatalogProviderError> {
    let mut select = DbRegion::find();

    if let Some(parent_region_id) = &params.parent_region_id {
        select = select.filter(db_region::Column::ParentRegionId.eq(parent_region_id));
    }

    let mut cursor = select.cursor_by(db_region::Column::Id);
    if let Some(marker) = &params.pagination.marker {
        if params.pagination.page_reverse {
            cursor.before(marker);
        } else {
            cursor.after(marker);
        }
    }
    // Over-fetch by one row so the API layer can tell "there is a
    // next/previous page" exactly, instead of guessing from
    // `returned == limit` (false-positives when exactly `limit` rows
    // remain). `.last()` fetches in descending order but sea-orm returns
    // rows back in ascending order.
    if let Some(limit) = params.pagination.limit {
        if params.pagination.page_reverse {
            cursor.last(limit + 1);
        } else {
            cursor.first(limit + 1);
        }
    }
    Ok(cursor)
}

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
    get_list_query(params)?
        .all(db)
        .await
        .context("fetching regions")?
        .into_iter()
        .map(TryInto::<Region>::try_into)
        .collect::<Result<_, _>>()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, QuerySelect, Transaction, sea_query::*};
    use serde_json::json;

    use super::super::tests::get_region_mock;
    use super::*;

    #[tokio::test]
    async fn test_query_all() {
        assert_eq!(
            r#"SELECT "region"."id", "region"."description", "region"."parent_region_id", "region"."extra" FROM "region""#,
            QuerySelect::query(&mut get_list_query(&RegionListParameters::default()).unwrap())
                .to_string(PostgresQueryBuilder)
        );
    }

    #[tokio::test]
    async fn test_query_parent_region_id() {
        assert!(
            QuerySelect::query(
                &mut get_list_query(&RegionListParameters {
                    parent_region_id: Some("parent".into()),
                    ..Default::default()
                })
                .unwrap()
            )
            .to_string(PostgresQueryBuilder)
            .contains(r#""region"."parent_region_id" = 'parent'"#)
        );
    }

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
                    ..Default::default()
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
                    r#"SELECT "region"."id", "region"."description", "region"."parent_region_id", "region"."extra" FROM "region" ORDER BY "region"."id" ASC"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "region"."id", "region"."description", "region"."parent_region_id", "region"."extra" FROM "region" WHERE "region"."parent_region_id" = $1 ORDER BY "region"."id" ASC"#,
                    ["parent".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_pagination_over_fetches_and_uses_marker() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_region_mock("1"), get_region_mock("2")]])
            .into_connection();

        let regions = list(
            &db,
            &RegionListParameters {
                pagination: openstack_keystone_core_types::ListPagination {
                    limit: Some(1),
                    marker: Some("0".into()),
                    page_reverse: false,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(regions.len(), 2, "backend over-fetched limit+1 rows");

        let txns = db.into_transaction_log();
        let sql = &txns[0].statements()[0].sql;
        assert!(sql.contains(r#""region"."id" >"#));
        assert!(sql.contains("LIMIT"));
    }
}
