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

use crate::entity::{endpoint as db_endpoint, prelude::Endpoint as DbEndpoint};

/// Prepare the paginated query for listing endpoints.
///
/// # Parameters
/// - `params`: The parameters for listing endpoints.
///
/// # Returns
/// A `Result` containing a `Cursor` for the select model.
fn get_list_query(
    params: &EndpointListParameters,
) -> Result<Cursor<SelectModel<db_endpoint::Model>>, CatalogProviderError> {
    let mut select = DbEndpoint::find();

    if let Some(val) = &params.interface {
        select = select.filter(db_endpoint::Column::Interface.eq(val));
    }
    if let Some(val) = &params.service_id {
        select = select.filter(db_endpoint::Column::ServiceId.eq(val));
    }
    if let Some(val) = &params.region_id {
        select = select.filter(db_endpoint::Column::RegionId.eq(val));
    }

    let mut cursor = select.cursor_by(db_endpoint::Column::Id);
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

/// Lists endpoints.
///
/// # Parameters
/// - `db`: The database connection.
/// - `params`: The parameters for listing endpoints.
///
/// # Returns
/// A `Result` containing a vector of `Endpoint`s, or a `CatalogProviderError`.
pub async fn list(
    db: &DatabaseConnection,
    params: &EndpointListParameters,
) -> Result<Vec<Endpoint>, CatalogProviderError> {
    Ok(get_list_query(params)?
        .all(db)
        .await
        .context("fetching endpoints")?
        .into_iter()
        .map(TryInto::<Endpoint>::try_into)
        .collect::<Result<_, _>>()?)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, QueryOrder, Transaction, sea_query::*};

    use super::super::tests::get_endpoint_mock;
    use super::*;

    #[tokio::test]
    async fn test_query_all() {
        assert_eq!(
            r#"SELECT "endpoint"."id", "endpoint"."legacy_endpoint_id", "endpoint"."interface", "endpoint"."service_id", "endpoint"."url", "endpoint"."extra", "endpoint"."enabled", "endpoint"."region_id" FROM "endpoint""#,
            QueryOrder::query(&mut get_list_query(&EndpointListParameters::default()).unwrap())
                .to_string(PostgresQueryBuilder)
        );
    }

    #[tokio::test]
    async fn test_query_filters() {
        assert!(
            QueryOrder::query(
                &mut get_list_query(&EndpointListParameters {
                    interface: Some("public".into()),
                    service_id: Some("service_id".into()),
                    region_id: Some("region_id".into()),
                    ..Default::default()
                })
                .unwrap()
            )
            .to_string(PostgresQueryBuilder)
            .contains(
                r#""endpoint"."interface" = 'public' AND "endpoint"."service_id" = 'service_id' AND "endpoint"."region_id" = 'region_id'"#
            )
        );
    }

    #[tokio::test]
    async fn test_list() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_endpoint_mock("1")]])
            .append_query_results([vec![get_endpoint_mock("1")]])
            .into_connection();
        assert!(list(&db, &EndpointListParameters::default()).await.is_ok());
        assert_eq!(
            list(
                &db,
                &EndpointListParameters {
                    interface: Some("public".into()),
                    service_id: Some("service_id".into()),
                    region_id: Some("region_id".into()),
                    ..Default::default()
                }
            )
            .await
            .unwrap(),
            vec![Endpoint {
                id: "1".into(),
                interface: "public".into(),
                service_id: "srv_id".into(),
                region_id: Some("region".into()),
                enabled: true,
                url: "http://localhost".into(),
                extra: Default::default()
            }]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "endpoint"."id", "endpoint"."legacy_endpoint_id", "endpoint"."interface", "endpoint"."service_id", "endpoint"."url", "endpoint"."extra", "endpoint"."enabled", "endpoint"."region_id" FROM "endpoint" ORDER BY "endpoint"."id" ASC"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "endpoint"."id", "endpoint"."legacy_endpoint_id", "endpoint"."interface", "endpoint"."service_id", "endpoint"."url", "endpoint"."extra", "endpoint"."enabled", "endpoint"."region_id" FROM "endpoint" WHERE "endpoint"."interface" = $1 AND "endpoint"."service_id" = $2 AND "endpoint"."region_id" = $3 ORDER BY "endpoint"."id" ASC"#,
                    ["public".into(), "service_id".into(), "region_id".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_pagination_over_fetches_and_uses_marker() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_endpoint_mock("1"), get_endpoint_mock("2")]])
            .into_connection();

        let endpoints = list(
            &db,
            &EndpointListParameters {
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
        assert_eq!(endpoints.len(), 2, "backend over-fetched limit+1 rows");

        let txns = db.into_transaction_log();
        let sql = &txns[0].statements()[0].sql;
        assert!(sql.contains(r#""endpoint"."id" >"#));
        assert!(sql.contains("LIMIT"));
    }
}
