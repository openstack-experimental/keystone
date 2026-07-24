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

use crate::entity::{prelude::Service as DbService, service as db_service};

/// Prepare the paginated query for listing services.
///
/// # Parameters
/// - `params`: The parameters for listing services.
///
/// # Returns
/// A `Result` containing a `Cursor` for the select model.
fn get_list_query(
    params: &ServiceListParameters,
) -> Result<Cursor<SelectModel<db_service::Model>>, CatalogProviderError> {
    let mut select = DbService::find();

    if let Some(typ) = &params.r#type {
        select = select.filter(db_service::Column::Type.eq(typ));
    }

    let mut cursor = select.cursor_by(db_service::Column::Id);
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

/// Lists services.
///
/// # Parameters
/// - `db`: The database connection.
/// - `params`: The parameters for listing services.
///
/// # Returns
/// A `Result` containing a vector of `Service`s, or a `CatalogProviderError`.
pub async fn list(
    db: &DatabaseConnection,
    params: &ServiceListParameters,
) -> Result<Vec<Service>, CatalogProviderError> {
    let mut services: Vec<Service> = get_list_query(params)?
        .all(db)
        .await
        .context("fetching services")?
        .into_iter()
        .map(TryInto::<Service>::try_into)
        .collect::<Result<_, _>>()?;

    // The service `name` is stored inside the `extra` JSON blob, so it cannot be
    // filtered in the database query; apply it as a post-filter on the fetched
    // rows instead.
    if let Some(name) = &params.name {
        services.retain(|service| service.name().as_deref() == Some(name.as_str()));
    }

    Ok(services)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, QuerySelect, Transaction, sea_query::*};
    use serde_json::json;

    use super::super::tests::get_service_mock;
    use super::*;

    #[tokio::test]
    async fn test_query_all() {
        assert_eq!(
            r#"SELECT "service"."id", "service"."type", "service"."enabled", "service"."extra" FROM "service""#,
            QuerySelect::query(&mut get_list_query(&ServiceListParameters::default()).unwrap())
                .to_string(PostgresQueryBuilder)
        );
    }

    #[tokio::test]
    async fn test_query_type() {
        assert!(
            QuerySelect::query(
                &mut get_list_query(&ServiceListParameters {
                    r#type: Some("type".into()),
                    ..Default::default()
                })
                .unwrap()
            )
            .to_string(PostgresQueryBuilder)
            .contains(r#""service"."type" = 'type'"#)
        );
    }

    #[tokio::test]
    async fn test_list() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_service_mock("1")]])
            .append_query_results([vec![get_service_mock("1")]])
            .into_connection();
        assert_eq!(
            list(&db, &ServiceListParameters::default()).await.unwrap(),
            vec![Service {
                id: "1".into(),
                r#type: Some("type".into()),
                enabled: true,
                extra: [("name".to_string(), json!("srv"))].into(),
            }]
        );
        // The `type` filter is pushed down to the database query (see the
        // transaction log below).
        assert_eq!(
            list(
                &db,
                &ServiceListParameters {
                    r#type: Some("type".into()),
                    name: None,
                    ..Default::default()
                }
            )
            .await
            .unwrap()
            .len(),
            1
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "service"."id", "service"."type", "service"."enabled", "service"."extra" FROM "service" ORDER BY "service"."id" ASC"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "service"."id", "service"."type", "service"."enabled", "service"."extra" FROM "service" WHERE "service"."type" = $1 ORDER BY "service"."id" ASC"#,
                    ["type".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_filter_by_name() {
        // Two services whose names are stored inside the `extra` blob.
        let alpha = db_service::Model {
            id: "1".into(),
            r#type: Some("type".into()),
            enabled: true,
            extra: Some(r#"{"name":"alpha"}"#.into()),
        };
        let beta = db_service::Model {
            id: "2".into(),
            r#type: Some("type".into()),
            enabled: true,
            extra: Some(r#"{"name":"beta"}"#.into()),
        };
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![alpha, beta]])
            .into_connection();

        // Only the service named "alpha" should survive the post-filter.
        let result = list(
            &db,
            &ServiceListParameters {
                name: Some("alpha".into()),
                r#type: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "1");
        assert_eq!(result[0].name().as_deref(), Some("alpha"));
    }

    #[tokio::test]
    async fn test_list_pagination_over_fetches_and_uses_marker() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_service_mock("1"), get_service_mock("2")]])
            .into_connection();

        let services = list(
            &db,
            &ServiceListParameters {
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
        assert_eq!(services.len(), 2, "backend over-fetched limit+1 rows");

        let txns = db.into_transaction_log();
        let sql = &txns[0].statements()[0].sql;
        assert!(sql.contains(r#""service"."id" >"#));
        assert!(sql.contains("LIMIT"));
    }
}
