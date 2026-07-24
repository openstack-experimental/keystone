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

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::role::RoleProviderError;
use openstack_keystone_core_types::role::{Role, RoleListParameters};

use crate::entity::{prelude::Role as DbRole, role as db_role};
use crate::role::NULL_DOMAIN_ID;

/// Prepare the paginated query for listing roles.
///
/// # Parameters
/// - `params`: The list parameters.
///
/// # Returns
/// A `Result` containing a `Cursor` for the select model.
fn get_list_query(
    params: &RoleListParameters,
) -> Result<Cursor<SelectModel<db_role::Model>>, RoleProviderError> {
    let mut select = DbRole::find();

    if let Some(domain_id) = &params.domain_id {
        select = select
            .filter(db_role::Column::DomainId.eq(domain_id.as_ref().map_or(NULL_DOMAIN_ID, |x| x)));
    }
    if let Some(name) = &params.name {
        select = select.filter(db_role::Column::Name.eq(name));
    }

    let mut cursor = select.cursor_by(db_role::Column::Id);
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

/// List roles.
///
/// # Parameters
/// - `db`: The database connection.
/// - `params`: The list parameters.
///
/// # Returns
/// A `Result` containing a list of `Role`s, or an `Error`.
pub async fn list(
    db: &DatabaseConnection,
    params: &RoleListParameters,
) -> Result<Vec<Role>, RoleProviderError> {
    Ok(get_list_query(params)?
        .all(db)
        .await
        .context("listing roles")?
        .into_iter()
        .map(TryInto::<Role>::try_into)
        .collect::<Result<Vec<Role>, _>>()?)
}

#[cfg(test)]
pub(super) mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, QueryOrder, Transaction, sea_query::*};

    use openstack_keystone_core_types::role::RoleBuilder;

    use super::*;
    use crate::role::tests::get_role_mock;

    #[tokio::test]
    async fn test_query_all() {
        assert_eq!(
            r#"SELECT "role"."id", "role"."name", "role"."extra", "role"."domain_id", "role"."description" FROM "role""#,
            QueryOrder::query(&mut get_list_query(&RoleListParameters::default()).unwrap())
                .to_string(PostgresQueryBuilder)
        );
    }

    #[tokio::test]
    async fn test_list() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([
                // First query result - select user itself
                vec![get_role_mock("1", "foo")],
            ])
            .append_query_results([
                // First query result - select user itself
                vec![get_role_mock("1", "foo")],
            ])
            .append_query_results([
                // First query result - select user itself
                vec![get_role_mock("1", "foo")],
            ])
            .into_connection();
        assert!(list(&db, &RoleListParameters::default()).await.is_ok());
        assert_eq!(
            list(
                &db,
                &RoleListParameters {
                    name: Some("foo".into()),
                    domain_id: Some(Some("foo_domain".into())),
                    ..Default::default()
                }
            )
            .await
            .unwrap(),
            vec![
                RoleBuilder::default()
                    .id("1")
                    .domain_id("foo_domain")
                    .name("foo")
                    .build()
                    .unwrap()
            ]
        );

        list(
            &db,
            &RoleListParameters {
                domain_id: Some(None),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "role"."id", "role"."name", "role"."extra", "role"."domain_id", "role"."description" FROM "role" ORDER BY "role"."id" ASC"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "role"."id", "role"."name", "role"."extra", "role"."domain_id", "role"."description" FROM "role" WHERE "role"."domain_id" = $1 AND "role"."name" = $2 ORDER BY "role"."id" ASC"#,
                    ["foo_domain".into(), "foo".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "role"."id", "role"."name", "role"."extra", "role"."domain_id", "role"."description" FROM "role" WHERE "role"."domain_id" = $1 ORDER BY "role"."id" ASC"#,
                    [NULL_DOMAIN_ID.into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_pagination_over_fetches_and_uses_marker() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_mock("1", "a"), get_role_mock("2", "b")]])
            .into_connection();

        let roles = list(
            &db,
            &RoleListParameters {
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
        assert_eq!(roles.len(), 2, "backend over-fetched limit+1 rows");

        let txns = db.into_transaction_log();
        let sql = &txns[0].statements()[0].sql;
        assert!(sql.contains(r#""role"."id" >"#));
        assert!(sql.contains("LIMIT"));
    }
}
