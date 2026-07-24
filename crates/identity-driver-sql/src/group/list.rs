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
use openstack_keystone_core::identity::IdentityProviderError;
use openstack_keystone_core_types::identity::{Group, GroupListParameters};

use crate::entity::{group, prelude::Group as DbGroup};

/// Prepare the paginated query for listing groups.
///
/// # Parameters
/// - `params`: The parameters to filter the group list.
///
/// # Returns
/// A `Result` containing a `Cursor` for the select model.
fn get_list_query(
    params: &GroupListParameters,
) -> Result<Cursor<SelectModel<group::Model>>, IdentityProviderError> {
    let mut group_select = DbGroup::find();

    if let Some(domain_id) = &params.domain_id {
        group_select = group_select.filter(group::Column::DomainId.eq(domain_id));
    }
    if let Some(name) = &params.name {
        group_select = group_select.filter(group::Column::Name.eq(name));
    }

    let mut cursor = group_select.cursor_by(group::Column::Id);
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

/// Lists groups based on the provided parameters.
///
/// # Parameters
/// - `db`: The database connection.
/// - `params`: The parameters to filter the group list.
///
/// # Returns
/// A `Result` containing a vector of groups, or an `Error`.
#[tracing::instrument(skip_all)]
pub async fn list(
    db: &DatabaseConnection,
    params: &GroupListParameters,
) -> Result<Vec<Group>, IdentityProviderError> {
    Ok(get_list_query(params)?
        .all(db)
        .await
        .context("listing groups")?
        .into_iter()
        .map(Into::into)
        .collect())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, QuerySelect, Transaction, sea_query::*};
    use serde_json::json;

    use openstack_keystone_core_types::identity::GroupListParametersBuilder;

    use crate::entity::group;

    use super::*;
    use crate::group::tests::get_group_mock;

    #[tokio::test]
    async fn test_query_all() {
        assert_eq!(
            r#"SELECT "group"."id", "group"."domain_id", "group"."name", "group"."description", "group"."extra" FROM "group""#,
            QuerySelect::query(&mut get_list_query(&GroupListParameters::default()).unwrap())
                .to_string(PostgresQueryBuilder)
        );
    }

    #[tokio::test]
    async fn test_list() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([
                // First query result - select user itself
                vec![get_group_mock("1")],
            ])
            .into_connection();
        assert_eq!(
            list(&db, &GroupListParameters::default()).await.unwrap(),
            vec![Group {
                id: "1".into(),
                domain_id: "foo_domain".into(),
                name: "group".into(),
                description: Some("fake".into()),
                extra: std::collections::HashMap::from([("foo".into(), json!("bar"))])
            }]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "group"."id", "group"."domain_id", "group"."name", "group"."description", "group"."extra" FROM "group" ORDER BY "group"."id" ASC"#,
                []
            ),]
        );
    }

    #[tokio::test]
    async fn test_list_pagination_over_fetches_and_uses_marker() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_group_mock("1"), get_group_mock("2")]])
            .into_connection();

        let groups = list(
            &db,
            &GroupListParametersBuilder::default()
                .pagination(openstack_keystone_core_types::ListPagination {
                    limit: Some(1),
                    marker: Some("0".into()),
                    page_reverse: false,
                })
                .build()
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(groups.len(), 2, "backend over-fetched limit+1 rows");

        let txns = db.into_transaction_log();
        let sql = &txns[0].statements()[0].sql;
        assert!(sql.contains(r#""group"."id" >"#));
        assert!(sql.contains("LIMIT"));
    }

    #[tokio::test]
    async fn test_list_with_filters() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<group::Model>::new()])
            .into_connection();
        assert_eq!(
            list(
                &db,
                &GroupListParametersBuilder::default()
                    .domain_id("d")
                    .name("n")
                    .build()
                    .unwrap()
            )
            .await
            .unwrap(),
            vec![]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "group"."id", "group"."domain_id", "group"."name", "group"."description", "group"."extra" FROM "group" WHERE "group"."domain_id" = $1 AND "group"."name" = $2 ORDER BY "group"."id" ASC"#,
                ["d".into(), "n".into()]
            ),]
        );
    }
}
