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
//! # List policies

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::{Cursor, SelectModel};

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::policy_store::PolicyStoreProviderError;
use openstack_keystone_core_types::policy_store::*;

use crate::entity::{policy as db_policy, prelude::Policy as DbPolicy};

/// Prepare the paginated query for listing policies.
///
/// The `type` filter is an exact match, matching python keystone's
/// `filter_by_attributes` behaviour for the `type` hint (which it applies in
/// its API layer; pushing it into SQL here is observably identical).
///
/// # Parameters
/// - `params`: The parameters for listing policies.
///
/// # Returns
/// A `Result` containing a `Cursor` for the select model.
fn get_list_query(
    params: &PolicyListParameters,
) -> Result<Cursor<SelectModel<db_policy::Model>>, PolicyStoreProviderError> {
    let mut select = DbPolicy::find();

    if let Some(r#type) = &params.r#type {
        select = select.filter(db_policy::Column::Type.eq(r#type));
    }

    let mut cursor = select.cursor_by(db_policy::Column::Id);
    if let Some(marker) = &params.pagination.marker {
        if params.pagination.page_reverse {
            cursor.before(marker);
        } else {
            cursor.after(marker);
        }
    }
    // Over-fetch by one row so the API layer can tell "there is a
    // next/previous page" exactly instead of guessing from
    // `returned == limit` (ADR 0029).
    if let Some(limit) = params.pagination.limit {
        if params.pagination.page_reverse {
            cursor.last(limit + 1);
        } else {
            cursor.first(limit + 1);
        }
    }
    Ok(cursor)
}

/// Lists policies.
///
/// # Parameters
/// - `db`: The database connection.
/// - `params`: The parameters for listing policies.
///
/// # Returns
/// A `Result` containing a vector of `Policy`s, or a
/// `PolicyStoreProviderError`.
pub async fn list(
    db: &DatabaseConnection,
    params: &PolicyListParameters,
) -> Result<Vec<Policy>, PolicyStoreProviderError> {
    get_list_query(params)?
        .all(db)
        .await
        .context("fetching policies")?
        .into_iter()
        .map(TryInto::<Policy>::try_into)
        .collect::<Result<_, _>>()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, QuerySelect, Transaction, sea_query::*};

    use super::super::tests::get_policy_mock;
    use super::*;

    #[tokio::test]
    async fn test_query_all() {
        assert_eq!(
            r#"SELECT "policy"."id", "policy"."type", "policy"."blob", "policy"."extra" FROM "policy""#,
            QuerySelect::query(&mut get_list_query(&PolicyListParameters::default()).unwrap())
                .to_string(PostgresQueryBuilder)
        );
    }

    /// `?type=` is an exact-match filter, not a prefix or `LIKE` match.
    #[tokio::test]
    async fn test_query_type_is_exact_match() {
        let sql = QuerySelect::query(
            &mut get_list_query(&PolicyListParameters {
                r#type: Some("application/json".into()),
                ..Default::default()
            })
            .unwrap(),
        )
        .to_string(PostgresQueryBuilder);

        assert!(sql.contains(r#""policy"."type" = 'application/json'"#));
        assert!(!sql.to_uppercase().contains("LIKE"));
    }

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_policy_mock("1")]])
            .append_query_results([vec![get_policy_mock("1")]])
            .into_connection();

        assert!(list(&db, &PolicyListParameters::default()).await.is_ok());
        let filtered = list(
            &db,
            &PolicyListParameters {
                r#type: Some("application/json".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "1");

        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "policy"."id", "policy"."type", "policy"."blob", "policy"."extra" FROM "policy" ORDER BY "policy"."id" ASC"#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "policy"."id", "policy"."type", "policy"."blob", "policy"."extra" FROM "policy" WHERE "policy"."type" = $1 ORDER BY "policy"."id" ASC"#,
                    ["application/json".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_pagination_over_fetches_and_uses_marker() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_policy_mock("1"), get_policy_mock("2")]])
            .into_connection();

        let policies = list(
            &db,
            &PolicyListParameters {
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
        assert_eq!(policies.len(), 2, "backend over-fetched limit+1 rows");

        let txns = db.into_transaction_log();
        let sql = &txns[0].statements()[0].sql;
        assert!(sql.contains(r#""policy"."id" >"#));
        assert!(sql.contains("LIMIT"));
    }
}
