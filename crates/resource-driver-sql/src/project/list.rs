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
use openstack_keystone_core::resource::ResourceProviderError;
use openstack_keystone_core_types::resource::{Project, ProjectListParameters};

use crate::entity::{prelude::Project as DbProject, project as db_project};

/// Prepare the paginated query for listing projects.
///
/// # Parameters
/// - `params`: List parameters for projects.
///
/// # Returns
/// A `Result` containing a `Cursor` for the select model.
fn get_list_query(
    params: &ProjectListParameters,
) -> Result<Cursor<SelectModel<db_project::Model>>, ResourceProviderError> {
    let mut select = DbProject::find().filter(db_project::Column::IsDomain.eq(false));

    if let Some(val) = &params.domain_id {
        select = select.filter(db_project::Column::DomainId.eq(val));
    }

    if let Some(val) = &params.name {
        select = select.filter(db_project::Column::Name.eq(val));
    }

    if let Some(val) = &params.ids
        && !val.is_empty()
    {
        select = select.filter(db_project::Column::Id.is_in(val));
    }

    let mut cursor = select.cursor_by(db_project::Column::Id);
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

/// List projects.
///
/// # Parameters
/// - `db`: Database connection.
/// - `params`: List parameters for projects.
///
/// # Returns
/// A `Vec<Project>`.
pub async fn list(
    db: &DatabaseConnection,
    params: &ProjectListParameters,
) -> Result<Vec<Project>, ResourceProviderError> {
    get_list_query(params)?
        .all(db)
        .await
        .context("listing projects")?
        .into_iter()
        .map(TryInto::try_into)
        .collect()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, QuerySelect, Transaction, sea_query::*};

    use super::super::tests::*;
    use super::*;

    #[tokio::test]
    async fn test_query_all() {
        assert_eq!(
            r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."is_domain" = FALSE"#,
            QuerySelect::query(&mut get_list_query(&ProjectListParameters::default()).unwrap())
                .to_string(PostgresQueryBuilder)
        );
    }

    #[tokio::test]
    async fn test_query_domain_id() {
        assert!(
            QuerySelect::query(
                &mut get_list_query(&ProjectListParameters {
                    domain_id: Some("did".into()),
                    ..Default::default()
                })
                .unwrap()
            )
            .to_string(PostgresQueryBuilder)
            .contains("\"project\".\"domain_id\" = 'did'")
        );
    }

    #[tokio::test]
    async fn test_query_name() {
        assert!(
            QuerySelect::query(
                &mut get_list_query(&ProjectListParameters {
                    name: Some("name".into()),
                    ..Default::default()
                })
                .unwrap()
            )
            .to_string(PostgresQueryBuilder)
            .contains("\"project\".\"name\" = 'name'")
        );
    }

    #[tokio::test]
    async fn test_query_ids() {
        let q = QuerySelect::query(
            &mut get_list_query(&ProjectListParameters {
                ids: Some(std::collections::HashSet::from([
                    "1".to_string(),
                    "2".to_string(),
                ])),
                ..Default::default()
            })
            .unwrap(),
        )
        .to_string(PostgresQueryBuilder);
        assert!(q.contains("\"project\".\"id\" IN ('"), "{}", q);
    }

    // Note: `Cursor`'s `.after()`/`.before()`/`.first()`/`.last()` state is
    // applied internally at execution time, not rendered by
    // `QuerySelect::query()`, so marker/limit behavior is verified against
    // the executed query's bind parameters below instead.

    #[tokio::test]
    async fn test_list_pagination_over_fetches_and_uses_marker() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_project_mock("pid1"), get_project_mock("pid2")]])
            .into_connection();

        let projects = list(
            &db,
            &ProjectListParameters {
                pagination: openstack_keystone_core_types::ListPagination {
                    limit: Some(1),
                    marker: Some("pid0".into()),
                    page_reverse: false,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(projects.len(), 2, "backend over-fetched limit+1 rows");

        let txns = db.into_transaction_log();
        let sql = &txns[0].statements()[0].sql;
        assert!(sql.contains(r#""project"."id" >"#));
        assert!(sql.contains("LIMIT"));
    }

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_project_mock("pid1")]])
            .into_connection();

        assert_eq!(
            list(&db, &ProjectListParameters::default()).await.unwrap(),
            vec![Project {
                description: None,
                domain_id: "did".into(),
                enabled: true,
                extra: std::collections::HashMap::new(),
                id: "pid1".into(),
                is_domain: false,
                name: "name".into(),
                parent_id: None,
            }]
        );

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."is_domain" = $1 ORDER BY "project"."id" ASC"#,
                [false.into()]
            ),]
        );
    }
}
