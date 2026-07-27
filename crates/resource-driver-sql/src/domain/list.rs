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
use openstack_keystone_core_types::resource::{Domain, DomainListParameters, ProjectOptions};

use crate::domain::NULL_DOMAIN_ID;
use crate::entity::{
    prelude::{Project as DbProject, ProjectOption},
    project as db_project,
};

/// Prepare the paginated query for listing domains.
///
/// # Parameters
/// - `params`: List parameters for domains.
///
/// # Returns
/// A `Result` containing a `Cursor` for the select model.
fn get_list_query(
    params: &DomainListParameters,
) -> Result<Cursor<SelectModel<db_project::Model>>, ResourceProviderError> {
    let mut select = DbProject::find()
        .filter(db_project::Column::IsDomain.eq(true))
        .filter(db_project::Column::Id.ne(NULL_DOMAIN_ID));

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

/// List domains.
///
/// # Parameters
/// - `db`: Database connection.
/// - `params`: List parameters for domains.
///
/// # Returns
/// A `Vec<Domain>`.
pub async fn list(
    db: &DatabaseConnection,
    params: &DomainListParameters,
) -> Result<Vec<Domain>, ResourceProviderError> {
    let rows = get_list_query(params)?
        .all(db)
        .await
        .context("listing domains")?;
    let options = rows
        .load_many(ProjectOption, db)
        .await
        .context("fetching options of the listed domains")?;

    rows.into_iter()
        .zip(options)
        .map(|(row, opts)| {
            let mut domain: Domain = row.try_into()?;
            domain.options = ProjectOptions::from_iter(opts);
            Ok(domain)
        })
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
            r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."is_domain" = TRUE AND "project"."id" <> '<<keystone.domain.root>>'"#,
            QuerySelect::query(&mut get_list_query(&DomainListParameters::default()).unwrap())
                .to_string(PostgresQueryBuilder)
        );
    }

    #[tokio::test]
    async fn test_query_name() {
        assert!(
            QuerySelect::query(
                &mut get_list_query(&DomainListParameters {
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
            &mut get_list_query(&DomainListParameters {
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

    #[tokio::test]
    async fn test_list_pagination_over_fetches_and_uses_marker() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_domain_mock("pid1"), get_domain_mock("pid2")]])
            .append_query_results([Vec::<crate::entity::project_option::Model>::new()])
            .into_connection();

        let domains = list(
            &db,
            &DomainListParameters {
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
        assert_eq!(domains.len(), 2, "backend over-fetched limit+1 rows");

        let txns = db.into_transaction_log();
        let sql = &txns[0].statements()[0].sql;
        assert!(sql.contains(r#""project"."id" >"#));
        assert!(sql.contains("LIMIT"));
    }

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_domain_mock("pid1")]])
            .append_query_results([Vec::<crate::entity::project_option::Model>::new()])
            .into_connection();

        assert_eq!(
            list(&db, &DomainListParameters::default()).await.unwrap(),
            vec![Domain {
                description: None,
                enabled: true,
                extra: std::collections::HashMap::new(),
                id: "pid1".into(),
                name: "name".into(),
                options: Default::default(),
            }]
        );

        assert_eq!(
            db.into_transaction_log()[0],
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."is_domain" = $1 AND "project"."id" <> $2 ORDER BY "project"."id" ASC"#,
                [true.into(), NULL_DOMAIN_ID.into()]
            ),
        );
    }

    #[tokio::test]
    async fn test_list_merges_options() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_domain_mock("pid1")]])
            .append_query_results([vec![crate::entity::project_option::Model {
                project_id: "pid1".into(),
                option_id: "IMMU".into(),
                option_value: Some("true".into()),
            }]])
            .into_connection();

        let domains = list(&db, &DomainListParameters::default()).await.unwrap();
        assert_eq!(domains[0].options.immutable, Some(true));
    }
}
