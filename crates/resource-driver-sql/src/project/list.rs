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
use openstack_keystone_core_types::resource::{Project, ProjectListParameters, ProjectOptions};

use crate::entity::{
    prelude::{Project as DbProject, ProjectOption, ProjectTag, ProjectTag as DbProjectTag},
    project as db_project, project_tag as db_project_tag,
};

/// Sub-query selecting the IDs of the projects carrying the tag(s).
fn tagged_projects<'a>(
    tags: impl IntoIterator<Item = &'a String>,
) -> sea_orm::sea_query::SelectStatement {
    DbProjectTag::find()
        .select_only()
        .column(db_project_tag::Column::ProjectId)
        .filter(
            sea_orm::sea_query::Expr::expr(sea_orm::sea_query::Func::lower(
                sea_orm::sea_query::Expr::col(db_project_tag::Column::Name),
            ))
            .is_in(tags.into_iter().map(|tag| tag.to_lowercase())),
        )
        .into_query()
}

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

    if let Some(enabled) = params.enabled {
        select = select.filter(db_project::Column::Enabled.eq(enabled));
    }

    if let Some(val) = &params.ids
        && !val.is_empty()
    {
        select = select.filter(db_project::Column::Id.is_in(val));
    }

    // all the tags must be present
    for tag in params.tags.iter().flatten() {
        select = select.filter(db_project::Column::Id.in_subquery(tagged_projects([tag])));
    }
    // at least one of the tags must be present
    if let Some(tags) = params.tags_any.as_ref().filter(|t| !t.is_empty()) {
        select = select.filter(db_project::Column::Id.in_subquery(tagged_projects(tags)));
    }
    // not all of the tags are present
    if let Some(tags) = params.not_tags.as_ref().filter(|t| !t.is_empty()) {
        select = select.filter(tags.iter().fold(Condition::any(), |cond, tag| {
            cond.add(db_project::Column::Id.not_in_subquery(tagged_projects([tag])))
        }));
    }
    // none of the tags is present
    if let Some(tags) = params.not_tags_any.as_ref().filter(|t| !t.is_empty()) {
        select = select.filter(db_project::Column::Id.not_in_subquery(tagged_projects(tags)));
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
    let rows = get_list_query(params)?
        .all(db)
        .await
        .context("listing projects")?;
    let options = rows
        .load_many(ProjectOption, db)
        .await
        .context("fetching options of the listed projects")?;
    let tags = rows
        .load_many(ProjectTag, db)
        .await
        .context("fetching tags of the listed projects")?;

    rows.into_iter()
        .zip(options.into_iter().zip(tags))
        .map(|(row, (opts, tags))| {
            let mut project: Project = row.try_into()?;
            project.options = ProjectOptions::from_iter(opts);
            project.tags = tags.into_iter().map(|tag| tag.name).collect();
            project.tags.sort();
            Ok(project)
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

    fn tag_query(params: ProjectListParameters) -> String {
        QuerySelect::query(&mut get_list_query(&params).unwrap()).to_string(PostgresQueryBuilder)
    }

    fn set(items: &[&str]) -> Option<std::collections::BTreeSet<String>> {
        Some(items.iter().map(|s| String::from(*s)).collect())
    }

    #[tokio::test]
    async fn test_query_tags() {
        let q = tag_query(ProjectListParameters {
            tags: set(&["a", "b"]),
            ..Default::default()
        });
        assert!(q.contains(r#""project"."id" IN (SELECT "project_tag"."project_id" FROM "project_tag" WHERE LOWER("name") IN ('a')) AND "project"."id" IN (SELECT "project_tag"."project_id" FROM "project_tag" WHERE LOWER("name") IN ('b'))"#), "{q}");
    }

    #[tokio::test]
    async fn test_query_tags_any() {
        let q = tag_query(ProjectListParameters {
            tags_any: set(&["a", "b"]),
            ..Default::default()
        });
        assert!(q.contains(r#""project"."id" IN (SELECT "project_tag"."project_id" FROM "project_tag" WHERE LOWER("name") IN ('a', 'b'))"#), "{q}");
    }

    #[tokio::test]
    async fn test_query_not_tags() {
        let q = tag_query(ProjectListParameters {
            not_tags: set(&["a", "b"]),
            ..Default::default()
        });
        assert!(q.contains(r#""project"."id" NOT IN (SELECT "project_tag"."project_id" FROM "project_tag" WHERE LOWER("name") IN ('a')) OR "project"."id" NOT IN (SELECT "project_tag"."project_id" FROM "project_tag" WHERE LOWER("name") IN ('b'))"#), "{q}");
    }

    #[tokio::test]
    async fn test_query_not_tags_any() {
        let q = tag_query(ProjectListParameters {
            not_tags_any: set(&["a", "b"]),
            ..Default::default()
        });
        assert!(q.contains(r#""project"."id" NOT IN (SELECT "project_tag"."project_id" FROM "project_tag" WHERE LOWER("name") IN ('a', 'b'))"#), "{q}");
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
    async fn test_query_enabled() {
        let q = QuerySelect::query(
            &mut get_list_query(&ProjectListParameters {
                enabled: Some(false),
                ..Default::default()
            })
            .unwrap(),
        )
        .to_string(PostgresQueryBuilder);
        assert!(q.contains("\"project\".\"enabled\" = FALSE"), "{}", q);
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
            .append_query_results([Vec::<crate::entity::project_option::Model>::new()])
            .append_query_results([Vec::<crate::entity::project_tag::Model>::new()])
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
            .append_query_results([Vec::<crate::entity::project_option::Model>::new()])
            .append_query_results([Vec::<crate::entity::project_tag::Model>::new()])
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
                options: Default::default(),
                parent_id: None,
                tags: Vec::new(),
            }]
        );

        assert_eq!(
            db.into_transaction_log()[0],
            Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."is_domain" = $1 ORDER BY "project"."id" ASC"#,
                [false.into()]
            ),
        );
    }

    #[tokio::test]
    async fn test_list_merges_options() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_project_mock("pid1")]])
            .append_query_results([vec![crate::entity::project_option::Model {
                project_id: "pid1".into(),
                option_id: "IMMU".into(),
                option_value: Some("true".into()),
            }]])
            .append_query_results([vec![
                crate::entity::project_tag::Model {
                    project_id: "pid1".into(),
                    name: "b".into(),
                },
                crate::entity::project_tag::Model {
                    project_id: "pid1".into(),
                    name: "a".into(),
                },
            ]])
            .into_connection();

        let projects = list(&db, &ProjectListParameters::default()).await.unwrap();
        assert_eq!(projects[0].options.immutable, Some(true));
        assert_eq!(projects[0].tags, vec!["a".to_string(), "b".to_string()]);
    }
}
