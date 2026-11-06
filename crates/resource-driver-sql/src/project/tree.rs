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

use std::collections::{HashMap, HashSet};

use sea_orm::query::*;
use sea_orm::sea_query::{
    Alias, CommonTableExpression, Expr, ExprTrait, MysqlQueryBuilder, PostgresQueryBuilder, Query,
    SqliteQueryBuilder, UnionType, WithClause,
};
use sea_orm::{
    DatabaseBackend, DatabaseConnection, DbErr, FromQueryResult, Iterable, Statement, entity::*,
};

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::resource::ResourceProviderError;
use openstack_keystone_core_types::resource::Project;

use crate::entity::project as db_project;
use crate::entity::{
    prelude::Project as DbProject,
    project::{Column as ProjectColumn, Model as ProjectModel},
};

/// Build the statement selecting a project together with all its ancestors.
///
/// A recursive CTE follows `parent_id` up to the root inside the database, so
/// the depth of the hierarchy does not change the number of round trips.
/// `UNION` (not `UNION ALL`) drops the rows already seen, which also ends the
/// recursion should the hierarchy ever contain a cycle.
fn ancestors_statement(
    backend: DatabaseBackend,
    id: &str,
    columns: &[ProjectColumn],
) -> Result<Statement, DbErr> {
    let ancestors = Alias::new("ancestors");
    let parent = Alias::new("parent");

    let base = Query::select()
        .columns(columns.iter().copied())
        .from(DbProject)
        .and_where(Expr::col(ProjectColumn::Id).eq(id))
        .to_owned();
    let mut step = Query::select();
    for column in columns {
        step.expr(Expr::col((parent.clone(), *column)));
    }
    step.from_as(DbProject, parent.clone()).inner_join(
        ancestors.clone(),
        Expr::col((ancestors.clone(), ProjectColumn::ParentId))
            .equals((parent.clone(), ProjectColumn::Id)),
    );
    let mut recursive = base;
    recursive.union(UnionType::Distinct, step.to_owned());

    let cte = CommonTableExpression::new()
        .query(recursive)
        .table_name(ancestors.clone())
        .columns(columns.iter().copied())
        .to_owned();
    let query = Query::select()
        .columns(columns.iter().copied())
        .from(ancestors)
        .to_owned()
        .with(WithClause::new().recursive(true).cte(cte).to_owned());

    let (sql, values) = match backend {
        DatabaseBackend::MySql => query.build(MysqlQueryBuilder),
        DatabaseBackend::Postgres => query.build(PostgresQueryBuilder),
        DatabaseBackend::Sqlite => query.build(SqliteQueryBuilder),
        other => {
            return Err(DbErr::Custom(format!(
                "unsupported database backend: {other:?}"
            )));
        }
    };
    Ok(Statement::from_sql_and_values(backend, sql, values))
}

/// Order the ancestors of a project.
///
/// `links` maps every row the query returned to its `parent_id`. The rows come
/// back unordered, so the chain is walked from the project up: the closest
/// parent comes first and the project itself is left out. A cycle ends the
/// walk. Returns `None` when the project is not among the rows.
fn parent_chain<'a>(
    id: &'a str,
    links: &HashMap<&'a str, Option<&'a str>>,
) -> Option<Vec<&'a str>> {
    let mut next = *links.get(id)?;
    let mut seen: HashSet<&str> = HashSet::from([id]);
    let mut chain = Vec::new();
    while let Some(parent_id) = next {
        if !links.contains_key(parent_id) || !seen.insert(parent_id) {
            break;
        }
        chain.push(parent_id);
        next = links[parent_id];
    }
    Some(chain)
}

/// Get the parents of a project.
///
/// The project and its whole ancestor chain are read with a single query.
///
/// # Parameters
/// - `db`: Database connection.
/// - `id`: ID of the project.
///
/// # Returns
/// A `Result` containing an `Option` with the `Vec<Project>` if found, or an
/// `Error`. The parents are ordered from the closest one to the root; the
/// project itself is not included.
pub async fn get_project_parents<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Vec<Project>>, ResourceProviderError> {
    let id = id.as_ref();
    let columns: Vec<ProjectColumn> = ProjectColumn::iter().collect();
    let statement = ancestors_statement(db.get_database_backend(), id, &columns)
        .context("building the project parents query")?;
    let rows = DbProject::find()
        .from_raw_sql(statement)
        .all(db)
        .await
        .context("resolving project parents")?;
    let by_id: HashMap<&str, &ProjectModel> =
        rows.iter().map(|row| (row.id.as_str(), row)).collect();
    let links: HashMap<&str, Option<&str>> = by_id
        .iter()
        .map(|(row_id, row)| (*row_id, row.parent_id.as_deref()))
        .collect();

    let Some(chain) = parent_chain(id, &links) else {
        return Ok(None);
    };
    let mut parents = chain
        .into_iter()
        .map(|parent_id| by_id[parent_id].clone().try_into())
        .collect::<Result<Vec<Project>, _>>()?;
    // Domains have no tags, the others get them with one more query.
    let mut tags = crate::project_tag::list_by_project_ids(
        db,
        parents
            .iter()
            .filter(|p| !p.is_domain)
            .map(|p| p.id.clone())
            .collect(),
    )
    .await?;
    for parent in &mut parents {
        parent.tags = tags.remove(&parent.id).unwrap_or_default();
    }
    Ok(Some(parents))
}

/// The columns needed to follow the parents.
#[derive(FromQueryResult)]
struct ParentLink {
    id: String,
    parent_id: Option<String>,
}

/// Get the IDs of the parents of a project.
///
/// The same single query as [`get_project_parents`], but only the `id` and
/// `parent_id` columns are read and no project is built.
///
/// # Parameters
/// - `db`: Database connection.
/// - `id`: ID of the project.
///
/// # Returns
/// A `Result` containing an `Option` with the parent IDs, the closest one
/// first, if the project exists, or an `Error`.
pub async fn get_project_parent_ids<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Vec<String>>, ResourceProviderError> {
    let id = id.as_ref();
    let statement = ancestors_statement(
        db.get_database_backend(),
        id,
        &[ProjectColumn::Id, ProjectColumn::ParentId],
    )
    .context("building the project parent IDs query")?;
    let rows = ParentLink::find_by_statement(statement)
        .all(db)
        .await
        .context("resolving project parent IDs")?;
    let links: HashMap<&str, Option<&str>> = rows
        .iter()
        .map(|row| (row.id.as_str(), row.parent_id.as_deref()))
        .collect();
    Ok(parent_chain(id, &links).map(|chain| chain.into_iter().map(str::to_string).collect()))
}

/// Get all descendants of a project.
///
/// The tree is walked level by level (one query per level) so that the result
/// is ordered breadth first: every project is listed after its parent.
///
/// # Parameters
/// - `db`: Database connection.
/// - `id`: ID of the project.
///
/// # Returns
/// A `Result` containing an `Option` with the `Vec<Project>` if the project
/// exists, or an `Error`.
pub async fn get_project_subtree<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Vec<Project>>, ResourceProviderError> {
    if DbProject::find_by_id(id.as_ref())
        .one(db)
        .await
        .context("resolving project")?
        .is_none()
    {
        return Ok(None);
    }
    let mut res: Vec<Project> = Vec::new();
    let mut seen: HashSet<String> = HashSet::from([id.as_ref().to_string()]);
    let mut level: Vec<String> = vec![id.as_ref().to_string()];
    while !level.is_empty() {
        let children = DbProject::find()
            .filter(db_project::Column::ParentId.is_in(level))
            .order_by_asc(db_project::Column::Id)
            .all(db)
            .await
            .context("resolving project subtree")?;
        level = Vec::new();
        for child in children {
            // Guard against corrupt parent loops.
            if seen.insert(child.id.clone()) {
                level.push(child.id.clone());
                res.push(child.try_into()?);
            }
        }
    }
    Ok(Some(res))
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use crate::entity::project;

    use super::*;

    pub(super) fn get_mock<I: AsRef<str>, P: AsRef<str>>(
        id: I,
        parent_id: Option<P>,
    ) -> project::Model {
        project::Model {
            id: id.as_ref().to_string(),
            name: "project_name".into(),
            extra: None,
            description: Some("description".into()),
            enabled: Some(true),
            domain_id: "domain_id".into(),
            parent_id: parent_id.as_ref().map(|val| val.as_ref().into()),
            is_domain: false,
        }
    }

    #[tokio::test]
    async fn test_get_project_parents() {
        // One query returns the project and its ancestors, in any order.
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_mock("domain_id", None::<&str>),
                get_mock("3", Some("2")),
                get_mock("1", Some("domain_id")),
                get_mock("2", Some("1")),
            ]])
            .append_query_results([Vec::<crate::entity::project_tag::Model>::new()])
            .into_connection();

        let parents = get_project_parents(&db, "3").await.unwrap().unwrap();

        assert_eq!(
            vec!["2", "1", "domain_id"],
            parents.iter().map(|p| p.id.as_str()).collect::<Vec<_>>()
        );
        assert_eq!(Some("1".to_string()), parents[0].parent_id);
        assert_eq!(None, parents[2].parent_id);

        // The ancestors, then the tags of the non-domain ones.
        let log = db.into_transaction_log();
        assert_eq!(2, log.len(), "{log:?}");
    }

    #[tokio::test]
    async fn test_get_project_parents_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<project::Model>::new()])
            .into_connection();

        assert!(get_project_parents(&db, "3").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_get_project_parents_root() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mock("domain_id", None::<&str>)]])
            .append_query_results([Vec::<crate::entity::project_tag::Model>::new()])
            .into_connection();

        assert!(
            get_project_parents(&db, "domain_id")
                .await
                .unwrap()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_get_project_subtree() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mock("1", Some("domain_id"))]])
            .append_query_results([vec![get_mock("2", Some("1")), get_mock("3", Some("1"))]])
            .append_query_results([vec![get_mock("4", Some("2"))]])
            .append_query_results([Vec::<project::Model>::new()])
            .into_connection();
        let res = get_project_subtree(&db, "1").await.unwrap().unwrap();
        assert_eq!(
            res.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(),
            vec!["2", "3", "4"]
        );
    }

    #[tokio::test]
    async fn test_get_project_subtree_leaf() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mock("1", Some("domain_id"))]])
            .append_query_results([Vec::<project::Model>::new()])
            .into_connection();
        let res = get_project_subtree(&db, "1").await.unwrap().unwrap();
        assert!(res.is_empty());
    }

    #[tokio::test]
    async fn test_get_project_subtree_parent_loop() {
        // 1 -> 2 -> 1: the corrupt back reference must not be followed again.
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mock("1", Some("2"))]])
            .append_query_results([vec![get_mock("2", Some("1"))]])
            .append_query_results([vec![get_mock("1", Some("2"))]])
            .into_connection();
        let res = get_project_subtree(&db, "1").await.unwrap().unwrap();
        assert_eq!(
            res.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(),
            vec!["2"]
        );
    }

    #[tokio::test]
    async fn test_get_project_subtree_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<project::Model>::new()])
            .into_connection();
        assert!(get_project_subtree(&db, "1").await.unwrap().is_none());
    }

    #[test]
    fn test_ancestors_statement_is_one_recursive_query() {
        for backend in [
            DatabaseBackend::Postgres,
            DatabaseBackend::MySql,
            DatabaseBackend::Sqlite,
        ] {
            let stmt = ancestors_statement(backend, "3", &[ProjectColumn::Id]).unwrap();
            assert!(stmt.sql.starts_with("WITH RECURSIVE"), "{}", stmt.sql);
            assert!(!stmt.sql.contains("UNION ALL"), "{}", stmt.sql);
            assert_eq!(1, stmt.values.map_or(0, |v| v.0.len()), "{}", stmt.sql);
        }
    }
}
