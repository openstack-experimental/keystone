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

use std::collections::HashSet;

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::resource::ResourceProviderError;
use openstack_keystone_core_types::resource::Project;

use crate::entity::prelude::Project as DbProject;
use crate::entity::project as db_project;

/// Get the parents of a project.
///
/// # Parameters
/// - `db`: Database connection.
/// - `id`: ID of the project.
///
/// # Returns
/// A `Result` containing an `Option` with the `Vec<Project>` if found, or an
/// `Error`.
pub async fn get_project_parents<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Vec<Project>>, ResourceProviderError> {
    let mut res: Vec<Project> = Vec::new();
    let mut project_id: Option<String> = Some(id.as_ref().to_string());
    while let Some(pid) = project_id {
        let project = DbProject::find_by_id(pid.clone())
            .one(db)
            .await
            .context("resolving project parents")?;
        if pid == id.as_ref() && project.is_none() {
            return Ok(None);
        }
        if let Some(p) = &project
            && pid != id.as_ref()
        {
            let mut parent: Project = p.clone().try_into()?;
            if !p.is_domain {
                parent.tags = crate::project_tag::list_by_project_id(db, &p.id).await?;
            }
            res.push(parent);
        }
        project_id = project.and_then(|project| project.parent_id);
    }

    Ok(Some(res))
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
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use openstack_keystone_core_types::resource::Project;

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
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mock("3", Some("2"))]])
            .append_query_results([vec![get_mock("2", Some("1"))]])
            .append_query_results([vec![crate::entity::project_tag::Model {
                project_id: "2".into(),
                name: "tag".into(),
            }]])
            .append_query_results([vec![get_mock("1", Some("domain_id"))]])
            .append_query_results([Vec::<crate::entity::project_tag::Model>::new()])
            .append_query_results([vec![get_mock("domain_id", None::<&str>)]])
            .append_query_results([Vec::<crate::entity::project_tag::Model>::new()])
            .into_connection();
        assert_eq!(
            get_project_parents(&db, "3").await.unwrap().unwrap(),
            vec![
                Project {
                    tags: vec!["tag".to_string()],
                    id: "2".into(),
                    parent_id: Some("1".into()),
                    name: "project_name".into(),
                    domain_id: "domain_id".into(),
                    enabled: true,
                    description: Some("description".into()),
                    extra: std::collections::HashMap::new(),
                    is_domain: false,
                    options: Default::default(),
                },
                Project {
                    tags: Default::default(),
                    id: "1".into(),
                    parent_id: Some("domain_id".into()),
                    name: "project_name".into(),
                    domain_id: "domain_id".into(),
                    enabled: true,
                    description: Some("description".into()),
                    extra: std::collections::HashMap::new(),
                    is_domain: false,
                    options: Default::default(),
                },
                Project {
                    tags: Default::default(),
                    id: "domain_id".into(),
                    parent_id: None,
                    name: "project_name".into(),
                    domain_id: "domain_id".into(),
                    enabled: true,
                    description: Some("description".into()),
                    extra: std::collections::HashMap::new(),
                    is_domain: false,
                    options: Default::default(),
                }
            ]
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."id" = $1 LIMIT $2"#,
                    ["3".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."id" = $1 LIMIT $2"#,
                    ["2".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "project_tag"."project_id", "project_tag"."name" FROM "project_tag" WHERE "project_tag"."project_id" = $1 ORDER BY "project_tag"."name" ASC"#,
                    ["2".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."id" = $1 LIMIT $2"#,
                    ["1".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "project_tag"."project_id", "project_tag"."name" FROM "project_tag" WHERE "project_tag"."project_id" = $1 ORDER BY "project_tag"."name" ASC"#,
                    ["1".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."id" = $1 LIMIT $2"#,
                    ["domain_id".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "project_tag"."project_id", "project_tag"."name" FROM "project_tag" WHERE "project_tag"."project_id" = $1 ORDER BY "project_tag"."name" ASC"#,
                    ["domain_id".into()]
                ),
            ]
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
}
