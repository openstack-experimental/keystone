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

use crate::db::entity::{prelude::Project as DbProject, project as db_project};
use crate::error::DbContextExt;
use crate::resource::backend::error::ResourceDatabaseError;
use crate::resource::types::*;

/// Prepare the paginated query for listing mappings.
fn get_list_query(
    params: &ProjectListParameters,
) -> Result<Cursor<SelectModel<db_project::Model>>, ResourceDatabaseError> {
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

    Ok(select.cursor_by(db_project::Column::Id))
}

pub async fn list(
    db: &DatabaseConnection,
    params: &ProjectListParameters,
) -> Result<Vec<Project>, ResourceDatabaseError> {
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
    use sea_orm::{DatabaseBackend, MockDatabase, QueryOrder, Transaction, sea_query::*};

    use super::super::tests::*;
    use super::*;

    #[tokio::test]
    async fn test_query_all() {
        assert_eq!(
            r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."is_domain" = FALSE"#,
            QueryOrder::query(&mut get_list_query(&ProjectListParameters::default()).unwrap())
                .to_string(PostgresQueryBuilder)
        );
    }

    #[tokio::test]
    async fn test_query_domain_id() {
        assert!(
            QueryOrder::query(
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
            QueryOrder::query(
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
        let q = QueryOrder::query(
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
                extra: None,
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
