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
use crate::resource::{
    ResourceProviderError,
    types::{Domain, DomainListParameters},
};

/// Prepare the paginated query for listing domains.
fn get_list_query(
    params: &DomainListParameters,
) -> Result<Cursor<SelectModel<db_project::Model>>, ResourceProviderError> {
    let mut select = DbProject::find().filter(db_project::Column::IsDomain.eq(true));

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
    params: &DomainListParameters,
) -> Result<Vec<Domain>, ResourceProviderError> {
    get_list_query(params)?
        .all(db)
        .await
        .context("listing domains")?
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
            r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."is_domain" = TRUE"#,
            QueryOrder::query(&mut get_list_query(&DomainListParameters::default()).unwrap())
                .to_string(PostgresQueryBuilder)
        );
    }

    #[tokio::test]
    async fn test_query_name() {
        assert!(
            QueryOrder::query(
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
        let q = QueryOrder::query(
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
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_domain_mock("pid1")]])
            .into_connection();

        assert_eq!(
            list(&db, &DomainListParameters::default()).await.unwrap(),
            vec![Domain {
                description: None,
                enabled: true,
                extra: None,
                id: "pid1".into(),
                name: "name".into(),
            }]
        );

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "project"."id", "project"."name", "project"."extra", "project"."description", "project"."enabled", "project"."domain_id", "project"."parent_id", "project"."is_domain" FROM "project" WHERE "project"."is_domain" = $1 ORDER BY "project"."id" ASC"#,
                [true.into()]
            ),]
        );
    }
}
