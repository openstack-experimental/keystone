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

use crate::db::entity::{group, prelude::Group as DbGroup};
use crate::error::DbContextExt;
use crate::identity::backend::sql::IdentityDatabaseError;
use crate::identity::types::{Group, GroupListParameters};

pub async fn list(
    db: &DatabaseConnection,
    params: &GroupListParameters,
) -> Result<Vec<Group>, IdentityDatabaseError> {
    // Prepare basic selects
    let mut group_select = DbGroup::find();

    if let Some(domain_id) = &params.domain_id {
        group_select = group_select.filter(group::Column::DomainId.eq(domain_id));
    }
    if let Some(name) = &params.name {
        group_select = group_select.filter(group::Column::Name.eq(name));
    }

    Ok(group_select
        .all(db)
        .await
        .context("listing groups")?
        .into_iter()
        .map(Into::into)
        .collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::derivable_impls)]

    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
    use serde_json::json;

    use crate::db::entity::group;
    use crate::identity::types::group::GroupListParametersBuilder;

    use super::super::tests::get_group_mock;
    use super::*;

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
                extra: Some(json!({"foo": "bar"}))
            }]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "group"."id", "group"."domain_id", "group"."name", "group"."description", "group"."extra" FROM "group""#,
                //["1".into(), 1u64.into()]
                []
            ),]
        );
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
                r#"SELECT "group"."id", "group"."domain_id", "group"."name", "group"."description", "group"."extra" FROM "group" WHERE "group"."domain_id" = $1 AND "group"."name" = $2"#,
                ["d".into(), "n".into()]
            ),]
        );
    }
}
