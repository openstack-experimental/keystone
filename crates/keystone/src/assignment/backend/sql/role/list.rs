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

use crate::assignment::backend::error::AssignmentDatabaseError;
use crate::assignment::types::*;
use crate::db::entity::{prelude::Role as DbRole, role as db_role};
use crate::error::DbContextExt;

pub async fn list(
    db: &DatabaseConnection,
    params: &RoleListParameters,
) -> Result<Vec<Role>, AssignmentDatabaseError> {
    let mut select = DbRole::find();

    if let Some(domain_id) = &params.domain_id {
        select = select.filter(db_role::Column::DomainId.eq(domain_id));
    }
    if let Some(name) = &params.name {
        select = select.filter(db_role::Column::Name.eq(name));
    }

    let db_roles: Vec<db_role::Model> = select.all(db).await.context("listing roles")?;
    let results: Result<Vec<Role>, _> = db_roles
        .into_iter()
        .map(TryInto::<Role>::try_into)
        .collect();

    results
}

#[cfg(test)]
pub(super) mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_role_mock;
    use super::*;

    #[tokio::test]
    async fn test_list() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([
                // First query result - select user itself
                vec![get_role_mock("1", "foo")],
            ])
            .append_query_results([
                // First query result - select user itself
                vec![get_role_mock("1", "foo")],
            ])
            .append_query_results([
                // First query result - select user itself
                vec![get_role_mock("1", "foo")],
            ])
            .into_connection();
        assert!(list(&db, &RoleListParameters::default()).await.is_ok());
        assert_eq!(
            list(
                &db,
                &RoleListParameters {
                    name: Some("foo".into()),
                    domain_id: Some("foo_domain".into())
                }
            )
            .await
            .unwrap(),
            vec![Role {
                id: "1".into(),
                domain_id: Some("foo_domain".into()),
                name: "foo".to_owned(),
                ..Default::default()
            }]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "role"."id", "role"."name", "role"."extra", "role"."domain_id", "role"."description" FROM "role""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "role"."id", "role"."name", "role"."extra", "role"."domain_id", "role"."description" FROM "role" WHERE "role"."domain_id" = $1 AND "role"."name" = $2"#,
                    ["foo_domain".into(), "foo".into()]
                ),
            ]
        );
    }
}
