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

use serde_json::Value;
use tracing::error;

mod create;
mod list;

pub use create::create;
pub use list::get;
pub use list::list;

use crate::assignment::backend::error::AssignmentDatabaseError;
use crate::assignment::types::role::*;
use crate::db::entity::role as db_role;

static NULL_DOMAIN_ID: &str = "<<null>>";

impl TryFrom<db_role::Model> for Role {
    type Error = AssignmentDatabaseError;

    fn try_from(value: db_role::Model) -> Result<Self, Self::Error> {
        let mut builder = RoleBuilder::default();
        builder.id(value.id.clone());
        builder.name(value.name.clone());
        if value.domain_id != NULL_DOMAIN_ID {
            builder.domain_id(value.domain_id.clone());
        }
        if let Some(description) = &value.description {
            builder.description(description.clone());
        }
        if let Some(extra) = &value.extra {
            builder.extra(
                serde_json::from_str::<Value>(extra)
                    .inspect_err(|e| error!("failed to deserialize role extra: {e}"))
                    .unwrap_or_default(),
            );
        }

        Ok(builder.build()?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use crate::config::Config;
    use crate::db::entity::role;

    use super::*;

    pub(crate) fn get_role_mock(id: String) -> role::Model {
        role::Model {
            id: id.clone(),
            domain_id: "foo_domain".into(),
            name: "foo".into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_get() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([
                // First query result - select user itself
                vec![get_role_mock("1".into())],
            ])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            get(&config, &db, "1").await.unwrap().unwrap(),
            Role {
                id: "1".into(),
                domain_id: Some("foo_domain".into()),
                name: "foo".to_owned(),
                ..Default::default()
            }
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "role"."id", "role"."name", "role"."extra", "role"."domain_id", "role"."description" FROM "role" WHERE "role"."id" = $1 LIMIT $2"#,
                ["1".into(), 1u64.into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_list() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([
                // First query result - select user itself
                vec![get_role_mock("1".into())],
            ])
            .append_query_results([
                // First query result - select user itself
                vec![get_role_mock("1".into())],
            ])
            .append_query_results([
                // First query result - select user itself
                vec![get_role_mock("1".into())],
            ])
            .into_connection();
        let config = Config::default();
        assert!(
            list(&config, &db, &RoleListParameters::default())
                .await
                .is_ok()
        );
        assert_eq!(
            list(
                &config,
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
