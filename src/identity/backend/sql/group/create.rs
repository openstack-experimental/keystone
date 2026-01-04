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
use serde_json::json;

use crate::db::entity::group;
use crate::error::DbContextExt;
use crate::identity::backend::sql::IdentityDatabaseError;
use crate::identity::types::{Group, GroupCreate};

pub async fn create(
    db: &DatabaseConnection,
    group: GroupCreate,
) -> Result<Group, IdentityDatabaseError> {
    let entry = group::ActiveModel {
        id: Set(group.id.clone().unwrap_or_default()),
        domain_id: Set(group.domain_id.clone()),
        name: Set(group.name.clone()),
        description: Set(group.description.clone()),
        extra: Set(Some(serde_json::to_string(
            &group.extra.as_ref().or(Some(&json!({}))),
        )?)),
    };

    let db_entry: group::Model = entry
        .insert(db)
        .await
        .context("persisting new group record")?;

    Ok(db_entry.into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::derivable_impls)]

    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
    use serde_json::json;

    use super::super::tests::get_group_mock;
    use super::*;

    #[tokio::test]
    async fn test_create() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_group_mock("1")], vec![]])
            .into_connection();

        let req = GroupCreate {
            id: Some("1".into()),
            domain_id: "foo_domain".into(),
            name: "group".into(),
            description: Some("fake".into()),
            extra: Some(json!({"foo": "bar"})),
        };
        assert_eq!(create(&db, req).await.unwrap(), get_group_mock("1").into());
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "group" ("id", "domain_id", "name", "description", "extra") VALUES ($1, $2, $3, $4, $5) RETURNING "id", "domain_id", "name", "description", "extra""#,
                [
                    "1".into(),
                    "foo_domain".into(),
                    "group".into(),
                    "fake".into(),
                    "{\"foo\":\"bar\"}".into()
                ]
            ),]
        );
    }

    #[tokio::test]
    async fn test_create_empty_extra() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_group_mock("1")], vec![]])
            .into_connection();

        let req = GroupCreate {
            id: Some("1".into()),
            domain_id: "foo_domain".into(),
            name: "group".into(),
            description: Some("fake".into()),
            extra: None,
        };
        assert_eq!(create(&db, req).await.unwrap(), get_group_mock("1").into());
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "group" ("id", "domain_id", "name", "description", "extra") VALUES ($1, $2, $3, $4, $5) RETURNING "id", "domain_id", "name", "description", "extra""#,
                [
                    "1".into(),
                    "foo_domain".into(),
                    "group".into(),
                    "fake".into(),
                    "{}".into()
                ]
            ),]
        );
    }
}
