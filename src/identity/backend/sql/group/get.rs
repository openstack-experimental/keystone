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

use crate::db::entity::prelude::Group as DbGroup;
use crate::error::DbContextExt;
use crate::identity::backend::sql::IdentityDatabaseError;
use crate::identity::types::Group;

#[tracing::instrument(skip_all)]
pub async fn get<S: AsRef<str>>(
    db: &DatabaseConnection,
    group_id: S,
) -> Result<Option<Group>, IdentityDatabaseError> {
    Ok(DbGroup::find_by_id(group_id.as_ref())
        .one(db)
        .await
        .context("fetching group data")?
        .map(Into::into))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::derivable_impls)]

    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
    use serde_json::json;

    use super::super::tests::get_group_mock;
    use super::*;

    #[tokio::test]
    async fn test_get() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_group_mock("1")], vec![]])
            .into_connection();

        assert_eq!(
            get(&db, "id").await.unwrap(),
            Some(Group {
                id: "1".into(),
                domain_id: "foo_domain".into(),
                name: "group".into(),
                description: Some("fake".into()),
                extra: Some(json!({"foo": "bar"}))
            })
        );
        assert!(get(&db, "missing").await.unwrap().is_none());

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "group"."id", "group"."domain_id", "group"."name", "group"."description", "group"."extra" FROM "group" WHERE "group"."id" = $1 LIMIT $2"#,
                    ["id".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "group"."id", "group"."domain_id", "group"."name", "group"."description", "group"."extra" FROM "group" WHERE "group"."id" = $1 LIMIT $2"#,
                    ["missing".into(), 1u64.into()]
                ),
            ]
        );
    }
}
