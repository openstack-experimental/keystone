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

use sea_orm::ConnectionTrait;
use sea_orm::entity::*;

use crate::db::entity::{nonlocal_user, user};
use crate::error::DbContextExt;
use crate::identity::IdentityProviderError;

/// Persist nonlocal user entry.
#[tracing::instrument(skip_all)]
pub async fn create<C, S>(
    db: &C,
    main_record: &user::Model,
    name: S,
) -> Result<nonlocal_user::Model, IdentityProviderError>
where
    C: ConnectionTrait,
    S: Into<String>,
{
    Ok(nonlocal_user::ActiveModel {
        user_id: Set(main_record.id.clone()),
        domain_id: Set(main_record.domain_id.clone()),
        name: Set(name.into()),
    }
    .insert(db)
    .await
    .context("inserting new nonlocal user record")?)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_create() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![nonlocal_user::Model {
                domain_id: "did".into(),
                name: "uname".into(),
                user_id: "1".into(),
            }]])
            .into_connection();

        let usr = user::Model {
            id: "1".into(),
            domain_id: "did".into(),
            ..Default::default()
        };
        assert_eq!(
            create(&db, &usr, "uname").await.unwrap(),
            nonlocal_user::Model {
                domain_id: "did".into(),
                name: "uname".into(),
                user_id: "1".into(),
            }
        );
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "nonlocal_user" ("domain_id", "name", "user_id") VALUES ($1, $2, $3) RETURNING "domain_id", "name", "user_id""#,
                ["did".into(), "uname".into(), "1".into(),]
            ),]
        );
    }
}
