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
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

use crate::db::entity::{prelude::WebauthnState as DbPasskeyState, webauthn_state};
use crate::error::DbContextExt;
use crate::webauthn::error::WebauthnError;

pub async fn get_register<U: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
) -> Result<Option<PasskeyRegistration>, WebauthnError> {
    match DbPasskeyState::find_by_id(user_id.as_ref())
        .filter(webauthn_state::Column::Type.eq("register"))
        .one(db)
        .await
        .context("searching for webauthn registration state record")?
    {
        Some(rec) => Ok(Some(serde_json::from_str(&rec.state)?)),
        None => Ok(None),
    }
}

pub async fn get_auth<U: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
) -> Result<Option<PasskeyAuthentication>, WebauthnError> {
    match DbPasskeyState::find_by_id(user_id.as_ref())
        .filter(webauthn_state::Column::Type.eq("auth"))
        .one(db)
        .await
        .context("searching for webauthn auth state record")?
    {
        Some(rec) => Ok(Some(serde_json::from_str(&rec.state)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_get_auth() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<webauthn_state::Model>::new()])
            .into_connection();

        assert!(get_auth(&db, "id").await.unwrap().is_none());

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "webauthn_state"."user_id", "webauthn_state"."state", "webauthn_state"."type", "webauthn_state"."created_at" FROM "webauthn_state" WHERE "webauthn_state"."user_id" = $1 AND "webauthn_state"."type" = $2 LIMIT $3"#,
                ["id".into(), "auth".into(), 1u64.into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_get_register() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<webauthn_state::Model>::new()])
            .into_connection();

        assert!(get_register(&db, "id").await.unwrap().is_none());

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "webauthn_state"."user_id", "webauthn_state"."state", "webauthn_state"."type", "webauthn_state"."created_at" FROM "webauthn_state" WHERE "webauthn_state"."user_id" = $1 AND "webauthn_state"."type" = $2 LIMIT $3"#,
                ["id".into(), "register".into(), 1u64.into()]
            ),]
        );
    }
}
