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

use crate::db::entity::{
    prelude::WebauthnCredential as DbWebauthnCredential,
    webauthn_credential as db_webauthn_credential,
};
use crate::error::DbContextExt;
use crate::webauthn::{WebauthnError, types::WebauthnCredential};

pub async fn update(
    db: &DatabaseConnection,
    internal_id: i32,
    credential: &WebauthnCredential,
) -> Result<WebauthnCredential, WebauthnError> {
    if let Some(current) = DbWebauthnCredential::find_by_id(internal_id)
        .one(db)
        .await
        .context("fetching current webauthn_credential data for update")?
    {
        if current.credential_id != credential.credential_id {
            return Err(WebauthnError::Conflict(
                "updating credential_id is not allowed".to_string(),
            ));
        }

        let mut entry: db_webauthn_credential::ActiveModel = current.into();

        entry.counter = Set(credential.counter.try_into()?);
        entry.passkey = Set(serde_json::to_string(&credential.data)?);
        if let Some(val) = &credential.description {
            entry.description = Set(Some(val.clone()));
        }
        if let Some(val) = credential.last_used_at {
            entry.last_used_at = Set(Some(val.naive_utc()));
        }
        if let Some(val) = credential.updated_at {
            entry.last_updated_at = Set(Some(val.naive_utc()));
        }
        entry
            .update(db)
            .await
            .context("updating webauthn credential")?
            .try_into()
    } else {
        Err(WebauthnError::CredentialNotFound(internal_id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::{get_fake_passkey, get_mock};
    use super::*;
    use crate::webauthn::types::*;

    #[tokio::test]
    async fn test_update() {
        let now = Utc::now();
        let passkey = get_fake_passkey();
        let current = get_mock("uid");
        let mut cred: WebauthnCredential = current.clone().try_into().unwrap();

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![current]])
            .append_query_results([vec![get_mock("uid")]])
            .into_connection();

        cred.last_used_at = Some(now);
        cred.updated_at = Some(now);
        cred.data = get_fake_passkey();
        cred.counter = 5;

        update(&db, 1, &cred).await.unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "webauthn_credential"."id", "webauthn_credential"."user_id", "webauthn_credential"."credential_id", "webauthn_credential"."description", "webauthn_credential"."passkey", "webauthn_credential"."counter", "webauthn_credential"."type", "webauthn_credential"."aaguid", "webauthn_credential"."created_at", "webauthn_credential"."last_used_at", "webauthn_credential"."last_updated_at" FROM "webauthn_credential" WHERE "webauthn_credential"."id" = $1 LIMIT $2"#,
                    [1i32.into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"UPDATE "webauthn_credential" SET "description" = $1, "passkey" = $2, "counter" = $3, "last_used_at" = $4, "last_updated_at" = $5 WHERE "webauthn_credential"."id" = $6 RETURNING "id", "user_id", "credential_id", "description", "passkey", "counter", "type", "aaguid", "created_at", "last_used_at", "last_updated_at""#,
                    [
                        cred.description.into(),
                        serde_json::to_string(&passkey).unwrap().into(),
                        5.into(),
                        now.naive_utc().into(),
                        now.naive_utc().into(),
                        cred.internal_id.into()
                    ]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_update_conflict() {
        let current = get_mock("uid");
        let mut cred: WebauthnCredential = current.clone().try_into().unwrap();

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![current]])
            .into_connection();

        cred.credential_id = "new".into();

        match update(&db, 1, &cred).await {
            Err(WebauthnError::Conflict(_)) => {
                // Checking transaction log
                assert_eq!(
                    db.into_transaction_log(),
                    [Transaction::from_sql_and_values(
                        DatabaseBackend::Postgres,
                        r#"SELECT "webauthn_credential"."id", "webauthn_credential"."user_id", "webauthn_credential"."credential_id", "webauthn_credential"."description", "webauthn_credential"."passkey", "webauthn_credential"."counter", "webauthn_credential"."type", "webauthn_credential"."aaguid", "webauthn_credential"."created_at", "webauthn_credential"."last_used_at", "webauthn_credential"."last_updated_at" FROM "webauthn_credential" WHERE "webauthn_credential"."id" = $1 LIMIT $2"#,
                        [1i32.into(), 1u64.into()]
                    ),]
                );
            }
            other => {
                panic!(
                    "Update of the credential_id must be rejected, got {:?}",
                    other
                );
            }
        }
    }
}
