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

use crate::db::entity::webauthn_credential;
use crate::error::DbContextExt;
use crate::webauthn::{WebauthnError, types::WebauthnCredential};

pub async fn create(
    db: &DatabaseConnection,
    credential: WebauthnCredential,
) -> Result<WebauthnCredential, WebauthnError> {
    webauthn_credential::ActiveModel::try_from(credential)?
        .insert(db)
        .await
        .context("inserting webauthn credential")?
        .try_into()
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::Utc;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::super::tests::{get_fake_passkey, get_mock};
    use super::*;
    use crate::webauthn::types::*;

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mock("uid")]])
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();
        let passkey = get_fake_passkey();
        let now = Utc::now();

        let cred = WebauthnCredential {
            created_at: now,
            credential_id: URL_SAFE_NO_PAD.encode(passkey.cred_id()),
            data: passkey.clone(),
            counter: 0,
            description: Some("description".into()),
            internal_id: 0,
            last_used_at: None,
            r#type: CredentialType::CrossPlatform,
            updated_at: None,
            user_id: "uid".into(),
        };
        create(&db, cred).await.unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "webauthn_credential" ("user_id", "credential_id", "description", "passkey", "counter", "type", "created_at") VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING "id", "user_id", "credential_id", "description", "passkey", "counter", "type", "aaguid", "created_at", "last_used_at", "last_updated_at""#,
                [
                    "uid".into(),
                    URL_SAFE_NO_PAD.encode(passkey.cred_id()).into(),
                    "description".into(),
                    serde_json::to_string(&passkey).unwrap().into(),
                    0.into(),
                    "cross-platform".into(),
                    now.naive_utc().into()
                ]
            ),]
        );
    }
}
