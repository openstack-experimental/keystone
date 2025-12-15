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

use chrono::{DateTime, Local, Utc};
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use webauthn_rs::prelude::Passkey;

use crate::db::entity::webauthn_credential;
use crate::webauthn::{WebauthnError, db_err, types::WebauthnCredential};

pub async fn create<U: AsRef<str>, D: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
    passkey: &Passkey,
    description: Option<D>,
    created_at: Option<DateTime<Utc>>,
) -> Result<WebauthnCredential, WebauthnError> {
    //let now = createLocal::now().naive_utc();
    let entry = webauthn_credential::ActiveModel {
        id: NotSet,
        user_id: Set(user_id.as_ref().to_string()),
        credential_id: Set(serde_json::to_string(passkey.cred_id())?
            .trim_matches('"')
            .to_string()),
        description: if let Some(v) = description {
            Set(Some(v.as_ref().to_string()))
        } else {
            NotSet
        },
        passkey: Set(serde_json::to_string(&passkey)?),
        r#type: Set("cross-platform".to_string()),
        aaguid: NotSet,
        created_at: Set(created_at
            .map(|dt| dt.naive_utc())
            .unwrap_or_else(|| Local::now().naive_utc())),
        last_used_at: NotSet,
        last_updated_at: NotSet,
    };
    let cred = entry
        .insert(db)
        .await
        .map_err(|e| db_err(e, "inserting webauth credential"))?
        .into();
    Ok(cred)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::super::tests::{get_fake_passkey, get_mock};
    use super::*;

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
        let now = Local::now();
        create(&db, "uid", &passkey, Some("desc"), Some(now.into()))
            .await
            .unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "webauthn_credential" ("user_id", "credential_id", "description", "passkey", "type", "created_at") VALUES ($1, $2, $3, $4, $5, $6) RETURNING "id", "user_id", "credential_id", "description", "passkey", "type", "aaguid", "created_at", "last_used_at", "last_updated_at""#,
                [
                    "uid".into(),
                    serde_json::to_string(passkey.cred_id())
                        .unwrap()
                        .trim_matches('"')
                        .into(),
                    "desc".into(),
                    serde_json::to_string(&passkey).unwrap().into(),
                    "cross-platform".into(),
                    now.naive_utc().into()
                ]
            ),]
        );
    }
}
