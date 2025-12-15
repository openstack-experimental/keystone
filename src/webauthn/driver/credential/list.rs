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
use webauthn_rs::prelude::Passkey;

use crate::db::entity::{prelude::WebauthnCredential as DbCred, webauthn_credential};
use crate::webauthn::{WebauthnError, db_err};

pub async fn list<U: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
) -> Result<Vec<Passkey>, WebauthnError> {
    let res: Result<Vec<Passkey>, _> = DbCred::find()
        .filter(webauthn_credential::Column::UserId.eq(user_id.as_ref()))
        .all(db)
        .await
        .map_err(|e| db_err(e, "listing webauth credential"))?
        .into_iter()
        .map(|x| serde_json::from_str::<Passkey>(&x.passkey))
        .collect();
    Ok(res?)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_mock;
    use super::*;

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mock("uid")]])
            .into_connection();

        list(&db, "uid").await.unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "webauthn_credential"."id", "webauthn_credential"."user_id", "webauthn_credential"."credential_id", "webauthn_credential"."description", "webauthn_credential"."passkey", "webauthn_credential"."type", "webauthn_credential"."aaguid", "webauthn_credential"."created_at", "webauthn_credential"."last_used_at", "webauthn_credential"."last_updated_at" FROM "webauthn_credential" WHERE "webauthn_credential"."user_id" = $1"#,
                ["uid".into()]
            ),]
        );
    }
}
