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

use sea_orm::entity::*;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

use openstack_keystone_core::error::DbContextExt;

use crate::WebauthnError;
use crate::driver::sql::model::prelude::WebauthnState as DbPasskeyState;

use super::StateType;

/// Get registration state.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_id`: The user ID.
///
/// # Returns
/// A `Result` containing an `Option` with the `PasskeyRegistration` if found,
/// or an `Error`.
pub async fn get_register<U: AsRef<str>>(
    db: &sea_orm::DatabaseConnection,
    user_id: U,
) -> Result<Option<PasskeyRegistration>, WebauthnError> {
    match DbPasskeyState::find_by_id((
        user_id.as_ref().to_string(),
        StateType::Register.as_str().to_string(),
    ))
    .one(db)
    .await
    .context("searching for webauthn registration state record")?
    {
        Some(rec) => Ok(Some(serde_json::from_str(&rec.state)?)),
        None => Ok(None),
    }
}

/// Get authentication state.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_id`: The user ID.
///
/// # Returns
/// A `Result` containing an `Option` with the `PasskeyAuthentication` if found,
/// or an `Error`.
pub async fn get_auth<U: AsRef<str>>(
    db: &sea_orm::DatabaseConnection,
    user_id: U,
) -> Result<Option<PasskeyAuthentication>, WebauthnError> {
    match DbPasskeyState::find_by_id((
        user_id.as_ref().to_string(),
        StateType::Auth.as_str().to_string(),
    ))
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
    use crate::driver::sql::model::webauthn_state;

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

    #[tokio::test]
    async fn test_get_auth_found() {
        // PasskeyAuthentication wraps AuthenticationState under "ast"
        let auth_json = r#"{"ast": {"credentials": [], "policy": "preferred", "challenge": "dGVzdC1jaGFsbGVuZ2U", "appid": null, "allow_backup_eligible_upgrade": false}}"#;

        let model = webauthn_state::Model {
            user_id: "uid".to_string(),
            state: auth_json.to_string(),
            r#type: "auth".to_string(),
            created_at: chrono::Utc::now().naive_utc(),
        };

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![model]])
            .into_connection();

        let result = get_auth(&db, "uid").await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_get_register_found() {
        // PasskeyRegistration wraps RegistrationState under "rs"
        let reg_json = r#"{"rs": {"policy": "preferred", "exclude_credentials": [], "challenge": "dGVzdC1jaGFsbGVuZ2U", "credential_algorithms": [], "require_resident_key": false, "authenticator_attachment": null, "extensions": {}, "allow_synchronised_authenticators": false}}"#;

        let model = webauthn_state::Model {
            user_id: "uid".to_string(),
            state: reg_json.to_string(),
            r#type: "register".to_string(),
            created_at: chrono::Utc::now().naive_utc(),
        };

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![model]])
            .into_connection();

        let result = get_register(&db, "uid").await.unwrap();
        assert!(result.is_some());
    }
}
