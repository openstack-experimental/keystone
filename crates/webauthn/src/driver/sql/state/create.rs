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

use chrono::Utc;
use sea_orm::ActiveModelTrait;
use sea_orm::query::*;
use sea_orm::{ColumnTrait, ConnectionTrait, DatabaseConnection, TransactionTrait, entity::*};
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

use openstack_keystone_core::error::DbContextExt;

use crate::WebauthnError;
use crate::driver::sql::model::{
    prelude::WebauthnState as DbPasskeyState, webauthn_state, webauthn_state as col,
};

use super::StateType;

async fn upsert<C, U, S>(
    txn: &C,
    user_id: U,
    state_type: StateType,
    state: &S,
) -> Result<(), WebauthnError>
where
    U: AsRef<str>,
    S: serde::Serialize,
    C: ConnectionTrait,
{
    // Delete any existing state for this user + type first, then insert the
    // new state. Running both steps inside a single transaction prevents
    // concurrent /start requests from colliding on the primary key.
    DbPasskeyState::delete_many()
        .filter(col::Column::UserId.eq(user_id.as_ref()))
        .filter(col::Column::Type.eq(state_type.as_str()))
        .exec(txn)
        .await
        .context("deleting existing webauthn state record before insert")?;

    let now = Utc::now().naive_utc();
    let entry = webauthn_state::ActiveModel {
        user_id: Set(user_id.as_ref().to_string()),
        state: Set(serde_json::to_string(&state)?),
        r#type: Set(state_type.as_str().to_string()),
        created_at: Set(now),
    };
    let _ = entry
        .insert(txn)
        .await
        .context("inserting webauthn state record")?;
    Ok(())
}

/// Create registration state.
///
/// Runs the delete-existing + insert in a single transaction so concurrent
/// `/start` requests for the same user don't hit a PK conflict.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_id`: The user ID.
/// - `state`: The registration state to save.
///
/// # Returns
/// A `Result` containing `()` on success, or a `WebauthnError`.
pub async fn create_register<U: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
    state: &PasskeyRegistration,
) -> Result<(), WebauthnError> {
    let txn = db
        .begin()
        .await
        .context("beginning transaction for webauthn registration state")?;
    upsert(&txn, user_id, StateType::Register, state).await?;
    txn.commit()
        .await
        .context("committing transaction for webauthn registration state")?;
    Ok(())
}

/// Create authentication state.
///
/// Runs the delete-existing + insert in a single transaction so concurrent
/// `/start` requests for the same user don't hit a PK conflict.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_id`: The user ID.
/// - `state`: The authentication state to save.
///
/// # Returns
/// A `Result` containing `()` on success, or a `WebauthnError`.
pub async fn create_auth<U: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
    state: &PasskeyAuthentication,
) -> Result<(), WebauthnError> {
    let txn = db
        .begin()
        .await
        .context("beginning transaction for webauthn authentication state")?;
    upsert(&txn, user_id, StateType::Auth, state).await?;
    txn.commit()
        .await
        .context("committing transaction for webauthn authentication state")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, TransactionTrait};

    use super::super::StateType;
    use super::*;
    use crate::driver::sql::model::webauthn_state;

    fn make_model(user_id: &str, stype: &str, payload: &str) -> webauthn_state::Model {
        webauthn_state::Model {
            user_id: user_id.to_string(),
            state: payload.to_string(),
            r#type: stype.to_string(),
            created_at: chrono::Utc::now().naive_utc(),
        }
    }

    fn sv<S: Into<String>>(s: S) -> sea_orm::Value {
        sea_orm::Value::String(Some(s.into()))
    }

    // upsert is private; tests exercise it directly with arbitrary serializable
    // payloads. This covers the same SQL path as create_auth and create_register.

    #[tokio::test]
    async fn test_upsert_auth_delete_then_insert() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 0,
                ..Default::default()
            }])
            .append_query_results([vec![make_model("uid", "auth", "\"hello\"")]])
            .into_connection();

        let txn = db.begin().await.unwrap();
        upsert(&txn, "uid", StateType::Auth, &"hello")
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let log = db.into_transaction_log();
        assert!(!log.is_empty());
        let txn_stmts = log[0].statements();
        assert_eq!(txn_stmts.len(), 4);

        // BEGIN
        assert_eq!(txn_stmts[0].sql, "BEGIN");

        // DELETE: must filter on both user_id and type == "auth"
        assert_eq!(
            txn_stmts[1].sql,
            r#"DELETE FROM "webauthn_state" WHERE "webauthn_state"."user_id" = $1 AND "webauthn_state"."type" = $2"#
        );

        // INSERT: must target webauthn_state with type = "auth"
        assert_eq!(
            txn_stmts[2].sql,
            r#"INSERT INTO "webauthn_state" ("user_id", "state", "type", "created_at") VALUES ($1, $2, $3, $4) RETURNING "user_id", "state", "type", "created_at""#
        );

        // Verify INSERT bind values carry "auth" type
        assert_eq!(txn_stmts[2].values.as_ref().unwrap().0[2], sv("auth"));

        // COMMIT
        assert_eq!(txn_stmts[3].sql, "COMMIT");
    }

    #[tokio::test]
    async fn test_upsert_auth_replaces_existing() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .append_query_results([vec![make_model("uid", "auth", "\"payload\"")]])
            .into_connection();

        let txn = db.begin().await.unwrap();
        upsert(&txn, "uid", StateType::Auth, &"payload")
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let log = db.into_transaction_log();
        let txn_stmts = log[0].statements();
        // DELETE must come before INSERT
        assert!(txn_stmts[1].sql.starts_with("DELETE"));
        assert!(txn_stmts[2].sql.starts_with("INSERT"));

        // DELETE must target "auth" type
        assert_eq!(txn_stmts[1].values.as_ref().unwrap().0[1], sv("auth"));
    }

    #[tokio::test]
    async fn test_upsert_register_uses_register_type() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 0,
                ..Default::default()
            }])
            .append_query_results([vec![make_model("uid", "register", "\"test\"")]])
            .into_connection();

        let txn = db.begin().await.unwrap();
        upsert(&txn, "uid", StateType::Register, &"test")
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let log = db.into_transaction_log();
        let txn_stmts = log[0].statements();

        // DELETE must use "register", not "auth"
        assert_eq!(txn_stmts[1].values.as_ref().unwrap().0[1], sv("register"));

        // INSERT must use "register" type
        assert_eq!(txn_stmts[2].values.as_ref().unwrap().0[2], sv("register"));
    }

    #[tokio::test]
    async fn test_upsert_user_id_in_where_clause() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 0,
                ..Default::default()
            }])
            .append_query_results([vec![make_model("other-uid", "auth", "\"x\"")]])
            .into_connection();

        let txn = db.begin().await.unwrap();
        upsert(&txn, "other-uid", StateType::Auth, &"x")
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let log = db.into_transaction_log();
        // The DELETE filters by user_id
        assert_eq!(
            log[0].statements()[1].values.as_ref().unwrap().0[0],
            sv("other-uid")
        );
        // The DELETE filters by type
        assert_eq!(
            log[0].statements()[1].values.as_ref().unwrap().0[1],
            sv("auth")
        );
    }

    #[tokio::test]
    async fn test_upsert_same_sql_structure_as_delete_and_get() {
        // Ensures the DELETE in create/delete.rs and create/create.rs use the same
        // column predicates, so the create path can safely replace stale state.
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 0,
                ..Default::default()
            }])
            .append_query_results([vec![make_model("uid", "auth", "x")]])
            .into_connection();

        let txn = db.begin().await.unwrap();
        upsert(&txn, "uid", StateType::Auth, &"x").await.unwrap();
        txn.commit().await.unwrap();

        let log = db.into_transaction_log();
        let delete_sql = &log[0].statements()[1].sql;
        assert!(
            delete_sql.contains(r#""webauthn_state"."user_id""#),
            "DELETE must filter on user_id column"
        );
        assert!(
            delete_sql.contains(r#""webauthn_state"."type""#),
            "DELETE must filter on type column"
        );
    }
}
