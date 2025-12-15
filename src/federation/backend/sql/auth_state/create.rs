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

use crate::db::entity::federated_auth_state as db_federated_auth_state;
use crate::federation::backend::error::{FederationDatabaseError, db_err};
use crate::federation::types::*;

pub async fn create(
    db: &DatabaseConnection,
    rec: AuthState,
) -> Result<AuthState, FederationDatabaseError> {
    let scope: Option<serde_json::Value> = if let Some(scope) = rec.scope {
        Some(serde_json::to_value(&scope)?)
    } else {
        None
    };
    let entry = db_federated_auth_state::ActiveModel {
        state: Set(rec.state.clone()),
        idp_id: Set(rec.idp_id.clone()),
        mapping_id: Set(rec.mapping_id.clone()),
        nonce: Set(rec.nonce.clone()),
        redirect_uri: Set(rec.redirect_uri.clone()),
        pkce_verifier: Set(rec.pkce_verifier.clone()),
        expires_at: Set(rec.expires_at.naive_utc()),
        requested_scope: scope.map(Set).unwrap_or(NotSet).into(),
    };

    let db_entry: db_federated_auth_state::Model = entry
        .insert(db)
        .await
        .map_err(|err| db_err(err, "persisting federation login auth_state"))?;

    db_entry.try_into()
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, NaiveDateTime, Utc};
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_auth_state_mock;
    use super::*;

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_auth_state_mock("state")]])
            .into_connection();

        let req = AuthState {
            idp_id: "idp".into(),
            mapping_id: "mapping".into(),
            state: "state".into(),
            nonce: "nonce".into(),
            redirect_uri: "redirect_uri".into(),
            pkce_verifier: "pkce_verifier".into(),
            expires_at: DateTime::<Utc>::default(),
            scope: None,
        };

        assert_eq!(
            create(&db, req).await.unwrap(),
            get_auth_state_mock("state").try_into().unwrap()
        );
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "federated_auth_state" ("idp_id", "mapping_id", "state", "nonce", "redirect_uri", "pkce_verifier", "expires_at") VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING "idp_id", "mapping_id", "state", "nonce", "redirect_uri", "pkce_verifier", "expires_at", "requested_scope""#,
                [
                    "idp".into(),
                    "mapping".into(),
                    "state".into(),
                    "nonce".into(),
                    "redirect_uri".into(),
                    "pkce_verifier".into(),
                    NaiveDateTime::default().into(),
                ]
            ),]
        );
    }
}
