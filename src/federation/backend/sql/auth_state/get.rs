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
    federated_auth_state as db_federated_auth_state,
    prelude::FederatedAuthState as DbFederatedAuthState,
};
use crate::federation::backend::error::{FederationDatabaseError, db_err};
use crate::federation::types::*;

pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    state: I,
) -> Result<Option<AuthState>, FederationDatabaseError> {
    let select = DbFederatedAuthState::find_by_id(state.as_ref());

    let entry: Option<db_federated_auth_state::Model> = select
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching federation login auth_state by id"))?;
    entry.map(TryInto::try_into).transpose()
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_auth_state_mock;
    use super::*;

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_auth_state_mock("state")]])
            .into_connection();
        assert_eq!(
            get(&db, "state").await.unwrap().unwrap(),
            AuthState {
                idp_id: "idp".into(),
                mapping_id: "mapping".into(),
                state: "state".into(),
                nonce: "nonce".into(),
                redirect_uri: "redirect_uri".into(),
                pkce_verifier: "pkce_verifier".into(),
                expires_at: DateTime::<Utc>::default(),
                scope: None,
            }
        );

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "federated_auth_state"."idp_id", "federated_auth_state"."mapping_id", "federated_auth_state"."state", "federated_auth_state"."nonce", "federated_auth_state"."redirect_uri", "federated_auth_state"."pkce_verifier", "federated_auth_state"."expires_at", "federated_auth_state"."requested_scope" FROM "federated_auth_state" WHERE "federated_auth_state"."state" = $1 LIMIT $2"#,
                ["state".into(), 1u64.into()]
            ),]
        );
    }
}
