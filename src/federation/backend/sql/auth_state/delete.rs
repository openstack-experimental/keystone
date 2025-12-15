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
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use crate::db::entity::{
    federated_auth_state as db_federated_auth_state,
    prelude::FederatedAuthState as DbFederatedAuthState,
};
use crate::federation::backend::error::{FederationDatabaseError, db_err};

pub async fn delete<S: AsRef<str>>(
    db: &DatabaseConnection,
    id: S,
) -> Result<(), FederationDatabaseError> {
    let res = DbFederatedAuthState::delete_by_id(id.as_ref())
        .exec(db)
        .await
        .map_err(|err| db_err(err, "deleting federation login auth_state"))?;
    if res.rows_affected == 1 {
        Ok(())
    } else {
        Err(FederationDatabaseError::AuthStateNotFound(
            id.as_ref().to_string(),
        ))
    }
}

pub async fn delete_expired(db: &DatabaseConnection) -> Result<(), FederationDatabaseError> {
    DbFederatedAuthState::delete_many()
        .filter(db_federated_auth_state::Column::ExpiresAt.lt(Utc::now()))
        .exec(db)
        .await
        .map_err(|err| db_err(err, "deleting expired federation login auth_states"))?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_delete() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        delete(&db, "state").await.unwrap();
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "federated_auth_state" WHERE "federated_auth_state"."state" = $1"#,
                ["state".into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_delete_expired() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        delete_expired(&db).await.unwrap();
        for (l,r) in db.into_transaction_log().iter().zip([Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "federated_auth_state" WHERE "federated_auth_state"."expires_at" < $1"#,
                []
            ),]) {
            assert_eq!(
                l.statements().iter().map(|x| x.sql.clone()).collect::<Vec<_>>(),
                r.statements().iter().map(|x| x.sql.clone()).collect::<Vec<_>>()
            );
        }
    }
}
