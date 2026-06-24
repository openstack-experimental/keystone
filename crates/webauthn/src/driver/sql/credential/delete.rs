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

use openstack_keystone_core::error::DbContextExt;

use crate::WebauthnError;
use crate::driver::sql::model::{prelude::WebauthnCredential, webauthn_credential};

/// Delete a webauthn credential owned by the given user.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_id`: The owner's user ID.
/// - `credential_id`: The ID of the credential to delete.
///
/// # Returns
/// A `Result` containing `()` on success, or a `WebauthnError`.
pub async fn delete<U: AsRef<str>, C: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
    credential_id: C,
) -> Result<(), WebauthnError> {
    let result = WebauthnCredential::delete_many()
        .filter(webauthn_credential::Column::UserId.eq(user_id.as_ref()))
        .filter(webauthn_credential::Column::CredentialId.eq(credential_id.as_ref()))
        .exec(db)
        .await
        .context("deleting webauthn credential record")?;
    if result.rows_affected == 0 {
        return Err(WebauthnError::CredentialNotFound(
            credential_id.as_ref().into(),
        ));
    }
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

        delete(&db, "uid", "cred_id").await.unwrap();
        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "webauthn_credential" WHERE "webauthn_credential"."user_id" = $1 AND "webauthn_credential"."credential_id" = $2"#,
                ["uid".into(), "cred_id".into()]
            ),]
        );
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 0,
                ..Default::default()
            }])
            .into_connection();

        match delete(&db, "uid", "cred_id").await {
            Err(WebauthnError::CredentialNotFound(id)) => {
                assert_eq!(id, String::from("cred_id"));
            }
            other => {
                panic!(
                    "Delete of non-existent credential must return CredentialNotFound, got {:?}",
                    other
                );
            }
        }
    }
}
