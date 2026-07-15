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
//! # Delete application credential
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::application_credential::ApplicationCredentialProviderError;
use openstack_keystone_core::error::DbContextExt;

use crate::entity::{
    application_credential as db_application_credential,
    prelude::ApplicationCredential as DbApplicationCredential,
};

pub async fn delete(
    db: &DatabaseConnection,
    id: &str,
) -> Result<(), ApplicationCredentialProviderError> {
    let res = DbApplicationCredential::delete_many()
        .filter(db_application_credential::Column::Id.eq(id))
        .exec(db)
        .await
        .context("deleting application credential")?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::super::tests::*;
    use super::*;

    #[tokio::test]
    async fn test_delete() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_application_credential_mock(
                "app_cred_id",
                Some(12345),
            )]])
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 1,
            }])
            .into_connection();

        delete(&db, "app_cred_id").await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "application_credential"."internal_id", "application_credential"."id", "application_credential"."name", "application_credential"."secret_hash", "application_credential"."description", "application_credential"."user_id", "application_credential"."project_id", "application_credential"."expires_at", "application_credential"."system", "application_credential"."unrestricted" FROM "application_credential" WHERE "application_credential"."id" = $1 LIMIT $2"#,
                    ["app_cred_id".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "application_credential" WHERE "application_credential"."internal_id" = $1"#,
                    [12345i32.into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<crate::entity::application_credential::Model>::new()])
            .into_connection();

        let result = delete(&db, "non-existing-id").await;

        assert!(matches!(
            result,
            Err(ApplicationCredentialProviderError::ApplicationCredentialNotFound(_))
        ));
    }
}
