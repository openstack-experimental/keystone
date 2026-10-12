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
    access_rule as db_access_rule, application_credential as db_application_credential,
    prelude::{AccessRule as DbAccessRule, ApplicationCredential as DbApplicationCredential},
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
    if res.rows_affected == 1 {
        Ok(())
    } else {
        Err(ApplicationCredentialProviderError::ApplicationCredentialNotFound(id.to_string()))
    }
}
/// Delete all application credentials and access rules owned by a user
/// (identity lifecycle cascade).
///
/// The credentials go first: an access rule still attached to one could not
/// be removed. The role and access-rule association rows follow their
/// credential through the foreign keys.
pub async fn delete_for_user(
    db: &DatabaseConnection,
    user_id: &str,
) -> Result<(), ApplicationCredentialProviderError> {
    DbApplicationCredential::delete_many()
        .filter(db_application_credential::Column::UserId.eq(user_id))
        .exec(db)
        .await
        .context("deleting application credentials for user")?;
    DbAccessRule::delete_many()
        .filter(db_access_rule::Column::UserId.eq(user_id))
        .exec(db)
        .await
        .context("deleting access rules for user")?;
    Ok(())
}

/// Delete all application credentials scoped to a project (resource
/// lifecycle cascade). The role and access-rule association rows follow their
/// credential through the foreign keys; the access rules themselves belong to
/// users and stay.
pub async fn delete_for_project(
    db: &DatabaseConnection,
    project_id: &str,
) -> Result<(), ApplicationCredentialProviderError> {
    DbApplicationCredential::delete_many()
        .filter(db_application_credential::Column::ProjectId.eq(project_id))
        .exec(db)
        .await
        .context("deleting application credentials for project")?;
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
                last_insert_id: 0,
                rows_affected: 1,
            }])
            .into_connection();

        delete(&db, "app_cred_id").await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "application_credential" WHERE "application_credential"."id" = $1"#,
                ["app_cred_id".into()]
            )]
        );
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 0,
            }])
            .into_connection();

        let result = delete(&db, "non-existing-id").await;

        assert!(matches!(
            result,
            Err(ApplicationCredentialProviderError::ApplicationCredentialNotFound(_))
        ));
    }

    #[tokio::test]
    async fn test_delete_for_project() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                last_insert_id: 0,
                rows_affected: 2,
            }])
            .into_connection();

        delete_for_project(&db, "project_id").await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "application_credential" WHERE "application_credential"."project_id" = $1"#,
                ["project_id".into()]
            )]
        );
    }

    #[tokio::test]
    async fn test_delete_for_user() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([
                MockExecResult {
                    last_insert_id: 0,
                    rows_affected: 2,
                },
                MockExecResult {
                    last_insert_id: 0,
                    rows_affected: 1,
                },
            ])
            .into_connection();

        delete_for_user(&db, "user_id").await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "application_credential" WHERE "application_credential"."user_id" = $1"#,
                    ["user_id".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"DELETE FROM "access_rule" WHERE "access_rule"."user_id" = $1"#,
                    ["user_id".into()]
                ),
            ]
        );
    }
}
