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

use openstack_keystone_core::credential::CredentialProviderError;
use openstack_keystone_core::error::DbContextExt;

use crate::entity::{credential as db_credential, prelude::Credential as DbCredential};

/// Delete a credential by ID.
pub async fn delete(db: &DatabaseConnection, id: &str) -> Result<(), CredentialProviderError> {
    DbCredential::delete_many()
        .filter(db_credential::Column::Id.eq(id))
        .exec(db)
        .await
        .context("deleting credential")?;
    Ok(())
}

/// Delete all credentials owned by a user (identity lifecycle cascade).
pub async fn delete_for_user(
    db: &DatabaseConnection,
    user_id: &str,
) -> Result<(), CredentialProviderError> {
    DbCredential::delete_many()
        .filter(db_credential::Column::UserId.eq(user_id))
        .exec(db)
        .await
        .context("deleting credentials for user")?;
    Ok(())
}

/// Delete all credentials bound to a project (identity lifecycle cascade;
/// primarily EC2 credentials).
pub async fn delete_for_project(
    db: &DatabaseConnection,
    project_id: &str,
) -> Result<(), CredentialProviderError> {
    DbCredential::delete_many()
        .filter(db_credential::Column::ProjectId.eq(project_id))
        .exec(db)
        .await
        .context("deleting credentials for project")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::DatabaseConnection;
    use sea_orm::entity::*;

    use crate::test_support::create_credential_table;

    use super::*;

    async fn test_db() -> DatabaseConnection {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        create_credential_table(&db).await.unwrap();
        db
    }

    async fn insert_credential(
        db: &DatabaseConnection,
        id: &str,
        user_id: &str,
        project_id: Option<&str>,
    ) {
        db_credential::ActiveModel {
            id: Set(id.to_string()),
            user_id: Set(user_id.to_string()),
            project_id: Set(project_id.map(str::to_string)),
            encrypted_blob: Set(String::new()),
            r#type: Set("totp".to_string()),
            key_hash: Set("hash".to_string()),
            extra: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
    }

    async fn remaining_ids(db: &DatabaseConnection) -> Vec<String> {
        DbCredential::find()
            .all(db)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.id)
            .collect()
    }

    #[tokio::test]
    async fn test_delete_removes_only_matching_id() {
        let db = test_db().await;
        insert_credential(&db, "cred-1", "user-1", None).await;
        insert_credential(&db, "cred-2", "user-1", None).await;

        delete(&db, "cred-1").await.unwrap();

        assert_eq!(remaining_ids(&db).await, vec!["cred-2".to_string()]);
    }

    #[tokio::test]
    async fn test_delete_for_user_removes_only_owned_credentials() {
        let db = test_db().await;
        insert_credential(&db, "cred-1", "user-1", None).await;
        insert_credential(&db, "cred-2", "user-2", None).await;

        delete_for_user(&db, "user-1").await.unwrap();

        assert_eq!(remaining_ids(&db).await, vec!["cred-2".to_string()]);
    }

    #[tokio::test]
    async fn test_delete_for_project_removes_only_bound_credentials() {
        let db = test_db().await;
        insert_credential(&db, "cred-1", "user-1", Some("project-a")).await;
        insert_credential(&db, "cred-2", "user-1", Some("project-b")).await;

        delete_for_project(&db, "project-a").await.unwrap();

        assert_eq!(remaining_ids(&db).await, vec!["cred-2".to_string()]);
    }
}
