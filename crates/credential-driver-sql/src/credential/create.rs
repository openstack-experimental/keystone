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

use sea_orm::ActiveValue::Set;
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_config::Config;
use openstack_keystone_core::credential::CredentialProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::credential::*;

use crate::entity::credential as db_credential;
use crate::fernet::FernetKeyRepository;

/// Create a new credential row, encrypting `rec.blob` with the current
/// Primary Key.
///
/// `rec.id` and `rec.user_id` must already be resolved by the caller (the
/// core `CredentialService` computes the EC2/UUID id and defaults
/// `user_id` before calling the backend — ADR 0019 §1, §2).
pub async fn create(
    cfg: &Config,
    db: &DatabaseConnection,
    rec: CredentialCreate,
) -> Result<Credential, CredentialProviderError> {
    let id = rec
        .id
        .clone()
        .ok_or_else(|| CredentialProviderError::Driver("credential id not set".into()))?;
    let user_id = rec
        .user_id
        .clone()
        .ok_or(CredentialProviderError::MissingUserId)?;

    let repo = FernetKeyRepository::new(cfg.credential.key_repository.clone());
    let keys = repo.load(cfg.credential.insecure_allow_null_key).await?;
    let encrypted_blob = keys.multi_fernet.encrypt(rec.blob.as_bytes());

    let extra = rec.extra.as_ref().map(serde_json::to_string).transpose()?;

    let model = db_credential::ActiveModel {
        id: Set(id.clone()),
        user_id: Set(user_id.clone()),
        project_id: Set(rec.project_id.clone()),
        encrypted_blob: Set(encrypted_blob),
        r#type: Set(rec.r#type.clone()),
        key_hash: Set(keys.primary_key_hash),
        extra: Set(extra),
    };
    model.insert(db).await.context("creating credential")?;

    Ok(Credential {
        id,
        user_id,
        project_id: rec.project_id,
        blob: rec.blob,
        r#type: rec.r#type,
        extra: rec.extra,
    })
}

#[cfg(test)]
mod tests {
    use sea_orm::DatabaseConnection;

    use openstack_keystone_core::credential::CredentialProviderError;

    use crate::credential::get::get;
    use crate::test_support::create_credential_table;

    use super::*;

    fn test_config(key_repo: &std::path::Path) -> Config {
        let mut cfg = Config::default();
        cfg.credential.key_repository = key_repo.to_path_buf();
        cfg
    }

    async fn test_db() -> DatabaseConnection {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        create_credential_table(&db).await.unwrap();
        db
    }

    #[tokio::test]
    async fn test_create_persists_encrypted_and_returns_plaintext() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;
        crate::fernet::FernetKeyRepository::new(key_dir.path().to_path_buf())
            .setup()
            .await
            .unwrap();

        let rec = CredentialCreate {
            id: Some("cred-1".into()),
            user_id: Some("user-1".into()),
            project_id: Some("project-1".into()),
            blob: "secret-blob".into(),
            r#type: "totp".into(),
            extra: None,
        };

        let created = create(&cfg, &db, rec).await.unwrap();
        assert_eq!(created.id, "cred-1");
        assert_eq!(created.blob, "secret-blob");

        // The row on disk must be encrypted, not plaintext.
        let stored = crate::entity::prelude::Credential::find_by_id("cred-1".to_string())
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(stored.encrypted_blob, "secret-blob");

        // Round-trips back to plaintext through get().
        let fetched = get(&cfg, &db, "cred-1").await.unwrap().unwrap();
        assert_eq!(fetched.blob, "secret-blob");
    }

    #[tokio::test]
    async fn test_create_missing_id_errors() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;

        let rec = CredentialCreate {
            id: None,
            user_id: Some("user-1".into()),
            project_id: None,
            blob: "secret-blob".into(),
            r#type: "totp".into(),
            extra: None,
        };

        let err = create(&cfg, &db, rec).await.unwrap_err();
        assert!(matches!(err, CredentialProviderError::Driver(_)));
    }

    #[tokio::test]
    async fn test_create_missing_user_id_errors() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;

        let rec = CredentialCreate {
            id: Some("cred-1".into()),
            user_id: None,
            project_id: None,
            blob: "secret-blob".into(),
            r#type: "totp".into(),
            extra: None,
        };

        let err = create(&cfg, &db, rec).await.unwrap_err();
        assert!(matches!(err, CredentialProviderError::MissingUserId));
    }
}
