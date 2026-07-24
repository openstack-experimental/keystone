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
use sea_orm::query::*;

use openstack_keystone_config::Config;
use openstack_keystone_core::credential::CredentialProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::credential::*;

use crate::credential::get::to_plaintext;
use crate::entity::{credential as db_credential, prelude::Credential as DbCredential};
use crate::fernet::FernetKeyRepository;

/// Update a credential. Updating `blob` re-encrypts it with the current
/// Primary Key and updates `key_hash` (ADR 0019 §2, Update).
pub async fn update(
    cfg: &Config,
    db: &DatabaseConnection,
    id: &str,
    rec: CredentialUpdate,
) -> Result<Credential, CredentialProviderError> {
    let model = DbCredential::find()
        .filter(db_credential::Column::Id.eq(id))
        .one(db)
        .await
        .context("fetching credential for update")?
        .ok_or_else(|| CredentialProviderError::CredentialNotFound(id.to_string()))?;

    let mut active: db_credential::ActiveModel = model.into();

    if let Some(new_type) = rec.r#type {
        active.r#type = Set(new_type);
    }
    if let Some(new_project_id) = rec.project_id {
        active.project_id = Set(Some(new_project_id));
    }
    if let Some(new_blob) = rec.blob {
        let repo = FernetKeyRepository::new(cfg.credential.key_repository.clone());
        let keys = repo.load(cfg.credential.insecure_allow_null_key).await?;
        active.encrypted_blob = Set(keys.multi_fernet.encrypt(new_blob.as_bytes()));
        active.key_hash = Set(keys.primary_key_hash);
    }

    let updated = active.update(db).await.context("updating credential")?;

    to_plaintext(cfg, updated).await
}

#[cfg(test)]
mod tests {
    use sea_orm::DatabaseConnection;

    use openstack_keystone_core::credential::CredentialProviderError;

    use crate::fernet::FernetKeyRepository;
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

    async fn insert_credential(cfg: &Config, db: &DatabaseConnection, id: &str, plaintext: &[u8]) {
        let repo = FernetKeyRepository::new(cfg.credential.key_repository.clone());
        let keys = repo.load(false).await.unwrap();
        db_credential::ActiveModel {
            id: Set(id.to_string()),
            user_id: Set("user-1".to_string()),
            project_id: Set(None),
            encrypted_blob: Set(keys.multi_fernet.encrypt(plaintext)),
            r#type: Set("totp".to_string()),
            key_hash: Set(keys.primary_key_hash),
            extra: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;
        FernetKeyRepository::new(key_dir.path().to_path_buf())
            .setup()
            .await
            .unwrap();

        let err = update(&cfg, &db, "missing", CredentialUpdate::default())
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialProviderError::CredentialNotFound(id) if id == "missing"));
    }

    #[tokio::test]
    async fn test_update_type_only_leaves_blob_and_key_hash_unchanged() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;
        FernetKeyRepository::new(key_dir.path().to_path_buf())
            .setup()
            .await
            .unwrap();
        insert_credential(&cfg, &db, "cred-1", b"original-secret").await;

        let rec = CredentialUpdate {
            blob: None,
            project_id: None,
            r#type: Some("ec2".into()),
        };
        let updated = update(&cfg, &db, "cred-1", rec).await.unwrap();
        assert_eq!(updated.r#type, "ec2");
        assert_eq!(updated.blob, "original-secret");
    }

    #[tokio::test]
    async fn test_update_project_id() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;
        FernetKeyRepository::new(key_dir.path().to_path_buf())
            .setup()
            .await
            .unwrap();
        insert_credential(&cfg, &db, "cred-1", b"original-secret").await;

        let rec = CredentialUpdate {
            blob: None,
            project_id: Some("new-project".into()),
            r#type: None,
        };
        let updated = update(&cfg, &db, "cred-1", rec).await.unwrap();
        assert_eq!(updated.project_id.as_deref(), Some("new-project"));
        assert_eq!(updated.blob, "original-secret");
    }

    #[tokio::test]
    async fn test_update_blob_reencrypts_with_current_primary_key() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;
        FernetKeyRepository::new(key_dir.path().to_path_buf())
            .setup()
            .await
            .unwrap();
        insert_credential(&cfg, &db, "cred-1", b"original-secret").await;

        let rec = CredentialUpdate {
            blob: Some("new-secret".into()),
            project_id: None,
            r#type: None,
        };
        let updated = update(&cfg, &db, "cred-1", rec).await.unwrap();
        assert_eq!(updated.blob, "new-secret");

        let repo = FernetKeyRepository::new(cfg.credential.key_repository.clone());
        let keys = repo.load(false).await.unwrap();
        let stored = DbCredential::find_by_id("cred-1".to_string())
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.key_hash, keys.primary_key_hash);
    }
}
