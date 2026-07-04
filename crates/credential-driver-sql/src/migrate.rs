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
//! `credential_migrate` (ADR 0019 §4).
//!
//! Exposed at the crate root (rather than nested under the private
//! `credential` module used by [`crate::SqlBackend`]) because this is an
//! offline administrative operation with no [`ServiceState`][state] —
//! `keystone-manage` calls it directly against a bare `Config` and
//! `DatabaseConnection`, the same way it already uses [`crate::fernet`] and
//! [`crate::entity`].
//!
//! [state]: openstack_keystone_core::keystone::ServiceState

use sea_orm::DatabaseConnection;
use sea_orm::TransactionTrait;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_config::Config;
use openstack_keystone_core::credential::CredentialProviderError;
use openstack_keystone_core::error::DbContextExt;

use crate::entity::{credential as db_credential, prelude::Credential as DbCredential};
use crate::fernet::FernetKeyRepository;

/// Re-encrypt all credentials still using a non-primary key with the
/// current Primary Key.
///
/// Runs in batches of `batch_size` rows, committing a transaction between
/// batches to bound transaction size on large tables. Safe to run
/// concurrently with active auth traffic: reads are unaffected, and a row
/// that has already been migrated simply stops matching the filter and is
/// skipped on the next pass.
///
/// # Errors
/// Returns [`CredentialProviderError`] if `batch_size` is zero, the key
/// repository can't be loaded, a row can't be decrypted with any active
/// key, or a database operation fails.
pub async fn migrate(
    cfg: &Config,
    db: &DatabaseConnection,
    batch_size: u64,
) -> Result<u64, CredentialProviderError> {
    if batch_size == 0 {
        return Err(CredentialProviderError::Driver(
            "batch_size must be greater than zero".to_string(),
        ));
    }

    let repo = FernetKeyRepository::new(cfg.credential.key_repository.clone());
    let keys = repo.load(cfg.credential.insecure_allow_null_key).await?;

    let mut total = 0u64;
    loop {
        let batch = DbCredential::find()
            .filter(db_credential::Column::KeyHash.ne(keys.primary_key_hash.as_str()))
            .limit(batch_size)
            .all(db)
            .await
            .context("fetching credentials pending migration")?;
        if batch.is_empty() {
            break;
        }
        let batch_len = batch.len() as u64;

        let txn = db
            .begin()
            .await
            .context("starting credential_migrate batch transaction")?;
        for model in batch {
            let id = model.id.clone();
            let plaintext = keys
                .multi_fernet
                .decrypt(&model.encrypted_blob)
                .map_err(|_| {
                    CredentialProviderError::Encryption(format!(
                        "failed to decrypt credential {id} with any active key; migration aborted"
                    ))
                })?;
            let re_encrypted = keys.multi_fernet.encrypt(&plaintext);

            let mut active: db_credential::ActiveModel = model.into();
            active.encrypted_blob = Set(re_encrypted);
            active.key_hash = Set(keys.primary_key_hash.clone());
            active
                .update(&txn)
                .await
                .context("updating credential during migration")?;
        }
        txn.commit()
            .await
            .context("committing credential_migrate batch")?;

        total += batch_len;
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use sea_orm::DatabaseConnection;

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

    async fn insert_credential(
        db: &DatabaseConnection,
        id: &str,
        encrypted_blob: String,
        key_hash: String,
    ) {
        db_credential::ActiveModel {
            id: Set(id.to_string()),
            user_id: Set("user-1".to_string()),
            project_id: Set(None),
            encrypted_blob: Set(encrypted_blob),
            r#type: Set("totp".to_string()),
            key_hash: Set(key_hash),
            extra: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_rejects_zero_batch_size() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;

        let err = migrate(&cfg, &db, 0).await.unwrap_err();
        assert!(matches!(err, CredentialProviderError::Driver(_)));
    }

    #[tokio::test]
    async fn test_reencrypts_stale_credentials() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;

        let repo = FernetKeyRepository::new(key_dir.path().to_path_buf());
        repo.setup().await.unwrap();
        // First rotation: original key becomes primary (renamed 0 -> 1); a
        // fresh key is staged as the new 0.
        repo.rotate().await.unwrap();
        let keys_after_first_rotate = repo.load(false).await.unwrap();
        let old_primary_hash = keys_after_first_rotate.primary_key_hash.clone();
        let blob = keys_after_first_rotate
            .multi_fernet
            .encrypt(b"needs-migration");
        insert_credential(&db, "cred-1", blob.clone(), old_primary_hash.clone()).await;

        // Second rotation: the credential above is now stale relative to
        // the new primary, but its encrypting key is still active (within
        // MAX_ACTIVE_KEYS) so it remains decryptable.
        repo.rotate().await.unwrap();
        let keys_after_second_rotate = repo.load(false).await.unwrap();
        assert_ne!(
            old_primary_hash, keys_after_second_rotate.primary_key_hash,
            "test setup sanity: the credential must actually be stale"
        );

        let migrated_count = migrate(&cfg, &db, 10).await.unwrap();
        assert_eq!(migrated_count, 1);

        let migrated = db_credential::Entity::find_by_id("cred-1")
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(migrated.key_hash, keys_after_second_rotate.primary_key_hash);
        assert_eq!(
            keys_after_second_rotate
                .multi_fernet
                .decrypt(&migrated.encrypted_blob)
                .unwrap(),
            b"needs-migration"
        );
        // The plaintext blob is unaffected by re-encryption.
        assert_ne!(migrated.encrypted_blob, blob);
    }

    #[tokio::test]
    async fn test_is_noop_when_nothing_is_stale() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;

        let repo = FernetKeyRepository::new(key_dir.path().to_path_buf());
        repo.setup().await.unwrap();
        let keys = repo.load(false).await.unwrap();
        let blob = keys.multi_fernet.encrypt(b"already-current");
        insert_credential(&db, "cred-1", blob.clone(), keys.primary_key_hash.clone()).await;

        let migrated_count = migrate(&cfg, &db, 10).await.unwrap();
        assert_eq!(migrated_count, 0);

        let unchanged = db_credential::Entity::find_by_id("cred-1")
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.encrypted_blob, blob);
        assert_eq!(unchanged.key_hash, keys.primary_key_hash);
    }
}
