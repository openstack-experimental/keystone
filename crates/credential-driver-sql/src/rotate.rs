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
//! `credential_rotate` (ADR 0019 §4).
//!
//! Exposed at the crate root for the same reason as [`crate::migrate`]:
//! this is an offline administrative operation invoked directly against a
//! bare `Config`/`DatabaseConnection`, not through [`crate::SqlBackend`].

use sea_orm::DatabaseConnection;
use sea_orm::PaginatorTrait;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_config::Config;
use openstack_keystone_core::credential::CredentialProviderError;
use openstack_keystone_core::error::DbContextExt;

use crate::entity::{credential as db_credential, prelude::Credential as DbCredential};
use crate::fernet::FernetKeyRepository;

/// Promote the staged key to Primary.
///
/// Refuses to rotate if any credential is still encrypted with a
/// non-primary key: promoting anyway risks that key being pruned by a
/// later rotation (once [`crate::fernet::MAX_ACTIVE_KEYS`] is exceeded)
/// before the credential is ever migrated, permanently stranding it. Run
/// [`crate::migrate::migrate`] first in that case.
///
/// # Concurrency
/// The stale-credential check and the key promotion are two separate
/// steps, not one atomic operation. Running this function concurrently —
/// from two nodes of either service, or from two overlapping invocations
/// of the same service — can let both calls pass the check before either
/// promotes. Operators must serialize calls to this function externally
/// (e.g. a deployment-level lock); this is not enforced in-process.
///
/// # Errors
/// Returns [`CredentialProviderError::Conflict`] if any credential still
/// references a non-primary key. Also returns an error if the key
/// repository can't be loaded or rotated, or a database operation fails.
pub async fn rotate(cfg: &Config, db: &DatabaseConnection) -> Result<(), CredentialProviderError> {
    let repo = FernetKeyRepository::new(cfg.credential.key_repository.clone());
    let keys = repo.load(cfg.credential.insecure_allow_null_key)?;

    let stale = DbCredential::find()
        .filter(db_credential::Column::KeyHash.ne(keys.primary_key_hash.as_str()))
        .count(db)
        .await
        .context("checking for credentials pending migration")?;
    if stale > 0 {
        return Err(CredentialProviderError::Conflict(format!(
            "refusing to rotate: {stale} credential(s) are still encrypted with a non-primary \
             key; run `credential migrate` first"
        )));
    }

    repo.rotate()?;
    Ok(())
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
    async fn test_refuses_when_credentials_are_stale() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;

        let repo = FernetKeyRepository::new(key_dir.path().to_path_buf());
        repo.setup().unwrap();
        let keys = repo.load(false).unwrap();
        let stale_blob = keys.multi_fernet.encrypt(b"stale-secret");
        // Wrong key_hash: never matches the current primary.
        insert_credential(&db, "cred-1", stale_blob, "not-the-primary-hash".into()).await;

        let err = rotate(&cfg, &db).await.unwrap_err();
        assert!(
            err.to_string().contains("credential migrate"),
            "error should direct the operator to migrate first, got: {err}"
        );
        // The repository must be left untouched — no new key promoted.
        assert!(!key_dir.path().join("1").exists());
    }

    #[tokio::test]
    async fn test_succeeds_when_all_credentials_current() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;

        let repo = FernetKeyRepository::new(key_dir.path().to_path_buf());
        repo.setup().unwrap();
        let keys = repo.load(false).unwrap();
        let blob = keys.multi_fernet.encrypt(b"current-secret");
        insert_credential(&db, "cred-1", blob, keys.primary_key_hash.clone()).await;

        rotate(&cfg, &db).await.unwrap();

        assert!(
            key_dir.path().join("1").exists(),
            "staged key must be promoted"
        );
        assert!(
            key_dir.path().join("0").exists(),
            "a fresh key must be staged"
        );
    }
}
