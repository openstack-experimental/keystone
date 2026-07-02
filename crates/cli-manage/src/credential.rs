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
//! Credential encryption key management commands (ADR 0019 §4).
//!
//! **These commands must not be run simultaneously from both the Python and
//! Rust services against the same database.** `credential_rotate` performs a
//! safety check followed by a key promotion in two steps; concurrent
//! execution from two nodes can race between the check and the promote.
//! Operational runbooks must treat these commands as mutually exclusive
//! across services.

use std::io;

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use color_eyre::{Report, eyre::WrapErr, eyre::eyre};
use eyre::Result;
use sea_orm::ConnectOptions;
use sea_orm::Database;
use sea_orm::DatabaseConnection;
use sea_orm::PaginatorTrait;
use sea_orm::TransactionTrait;
use sea_orm::entity::*;
use sea_orm::query::*;
use secrecy::ExposeSecret;
use tracing::info;
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    prelude::*,
};

use openstack_keystone_config::Config;
use openstack_keystone_credential_driver_sql::entity::{
    credential as db_credential, prelude::Credential as DbCredential,
};
use openstack_keystone_credential_driver_sql::fernet::FernetKeyRepository;

use crate::PerformAction;

/// Number of credentials re-encrypted per transaction during
/// `credential_migrate`, matching the Python Keystone default (ADR 0019 §4).
const DEFAULT_MIGRATE_BATCH_SIZE: u64 = 1000;

/// Credential encryption key management.
#[derive(Parser)]
pub struct CredentialCommand {
    /// Verbosity level. Repeat to increase level.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: CredentialCommands,
}

#[derive(Subcommand)]
enum CredentialCommands {
    /// Populate the credential key repository with an initial staged key.
    ///
    /// Must be run once during deployment, before any credentials are
    /// created via either service.
    Setup,

    /// Re-encrypt credentials still using a non-primary key with the current
    /// Primary Key.
    ///
    /// Safe to run concurrently with active auth — reads are unaffected,
    /// writes are idempotent. Runs in batches (`COMMIT` between batches) to
    /// bound transaction size.
    Migrate {
        /// Number of credentials to re-encrypt per transaction.
        #[arg(long, default_value_t = DEFAULT_MIGRATE_BATCH_SIZE)]
        batch_size: u64,
    },

    /// Promote the staged key to Primary.
    ///
    /// Aborts if any credential is still encrypted with a non-primary key —
    /// run `credential migrate` first to avoid making those credentials
    /// indecipherable.
    Rotate,
}

fn setup_logging(verbose: u8) {
    let filter = Targets::new().with_default(match verbose {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    });

    let log_layer = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .with_filter(filter);

    let _ = tracing::subscriber::set_global_default(tracing_subscriber::registry().with(log_layer));
}

async fn connect_db(config: &Config) -> Result<DatabaseConnection> {
    let secret = config.database.get_connection();
    let conn_url = secret.expose_secret().to_string();

    let opt = ConnectOptions::new(conn_url).sqlx_logging(false).to_owned();

    Database::connect(opt)
        .await
        .wrap_err("Database connection failed")
}

#[async_trait]
impl PerformAction for CredentialCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        setup_logging(self.verbose);
        let repo = FernetKeyRepository::new(config.credential.key_repository.clone());

        match self.command {
            CredentialCommands::Setup => {
                repo.setup()
                    .wrap_err("setting up credential key repository")?;
                println!(
                    "credential key repository initialized at {}",
                    config.credential.key_repository.display()
                );
                Ok(())
            }

            CredentialCommands::Migrate { batch_size } => {
                let db = connect_db(config).await?;
                let keys = repo
                    .load(config.credential.insecure_allow_null_key)
                    .wrap_err("loading credential key repository")?;

                let mut total = 0u64;
                loop {
                    let batch = DbCredential::find()
                        .filter(db_credential::Column::KeyHash.ne(keys.primary_key_hash.clone()))
                        .limit(batch_size)
                        .all(&db)
                        .await
                        .wrap_err("fetching credentials pending migration")?;
                    if batch.is_empty() {
                        break;
                    }
                    let batch_len = batch.len() as u64;

                    let txn = db
                        .begin()
                        .await
                        .wrap_err("starting credential_migrate batch transaction")?;
                    for model in batch {
                        let id = model.id.clone();
                        let plaintext =
                            keys.multi_fernet
                                .decrypt(&model.encrypted_blob)
                                .map_err(|_| {
                                    eyre!(
                                        "failed to decrypt credential {id} with any active key; \
                                     migration aborted"
                                    )
                                })?;
                        let re_encrypted = keys.multi_fernet.encrypt(&plaintext);

                        let mut active: db_credential::ActiveModel = model.into();
                        active.encrypted_blob = Set(re_encrypted);
                        active.key_hash = Set(keys.primary_key_hash.clone());
                        active
                            .update(&txn)
                            .await
                            .wrap_err_with(|| format!("updating credential {id}"))?;
                    }
                    txn.commit()
                        .await
                        .wrap_err("committing credential_migrate batch")?;

                    total += batch_len;
                    info!(migrated = total, "credential_migrate progress");
                }

                println!(
                    "credential_migrate complete: {total} credential(s) re-encrypted with the \
                     current primary key"
                );
                Ok(())
            }

            CredentialCommands::Rotate => {
                let db = connect_db(config).await?;
                let keys = repo
                    .load(config.credential.insecure_allow_null_key)
                    .wrap_err("loading credential key repository")?;

                let stale = DbCredential::find()
                    .filter(db_credential::Column::KeyHash.ne(keys.primary_key_hash.clone()))
                    .count(&db)
                    .await
                    .wrap_err("checking for credentials pending migration")?;
                if stale > 0 {
                    return Err(eyre!(
                        "refusing to rotate: {stale} credential(s) are still encrypted with a \
                         non-primary key; run `keystone-manage credential migrate` first"
                    ));
                }

                repo.rotate()
                    .wrap_err("rotating credential key repository")?;
                println!("credential key repository rotated");
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use openstack_keystone_credential_driver_sql::test_support::create_credential_table;

    use super::*;

    /// Build a `Config` pointing at a fresh temp-file sqlite DB and the
    /// given key repository directory.
    fn test_config(db_path: &std::path::Path, key_repo: &std::path::Path) -> Config {
        let mut cfg = Config::default();
        cfg.database.connection =
            SecretString::from(format!("sqlite://{}?mode=rwc", db_path.display()));
        cfg.credential.key_repository = key_repo.to_path_buf();
        cfg
    }

    async fn setup_test_db(cfg: &Config) -> DatabaseConnection {
        let conn = connect_db(cfg).await.unwrap();
        create_credential_table(&conn).await.unwrap();
        conn
    }

    fn command(command: CredentialCommands) -> CredentialCommand {
        CredentialCommand {
            verbose: 0,
            command,
        }
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
    async fn test_setup_creates_staged_key() {
        let key_dir = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(&db_dir.path().join("ks.db"), key_dir.path());

        command(CredentialCommands::Setup)
            .take_action(&cfg)
            .await
            .unwrap();

        assert!(key_dir.path().join("0").exists());
    }

    #[tokio::test]
    async fn test_rotate_refuses_when_credentials_are_stale() {
        let key_dir = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(&db_dir.path().join("ks.db"), key_dir.path());
        let db = setup_test_db(&cfg).await;

        let repo = FernetKeyRepository::new(key_dir.path().to_path_buf());
        repo.setup().unwrap();
        let keys = repo.load(false).unwrap();
        let stale_blob = keys.multi_fernet.encrypt(b"stale-secret");
        // Wrong key_hash: never matches the current primary.
        insert_credential(&db, "cred-1", stale_blob, "not-the-primary-hash".into()).await;

        let err = command(CredentialCommands::Rotate)
            .take_action(&cfg)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("credential migrate"),
            "error should direct the operator to migrate first, got: {err}"
        );
        // The repository must be left untouched — no new key promoted.
        assert!(!key_dir.path().join("1").exists());
    }

    #[tokio::test]
    async fn test_rotate_succeeds_when_all_credentials_current() {
        let key_dir = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(&db_dir.path().join("ks.db"), key_dir.path());
        let db = setup_test_db(&cfg).await;

        let repo = FernetKeyRepository::new(key_dir.path().to_path_buf());
        repo.setup().unwrap();
        let keys = repo.load(false).unwrap();
        let blob = keys.multi_fernet.encrypt(b"current-secret");
        insert_credential(&db, "cred-1", blob, keys.primary_key_hash.clone()).await;

        command(CredentialCommands::Rotate)
            .take_action(&cfg)
            .await
            .unwrap();

        assert!(
            key_dir.path().join("1").exists(),
            "staged key must be promoted"
        );
        assert!(
            key_dir.path().join("0").exists(),
            "a fresh key must be staged"
        );
    }

    #[tokio::test]
    async fn test_migrate_reencrypts_stale_credentials() {
        let key_dir = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(&db_dir.path().join("ks.db"), key_dir.path());
        let db = setup_test_db(&cfg).await;

        let repo = FernetKeyRepository::new(key_dir.path().to_path_buf());
        repo.setup().unwrap();
        // First rotation: original key becomes primary (renamed 0 -> 1); a
        // fresh key is staged as the new 0.
        repo.rotate().unwrap();
        let keys_after_first_rotate = repo.load(false).unwrap();
        let old_primary_hash = keys_after_first_rotate.primary_key_hash.clone();
        let blob = keys_after_first_rotate
            .multi_fernet
            .encrypt(b"needs-migration");
        insert_credential(&db, "cred-1", blob.clone(), old_primary_hash.clone()).await;

        // Second rotation: the credential above is now stale relative to
        // the new primary, but its encrypting key is still active (within
        // MAX_ACTIVE_KEYS) so it remains decryptable.
        repo.rotate().unwrap();
        let keys_after_second_rotate = repo.load(false).unwrap();
        assert_ne!(
            old_primary_hash, keys_after_second_rotate.primary_key_hash,
            "test setup sanity: the credential must actually be stale"
        );

        command(CredentialCommands::Migrate { batch_size: 10 })
            .take_action(&cfg)
            .await
            .unwrap();

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
    async fn test_migrate_is_noop_when_nothing_is_stale() {
        let key_dir = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(&db_dir.path().join("ks.db"), key_dir.path());
        let db = setup_test_db(&cfg).await;

        let repo = FernetKeyRepository::new(key_dir.path().to_path_buf());
        repo.setup().unwrap();
        let keys = repo.load(false).unwrap();
        let blob = keys.multi_fernet.encrypt(b"already-current");
        insert_credential(&db, "cred-1", blob.clone(), keys.primary_key_hash.clone()).await;

        command(CredentialCommands::Migrate { batch_size: 10 })
            .take_action(&cfg)
            .await
            .unwrap();

        let unchanged = db_credential::Entity::find_by_id("cred-1")
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.encrypted_blob, blob);
        assert_eq!(unchanged.key_hash, keys.primary_key_hash);
    }
}
