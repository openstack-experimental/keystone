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
//! Thin wrapper around [`openstack_keystone_credential_driver_sql::migrate`]
//! and [`openstack_keystone_credential_driver_sql::rotate`], which own the
//! actual database/key-repository logic (kept in the driver crate so any
//! other caller gets the same safety checks — see those modules' docs).
//!
//! **`credential rotate` must not be run simultaneously from both the
//! Python and Rust services against the same database**, nor from two
//! overlapping invocations of either service alone. See
//! [`openstack_keystone_credential_driver_sql::rotate::rotate`]'s docs for
//! why the check-then-promote sequence isn't safe under concurrency.

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use color_eyre::{Report, eyre::WrapErr, eyre::eyre};
use eyre::Result;

use openstack_keystone_config::Config;
use openstack_keystone_credential_driver_sql::fernet::FernetKeyRepository;
use openstack_keystone_credential_driver_sql::{migrate, rotate};

use crate::PerformAction;
use crate::common::{connect_db, setup_logging};

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
        #[arg(
            long,
            default_value_t = DEFAULT_MIGRATE_BATCH_SIZE,
            value_parser = clap::value_parser!(u64).range(1..)
        )]
        batch_size: u64,
    },

    /// Promote the staged key to Primary.
    ///
    /// Aborts if any credential is still encrypted with a non-primary key —
    /// run `credential migrate` first to avoid making those credentials
    /// indecipherable.
    Rotate,
}

/// The only credential provider driver these commands know how to operate
/// on: the Fernet key repository and `credential` SQL table implemented by
/// `openstack-keystone-credential-driver-sql`.
const SUPPORTED_CREDENTIAL_DRIVER: &str = "sql";

#[async_trait]
impl PerformAction for CredentialCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        setup_logging(self.verbose);

        if config.credential.driver != SUPPORTED_CREDENTIAL_DRIVER {
            return Err(eyre!(
                "keystone-manage credential only supports the `{SUPPORTED_CREDENTIAL_DRIVER}` \
                 credential driver; configured driver is `{}`",
                config.credential.driver
            ));
        }

        match self.command {
            CredentialCommands::Setup => {
                let repo = FernetKeyRepository::new(config.credential.key_repository.clone());
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
                let total = migrate::migrate(config, &db, batch_size)
                    .await
                    .wrap_err("running credential_migrate")?;
                println!(
                    "credential_migrate complete: {total} credential(s) re-encrypted with the \
                     current primary key"
                );
                Ok(())
            }

            CredentialCommands::Rotate => {
                let db = connect_db(config).await?;
                rotate::rotate(config, &db)
                    .await
                    .wrap_err("running credential_rotate")?;
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

    fn test_config(db_path: &std::path::Path, key_repo: &std::path::Path) -> Config {
        let mut cfg = Config::default();
        cfg.database.connection =
            SecretString::from(format!("sqlite://{}?mode=rwc", db_path.display()));
        cfg.credential.key_repository = key_repo.to_path_buf();
        cfg
    }

    fn command(command: CredentialCommands) -> CredentialCommand {
        CredentialCommand {
            verbose: 0,
            command,
        }
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
    async fn test_rejects_unsupported_driver() {
        let key_dir = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let mut cfg = test_config(&db_dir.path().join("ks.db"), key_dir.path());
        cfg.credential.driver = "ldap".to_string();

        let err = command(CredentialCommands::Setup)
            .take_action(&cfg)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ldap"));
        // No DB connection or filesystem write should have been attempted.
        assert!(!key_dir.path().join("0").exists());
    }

    /// End-to-end wiring check: setup -> migrate -> rotate via the actual
    /// CLI dispatch, against a real (temp-file) DB. Substantive coverage of
    /// migrate/rotate semantics lives with their implementations in
    /// `openstack-keystone-credential-driver-sql`.
    #[tokio::test]
    async fn test_setup_migrate_rotate_roundtrip() {
        let key_dir = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(&db_dir.path().join("ks.db"), key_dir.path());

        command(CredentialCommands::Setup)
            .take_action(&cfg)
            .await
            .unwrap();

        let db = connect_db(&cfg).await.unwrap();
        create_credential_table(&db).await.unwrap();

        command(CredentialCommands::Migrate { batch_size: 10 })
            .take_action(&cfg)
            .await
            .unwrap();

        command(CredentialCommands::Rotate)
            .take_action(&cfg)
            .await
            .unwrap();

        assert!(key_dir.path().join("1").exists(), "staged key promoted");
    }
}
