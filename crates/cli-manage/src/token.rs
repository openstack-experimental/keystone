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
//! Fernet token encryption key management commands (ADR 0019 §4).
//!
//! Mirrors [`crate::credential::CredentialCommand`], backed by the same
//! shared [`openstack_keystone_key_repository`] logic. Unlike the
//! credential key repository, there is no `migrate` subcommand here: tokens
//! are short-lived and are never re-encrypted, they simply stop decrypting
//! once their key is pruned by a later rotation.

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use color_eyre::{Report, eyre::WrapErr};
use eyre::Result;

use openstack_keystone_config::Config;
use openstack_keystone_token_driver_fernet::utils::FernetUtils;

use crate::PerformAction;
use crate::common::setup_logging;

/// Fernet token encryption key management.
#[derive(Parser)]
pub struct TokenCommand {
    /// Verbosity level. Repeat to increase level.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: TokenCommands,
}

#[derive(Subcommand)]
enum TokenCommands {
    /// Populate the token key repository with an initial staged key.
    ///
    /// Must be run once during deployment, before any tokens are issued via
    /// either service.
    Setup,

    /// Promote the staged key to Primary.
    ///
    /// Aborts nothing else first — unlike `credential rotate`, there is no
    /// stale-data check to run: tokens issued under a key that gets pruned
    /// simply fail to decrypt (they expire long before `max_active_keys`
    /// rotations typically elapse).
    Rotate,
}

fn utils_from(config: &Config) -> FernetUtils {
    FernetUtils {
        key_repository: config.fernet_tokens.key_repository.clone(),
        max_active_keys: config.fernet_tokens.max_active_keys,
    }
}

#[async_trait]
impl PerformAction for TokenCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        setup_logging(self.verbose);

        let utils = utils_from(config);

        match self.command {
            TokenCommands::Setup => {
                utils
                    .initialize_key_repository()
                    .await
                    .wrap_err("setting up token key repository")?;
                println!(
                    "token key repository initialized at {}",
                    config.fernet_tokens.key_repository.display()
                );
                Ok(())
            }

            TokenCommands::Rotate => {
                utils.rotate().await.wrap_err("running token_rotate")?;
                println!("token key repository rotated");
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(key_repo: &std::path::Path) -> Config {
        let mut cfg = Config::default();
        cfg.fernet_tokens.key_repository = key_repo.to_path_buf();
        cfg
    }

    fn command(command: TokenCommands) -> TokenCommand {
        TokenCommand {
            verbose: 0,
            command,
        }
    }

    #[tokio::test]
    async fn test_setup_creates_staged_key() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());

        command(TokenCommands::Setup)
            .take_action(&cfg)
            .await
            .unwrap();

        assert!(key_dir.path().join("0").exists());
    }

    #[tokio::test]
    async fn test_setup_rotate_roundtrip() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());

        command(TokenCommands::Setup)
            .take_action(&cfg)
            .await
            .unwrap();
        command(TokenCommands::Rotate)
            .take_action(&cfg)
            .await
            .unwrap();

        assert!(key_dir.path().join("1").exists(), "staged key promoted");
        assert!(key_dir.path().join("0").exists(), "fresh key staged");
    }
}
