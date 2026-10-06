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
//! Audit framework key management commands (ADR 0023).

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use color_eyre::{Report, eyre::WrapErr};
use eyre::Result;

use cadf::HmacKeyring;
use openstack_keystone::server::startup::audit::AUDIT_SERVICE;
use openstack_keystone_config::LoadedConfig;

use crate::PerformAction;
use crate::common::setup_logging;

/// Audit framework management.
#[derive(Parser)]
pub struct AuditCommand {
    /// Verbosity level. Repeat to increase level.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: AuditCommands,
}

#[derive(Subcommand)]
enum AuditCommands {
    /// Rotate the audit HMAC signing key.
    ///
    /// Adds a new key version to the keyring (`[audit] hmac_kek_file`) and
    /// makes it current. Previous versions are kept so events already signed
    /// and shipped stay verifiable. Running Keystone servers switch to the new
    /// version within about 30 seconds; a server started later uses it
    /// immediately. The keyring must exist, i.e. Keystone must have started
    /// at least once.
    ///
    /// Distribute the updated keyring to the SIEM verifier before relying on
    /// events signed with the new version.
    RotateHmacKey,
}

#[async_trait]
impl PerformAction for AuditCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        setup_logging(self.verbose);

        match self.command {
            AuditCommands::RotateHmacKey => {
                let path = config.audit.hmac_kek_path(&AUDIT_SERVICE);
                let version = {
                    let path = path.clone();
                    tokio::task::spawn_blocking(move || HmacKeyring::rotate(&path))
                        .await
                        .wrap_err("audit key rotation task failed")?
                        .wrap_err("rotating the audit HMAC key")?
                };
                println!(
                    "audit HMAC key rotated: version {version} is now current ({})",
                    path.display()
                );
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rotate_adds_a_version_to_the_configured_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = LoadedConfig::new(Default::default());
        cfg.audit.hmac_kek_file = Some(dir.path().join("audit.keyring"));
        HmacKeyring::load_or_create(&cfg.audit.hmac_kek_path(&AUDIT_SERVICE)).unwrap();

        let command = || AuditCommand {
            verbose: 0,
            command: AuditCommands::RotateHmacKey,
        };
        command().take_action(&cfg).await.unwrap();
        command().take_action(&cfg).await.unwrap();

        let keyring = HmacKeyring::load(&cfg.audit.hmac_kek_path(&AUDIT_SERVICE))
            .unwrap()
            .unwrap();
        assert_eq!(keyring.current_version(), 3);
        assert_eq!(keyring.versions(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn rotate_fails_without_an_existing_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = LoadedConfig::new(Default::default());
        cfg.audit.hmac_kek_file = Some(dir.path().join("missing.keyring"));
        let command = AuditCommand {
            verbose: 0,
            command: AuditCommands::RotateHmacKey,
        };
        assert!(command.take_action(&cfg).await.is_err());
    }
}
