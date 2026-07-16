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
//! # OAuth2 subcommand of the keystone-manage cli.

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use color_eyre::{Report, eyre::WrapErr, eyre::eyre};
use reqwest::Client;
use spiffe_rustls::{authorizer, mtls_client};

use openstack_keystone_config::Config;

mod confirm_rotate_signing_key;
mod ensure_signing_key;
mod rotate_signing_key;

use crate::PerformAction;
use crate::oauth2::confirm_rotate_signing_key::ConfirmRotateSigningKeyCommand;
use crate::oauth2::ensure_signing_key::EnsureSigningKeyCommand;
use crate::oauth2::rotate_signing_key::RotateSigningKeyCommand;

/// OAuth2/OIDC provider administration (ADR 0026).
#[derive(Parser)]
pub struct Oauth2Command {
    #[command(subcommand)]
    command: Oauth2Commands,
}

#[async_trait]
impl PerformAction for Oauth2Command {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        match self.command {
            Oauth2Commands::RotateSigningKey(e) => e.take_action(config).await,
            Oauth2Commands::ConfirmRotateSigningKey(e) => e.take_action(config).await,
            Oauth2Commands::EnsureSigningKey(e) => e.take_action(config).await,
        }
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Subcommand)]
enum Oauth2Commands {
    RotateSigningKey(RotateSigningKeyCommand),
    ConfirmRotateSigningKey(ConfirmRotateSigningKeyCommand),
    EnsureSigningKey(EnsureSigningKeyCommand),
}

/// Build a `reqwest::Client` bound to the admin interface's Unix domain
/// socket, authenticating via SPIFFE mTLS. Mirrors `bootstrap.rs`: a request
/// over the admin UDS with a valid SVID auto-authenticates as `SystemAdmin`
/// (`crates/core/src/api/auth.rs`), so no bearer/Fernet token is needed.
async fn get_admin_client(config: &Config) -> Result<Client, Report> {
    let admin_if = config.interface_admin.as_ref().ok_or_else(|| {
        eyre!("admin interface not configured; oauth2 commands require [interface_admin]")
    })?;

    let source = spiffe::X509Source::new().await?;
    let client_config = mtls_client(source.clone())
        .authorize(authorizer::any())
        .build()
        .wrap_err("Building SPIFFE mTLS client config failed")?;

    Client::builder()
        .unix_socket(admin_if.listener.socket_path.clone())
        .tls_backend_preconfigured(client_config)
        .build()
        .wrap_err("Building reqwest client failed")
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Wrapper {
        #[command(subcommand)]
        command: Oauth2Commands,
    }

    #[test]
    fn test_parses_rotate_signing_key_subcommand() {
        let wrapper = Wrapper::parse_from(["oauth2", "rotate-signing-key", "--domain", "domain-1"]);
        assert!(matches!(
            wrapper.command,
            Oauth2Commands::RotateSigningKey(_)
        ));
    }

    #[test]
    fn test_parses_confirm_rotate_signing_key_subcommand() {
        let wrapper = Wrapper::parse_from([
            "oauth2",
            "confirm-rotate-signing-key",
            "--domain",
            "domain-1",
            "--rotation-id",
            "rot-1",
        ]);
        assert!(matches!(
            wrapper.command,
            Oauth2Commands::ConfirmRotateSigningKey(_)
        ));
    }

    #[tokio::test]
    async fn test_get_admin_client_rejects_missing_admin_interface_config() {
        let cfg = Config::default();
        let err = get_admin_client(&cfg).await.unwrap_err();
        assert!(
            err.to_string().contains("admin interface not configured"),
            "unexpected error: {err}"
        );
    }
}
