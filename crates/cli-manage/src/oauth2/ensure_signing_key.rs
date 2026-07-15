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

use async_trait::async_trait;
use clap::Parser;
use color_eyre::{Report, eyre::WrapErr, eyre::eyre};

use openstack_keystone_api_types::v4::oauth2_key::EnsureSigningKeyResponse;
use openstack_keystone_config::Config;

use super::get_admin_client;
use crate::PerformAction;

/// Idempotently ensure a domain has an OAuth2/OIDC signing key (ADR 0026 §3).
///
/// A domain created through Keystone's own `POST /v3/domains` gets its
/// signing key automatically, provisioned by `Oauth2KeyHook` when the
/// domain-create event fires. A domain provisioned any other way -- most
/// notably the legacy Python `keystone-manage bootstrap`, which writes the
/// `default` domain straight into the database and never calls the Rust
/// API -- never fires that hook and is left without a signing key
/// indefinitely, so `/token` and `/jwks` fail for it. Run this once after
/// such a bootstrap (safe to re-run: a no-op if the domain already has a
/// key).
#[derive(Parser)]
pub(super) struct EnsureSigningKeyCommand {
    /// Domain to provision a signing key for.
    #[arg(long)]
    pub domain: String,
}

#[async_trait]
impl PerformAction for EnsureSigningKeyCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = get_admin_client(config).await?;

        let res = client
            .post(format!(
                "https://localhost/v4/oauth2/{}/ensure-signing-key",
                self.domain
            ))
            .send()
            .await
            .wrap_err("ensure-signing-key request failed")?;

        if !res.status().is_success() {
            return Err(eyre!(
                "ensure-signing-key failed: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        let body: EnsureSigningKeyResponse = res.json().await?;
        println!(
            "OAuth2 signing key present for domain {}. kid: {}",
            self.domain, body.kid
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        inner: EnsureSigningKeyCommand,
    }

    #[test]
    fn test_parses_domain_flag() {
        let wrapper = Wrapper::parse_from(["oauth2", "--domain", "domain-1"]);
        assert_eq!(wrapper.inner.domain, "domain-1");
    }

    #[tokio::test]
    async fn test_take_action_rejects_missing_admin_interface_config() {
        // Same fail-fast requirement as the other oauth2 subcommands:
        // `get_admin_client` is the first thing called, and a `Config`
        // without `[interface_admin]` must error clearly rather than
        // attempting SPIFFE mTLS setup against a nonexistent socket.
        let cfg = Config::default();
        let command = EnsureSigningKeyCommand {
            domain: "domain-1".to_string(),
        };

        let err = command.take_action(&cfg).await.unwrap_err();
        assert!(
            err.to_string().contains("admin interface not configured"),
            "unexpected error: {err}"
        );
    }
}
