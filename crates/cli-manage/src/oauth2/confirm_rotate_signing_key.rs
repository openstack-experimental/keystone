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

use openstack_keystone_api_types::v4::oauth2_key::{
    ConfirmRotateSigningKeyRequest, ConfirmRotateSigningKeyResponse,
};
use openstack_keystone_config::Config;

use super::get_admin_client;
use crate::PerformAction;

/// Confirm a pending emergency signing-key rotation (dual-control second
/// factor).
///
/// Must be invoked by a different operator than the one who ran
/// `rotate-signing-key --emergency`, within 15 minutes of that command --
/// enforced by the provider layer. If the window has already expired, the
/// pending rotation has been automatically aborted and this command will
/// return an error.
#[derive(Parser)]
pub(super) struct ConfirmRotateSigningKeyCommand {
    /// Domain whose signing-key rotation is being confirmed.
    #[arg(long)]
    pub domain: String,

    /// The rotation_id printed by `rotate-signing-key --emergency`.
    #[arg(long)]
    pub rotation_id: String,

    /// JTIs known to have been issued by the compromised key during the
    /// incident window, to add to the JTI revocation list. Repeat the flag
    /// for multiple JTIs.
    #[arg(long = "revoke-jti")]
    pub revoke_jtis: Vec<String>,
}

#[async_trait]
impl PerformAction for ConfirmRotateSigningKeyCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = get_admin_client(config).await?;

        let res = client
            .post(format!(
                "https://localhost/v4/oauth2/{}/confirm-rotate-signing-key",
                self.domain
            ))
            .json(&ConfirmRotateSigningKeyRequest {
                rotation_id: self.rotation_id.clone(),
                revoke_jtis: self.revoke_jtis,
            })
            .send()
            .await
            .wrap_err("confirm-rotate-signing-key request failed")?;

        if !res.status().is_success() {
            return Err(eyre!(
                "confirm-rotate-signing-key failed: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        let body: ConfirmRotateSigningKeyResponse = res.json().await?;
        println!(
            "Emergency signing-key rotation {} confirmed for domain {}. New kid: {}",
            self.rotation_id, self.domain, body.kid
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
        inner: ConfirmRotateSigningKeyCommand,
    }

    #[test]
    fn test_parses_repeated_revoke_jti_flags() {
        let wrapper = Wrapper::parse_from([
            "oauth2",
            "--domain",
            "domain-1",
            "--rotation-id",
            "rot-1",
            "--revoke-jti",
            "jti-a",
            "--revoke-jti",
            "jti-b",
        ]);
        assert_eq!(wrapper.inner.domain, "domain-1");
        assert_eq!(wrapper.inner.rotation_id, "rot-1");
        assert_eq!(wrapper.inner.revoke_jtis, vec!["jti-a", "jti-b"]);
    }

    #[test]
    fn test_revoke_jti_defaults_to_empty() {
        let wrapper =
            Wrapper::parse_from(["oauth2", "--domain", "domain-1", "--rotation-id", "rot-1"]);
        assert!(wrapper.inner.revoke_jtis.is_empty());
    }

    #[tokio::test]
    async fn test_take_action_rejects_missing_admin_interface_config() {
        let cfg = Config::default();
        let command = ConfirmRotateSigningKeyCommand {
            domain: "domain-1".to_string(),
            rotation_id: "rot-1".to_string(),
            revoke_jtis: vec![],
        };

        let err = command.take_action(&cfg).await.unwrap_err();
        assert!(
            err.to_string().contains("admin interface not configured"),
            "unexpected error: {err}"
        );
    }
}
