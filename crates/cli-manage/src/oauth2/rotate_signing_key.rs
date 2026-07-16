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
    RotateSigningKeyRequest, RotateSigningKeyResponse,
};
use openstack_keystone_config::Config;

use super::get_admin_client;
use crate::PerformAction;

/// Rotate an OAuth2/OIDC domain's signing key (ADR 0026 §3).
///
/// Normal rotation (default) generates a new key, promotes it to `Primary`
/// and demotes the current `Primary` to `Previous` immediately -- both keys
/// remain published in JWKS so in-flight tokens still verify.
///
/// Use `--emergency` when the current signing key is suspected or confirmed
/// compromised. Emergency rotation only stages the new key: a second
/// operator must run `confirm-rotate-signing-key` with the returned
/// rotation-id within 15 minutes, or the rotation is automatically aborted.
///
/// Use `--local-quorum-bypass` (with `--justification`) instead of
/// `--emergency` when the cluster has lost Raft quorum and the ordinary
/// emergency path -- itself a Raft proposal -- would block forever
/// (ADR 0028 §2). The candidate is written only to the responding node's
/// local emergency store; it must be explicitly reconciled once quorum
/// returns (not yet implemented). Refused unless that node's
/// `[local_emergency]` guardrail currently permits it.
#[derive(Parser)]
pub(super) struct RotateSigningKeyCommand {
    /// Domain whose signing key should be rotated.
    #[arg(long)]
    pub domain: String,

    /// Initiate an emergency rotation (dual-control required).
    #[arg(long, default_value_t = false)]
    pub emergency: bool,

    /// Stage a node-local, quorum-bypass emergency rotation instead
    /// (ADR 0028 §2). Mutually exclusive in effect with `--emergency`: when
    /// set, `--emergency` is ignored. Requires `--justification`.
    #[arg(long, default_value_t = false)]
    pub local_quorum_bypass: bool,

    /// Required with `--local-quorum-bypass`: the operator's reason for
    /// invoking the bypass, recorded with the candidate for audit.
    #[arg(long)]
    pub justification: Option<String>,
}

#[async_trait]
impl PerformAction for RotateSigningKeyCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        if self.local_quorum_bypass && self.justification.is_none() {
            return Err(eyre!(
                "--justification is required when --local-quorum-bypass is set"
            ));
        }

        let client = get_admin_client(config).await?;

        let res = client
            .post(format!(
                "https://localhost/v4/oauth2/{}/rotate-signing-key",
                self.domain
            ))
            .json(&RotateSigningKeyRequest {
                emergency: self.emergency,
                local_quorum_bypass: self.local_quorum_bypass,
                justification: self.justification.clone(),
            })
            .send()
            .await
            .wrap_err("rotate-signing-key request failed")?;

        if !res.status().is_success() {
            return Err(eyre!(
                "rotate-signing-key failed: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        let body: RotateSigningKeyResponse = res.json().await?;

        if self.local_quorum_bypass {
            match body.local_rotation_id {
                Some(rotation_id) => {
                    println!(
                        "Local quorum-bypass signing-key rotation staged for domain {} on the \
                         responding node.\nrotation_id={rotation_id}\n\n\
                         This candidate is NOT yet replicated. Once quorum returns, an operator \
                         must explicitly reconcile it.",
                        self.domain,
                    );
                }
                None => {
                    println!("Local quorum-bypass rotation staged but no rotation_id returned.");
                }
            }
        } else if self.emergency {
            match (body.pending_rotation_id, body.expires_at) {
                (Some(rotation_id), Some(expires_at)) => {
                    println!(
                        "Emergency signing-key rotation staged for domain {}.\n\
                         rotation_id={rotation_id}\n\
                         expires_at={expires_at}\n\n\
                         A second operator must confirm within 15 minutes:\n\
                         \n  keystone-manage oauth2 confirm-rotate-signing-key \\\n\
                           \t--domain {} --rotation-id {rotation_id}",
                        self.domain, self.domain,
                    );
                }
                _ => {
                    println!("Emergency signing-key rotation staged but no rotation_id returned.");
                }
            }
        } else {
            println!(
                "Signing-key rotation committed for domain {}. New kid: {}",
                self.domain,
                body.kid.unwrap_or_default()
            );
        }

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
        inner: RotateSigningKeyCommand,
    }

    #[test]
    fn test_parses_domain_and_emergency_flags() {
        let wrapper = Wrapper::parse_from(["oauth2", "--domain", "domain-1", "--emergency"]);
        assert_eq!(wrapper.inner.domain, "domain-1");
        assert!(wrapper.inner.emergency);
    }

    #[test]
    fn test_emergency_defaults_to_false() {
        let wrapper = Wrapper::parse_from(["oauth2", "--domain", "domain-1"]);
        assert_eq!(wrapper.inner.domain, "domain-1");
        assert!(!wrapper.inner.emergency);
    }

    #[tokio::test]
    async fn test_take_action_rejects_missing_admin_interface_config() {
        // `get_admin_client` is the first thing `take_action` calls: a
        // `Config` with no `[interface_admin]` section (the default) must
        // fail fast with a clear error rather than attempting SPIFFE mTLS
        // setup against a nonexistent socket.
        let cfg = Config::default();
        let command = RotateSigningKeyCommand {
            domain: "domain-1".to_string(),
            emergency: false,
            local_quorum_bypass: false,
            justification: None,
        };

        let err = command.take_action(&cfg).await.unwrap_err();
        assert!(
            err.to_string().contains("admin interface not configured"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_parses_local_quorum_bypass_and_justification() {
        let wrapper = Wrapper::parse_from([
            "oauth2",
            "--domain",
            "domain-1",
            "--local-quorum-bypass",
            "--justification",
            "suspected key compromise",
        ]);
        assert_eq!(wrapper.inner.domain, "domain-1");
        assert!(wrapper.inner.local_quorum_bypass);
        assert_eq!(
            wrapper.inner.justification.as_deref(),
            Some("suspected key compromise")
        );
    }

    #[test]
    fn test_local_quorum_bypass_defaults_to_false() {
        let wrapper = Wrapper::parse_from(["oauth2", "--domain", "domain-1"]);
        assert!(!wrapper.inner.local_quorum_bypass);
        assert!(wrapper.inner.justification.is_none());
    }

    #[tokio::test]
    async fn test_take_action_rejects_local_quorum_bypass_without_justification() {
        let cfg = Config::default();
        let command = RotateSigningKeyCommand {
            domain: "domain-1".to_string(),
            emergency: false,
            local_quorum_bypass: true,
            justification: None,
        };

        let err = command.take_action(&cfg).await.unwrap_err();
        assert!(
            err.to_string().contains("--justification is required"),
            "unexpected error: {err}"
        );
    }
}
