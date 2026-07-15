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
#[derive(Parser)]
pub(super) struct RotateSigningKeyCommand {
    /// Domain whose signing key should be rotated.
    #[arg(long)]
    pub domain: String,

    /// Initiate an emergency rotation (dual-control required).
    #[arg(long, default_value_t = false)]
    pub emergency: bool,
}

#[async_trait]
impl PerformAction for RotateSigningKeyCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = get_admin_client(config).await?;

        let res = client
            .post(format!(
                "https://localhost/v4/oauth2/{}/rotate-signing-key",
                self.domain
            ))
            .json(&RotateSigningKeyRequest {
                emergency: self.emergency,
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

        if self.emergency {
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
