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

use openstack_keystone_api_types::v4::oauth2_key::ListLocalEmergencyCandidatesResponse;
use openstack_keystone_config::Config;

use super::get_admin_client;
use crate::PerformAction;

/// List node-local, quorum-bypass emergency signing-key rotation candidates
/// on the responding node (ADR 0028 §6).
///
/// Run this against every node that may have been reachable during the
/// outage before choosing a `rotation_id` to pass to
/// `reconcile-local-emergency-key` -- a `conflicted: true` entry means
/// gossip observed a different active candidate for this domain elsewhere,
/// and the operator must make an explicit choice.
#[derive(Parser)]
pub(super) struct ListLocalEmergencyCandidatesCommand {
    /// Domain to list local emergency candidates for.
    #[arg(long)]
    pub domain: String,
}

#[async_trait]
impl PerformAction for ListLocalEmergencyCandidatesCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = get_admin_client(config).await?;

        let res = client
            .get(format!(
                "https://localhost/v4/oauth2/{}/local-emergency-candidates",
                self.domain
            ))
            .send()
            .await
            .wrap_err("list-local-emergency-candidates request failed")?;

        if !res.status().is_success() {
            return Err(eyre!(
                "list-local-emergency-candidates failed: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        let body: ListLocalEmergencyCandidatesResponse = res.json().await?;
        if body.candidates.is_empty() {
            println!(
                "No local emergency candidates on this node for domain {}.",
                self.domain
            );
            return Ok(());
        }

        for c in &body.candidates {
            println!(
                "rotation_id={}\n  initiator={}\n  justification={}\n  created_at_unix={}\n  origin_node_id={}\n  conflicted={}\n  revoked={}\n",
                c.rotation_id,
                c.initiator,
                c.justification,
                c.created_at_unix,
                c.origin_node_id
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "local".to_string()),
                c.conflicted,
                c.revoked,
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
        inner: ListLocalEmergencyCandidatesCommand,
    }

    #[test]
    fn test_parses_domain() {
        let wrapper = Wrapper::parse_from(["oauth2", "--domain", "domain-1"]);
        assert_eq!(wrapper.inner.domain, "domain-1");
    }

    #[tokio::test]
    async fn test_take_action_rejects_missing_admin_interface_config() {
        let cfg = Config::default();
        let command = ListLocalEmergencyCandidatesCommand {
            domain: "domain-1".to_string(),
        };

        let err = command.take_action(&cfg).await.unwrap_err();
        assert!(
            err.to_string().contains("admin interface not configured"),
            "unexpected error: {err}"
        );
    }
}
