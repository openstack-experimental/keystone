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
use color_eyre::Report;
use tonic::transport::Uri;

use openstack_keystone_config::Config;

use super::get_grpc_client;
use crate::PerformAction;

/// List node-local, quorum-bypass emergency DEK rotation candidates on the
/// responding node (ADR 0028 §6).
///
/// Run this against every node that may have been reachable during the
/// outage before choosing a `rotation_id` to pass to
/// `reconcile-dek-local-emergency` -- a `conflicted: true` entry means
/// gossip observed a different active candidate elsewhere, and the operator
/// must make an explicit choice.
#[derive(Parser)]
pub(super) struct ListDekLocalEmergencyCandidatesCommand {
    /// Address of the target cluster node (e.g. `https://127.0.0.1:50051`).
    #[arg(long)]
    pub cluster_addr: Option<Uri>,
}

#[async_trait]
impl PerformAction for ListDekLocalEmergencyCandidatesCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let mut client = get_grpc_client(config, self.cluster_addr).await?;

        let resp = client
            .list_dek_local_emergency_candidates(())
            .await?
            .into_inner();

        if resp.candidates.is_empty() {
            println!("No local emergency DEK candidates on this node.");
            return Ok(());
        }

        for c in &resp.candidates {
            println!(
                "rotation_id={}\n  initiator={}\n  justification={}\n  created_at_unix={}\n  origin_node_id={}\n  conflicted={}\n  revoked={}\n",
                c.rotation_id,
                c.initiator,
                c.justification,
                c.created_at_unix,
                if c.origin_node_id == 0 {
                    "local".to_string()
                } else {
                    c.origin_node_id.to_string()
                },
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
        inner: ListDekLocalEmergencyCandidatesCommand,
    }

    #[test]
    fn test_cluster_addr_defaults_to_none() {
        let wrapper = Wrapper::parse_from(["storage"]);
        assert!(wrapper.inner.cluster_addr.is_none());
    }

    #[test]
    fn test_parses_cluster_addr() {
        let wrapper = Wrapper::parse_from(["storage", "--cluster-addr", "https://127.0.0.1:50051"]);
        assert!(wrapper.inner.cluster_addr.is_some());
    }
}
