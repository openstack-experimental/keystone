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

//! # Promote a learner to a voter

use async_trait::async_trait;
use clap::Parser;
use color_eyre::{Report, eyre::eyre};
use tonic::transport::Uri;

use openstack_keystone_config::LoadedConfig;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::{connect_leader, rpc_error, voters};
use crate::PerformAction;

/// Promote a node to a voter.
///
/// This command is used to promote a permanent non-voter to a voter in the Raft
/// cluster. The node must already have joined as a learner. The change is
/// computed from, and proposed on, the Raft leader, which is located through
/// `--cluster-addr` (default: this host's `node_cluster_addr`), so it can be
/// run from any host that reaches a cluster member. Repeat once per learner.
#[derive(Parser)]
pub(super) struct PromoteCommand {
    /// Cluster member to contact first (e.g. `https://127.0.0.1:50051`).
    /// Defaults to this host's `node_cluster_addr`.
    #[arg(long)]
    pub cluster_addr: Option<Uri>,

    /// Node ID to be promoted.
    #[arg()]
    pub node_id: u64,
}

#[async_trait]
impl PerformAction for PromoteCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        if super::ds_config(config).is_none() {
            return Err(eyre!("no distributed_storage configuration"));
        }
        let (mut client, metrics) = connect_leader(config, self.cluster_addr).await?;

        let is_member = metrics
            .membership
            .as_ref()
            .is_some_and(|m| m.nodes.contains_key(&self.node_id));
        if !is_member {
            return Err(eyre!(
                "node {} is not a cluster member; join it as a learner first",
                self.node_id
            ));
        }
        let mut members = voters(&metrics);
        if !members.insert(self.node_id) {
            println!("Node {} is already a voter.", self.node_id);
            return Ok(());
        }

        client
            .change_membership(pb::raft::ChangeMembershipRequest {
                members: Vec::from_iter(members),
                retain: false,
            })
            .await
            .map_err(rpc_error)?;
        println!("Node {} promoted to voter.", self.node_id);
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
        inner: PromoteCommand,
    }

    #[test]
    fn test_parses_node_id_and_cluster_addr() {
        let wrapper = Wrapper::parse_from(["storage", "--cluster-addr", "https://n0:8300", "2"]);
        assert_eq!(wrapper.inner.node_id, 2);
        assert!(wrapper.inner.cluster_addr.is_some());
    }
}
