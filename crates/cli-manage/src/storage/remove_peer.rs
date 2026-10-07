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

//! # Remove a peer from the Raft cluster

use async_trait::async_trait;
use clap::Parser;
use color_eyre::{Report, eyre::eyre};
use tonic::transport::Uri;

use openstack_keystone_config::LoadedConfig;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::{connect_leader, rpc_error, voters};
use crate::PerformAction;

/// Removes a node from the Raft cluster.
///
/// This command is used to remove a node from being a peer to the Raft cluster.
/// In certain cases where a peer may be left behind in the Raft configuration
/// even though the server is no longer present and known to the cluster, this
/// command can be used to remove the failed server so that it no longer
/// affects the Raft quorum.
///
/// The change is computed from, and proposed on, the Raft leader, which is
/// located through `--cluster-addr` (default: this host's
/// `node_cluster_addr`). When the target is the current leader it steps down
/// once the change commits and the cluster has no leader until the next
/// election completes (leadership transfer is not implemented), so writes
/// briefly fail.
#[derive(Parser)]
pub(super) struct RemovePeerCommand {
    /// Cluster member to contact first (e.g. `https://127.0.0.1:50051`).
    /// Defaults to this host's `node_cluster_addr`.
    #[arg(long)]
    pub cluster_addr: Option<Uri>,

    /// Node ID of the voter to remove.
    #[arg()]
    pub node_id: u64,
}

#[async_trait]
impl PerformAction for RemovePeerCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        if super::ds_config(config).is_none() {
            return Err(eyre!("no distributed_storage configuration"));
        }
        let (mut client, metrics) = connect_leader(config, self.cluster_addr).await?;

        let mut members = voters(&metrics);
        if !members.remove(&self.node_id) {
            println!("Node {} is not a voter; nothing to do.", self.node_id);
            return Ok(());
        }
        if metrics.current_leader == Some(self.node_id) {
            eprintln!(
                "warning: node {} is the current leader; the cluster is leaderless until \
                 the next election completes",
                self.node_id
            );
        }

        client
            .change_membership(pb::raft::ChangeMembershipRequest {
                members: Vec::from_iter(members),
                retain: false,
            })
            .await
            .map_err(rpc_error)?;
        println!("Node {} removed from the cluster.", self.node_id);
        Ok(())
    }
}
