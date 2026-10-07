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

//! # Demote a Raft voter to a learner

use async_trait::async_trait;
use clap::Parser;
use color_eyre::{Report, eyre::eyre};
use tonic::transport::Uri;

use openstack_keystone_config::LoadedConfig;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::{connect_leader, rpc_error, voters};
use crate::PerformAction;

/// Demotes voter to a permanent non-voter.
///
/// This command is used to demote a voter to a permanent non-voter in the Raft
/// cluster.
///
/// The change is computed from, and proposed on, the Raft leader, which is
/// located through `--cluster-addr` (default: this host's
/// `node_cluster_addr`). When the target is the current leader it steps down
/// once the change commits and the cluster has no leader until the next
/// election completes (leadership transfer is not implemented), so writes
/// briefly fail.
#[derive(Parser)]
pub(super) struct DemoteCommand {
    /// Cluster member to contact first (e.g. `https://127.0.0.1:50051`).
    /// Defaults to this host's `node_cluster_addr`.
    #[arg(long)]
    pub cluster_addr: Option<Uri>,

    /// Node ID to be demoted to a non-voter.
    #[arg()]
    pub node_id: u64,
}

#[async_trait]
impl PerformAction for DemoteCommand {
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
                retain: true,
            })
            .await
            .map_err(rpc_error)?;
        println!("Node {} demoted to learner.", self.node_id);
        Ok(())
    }
}
