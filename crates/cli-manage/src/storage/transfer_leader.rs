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

//! # Transfer Raft leadership to another voter

use async_trait::async_trait;
use clap::Parser;
use color_eyre::{Report, eyre::eyre};
use tonic::transport::Uri;

use openstack_keystone_config::LoadedConfig;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::{call_leader, connect_leader, voters};
use crate::PerformAction;

/// Hands Raft leadership over to another voter.
///
/// Run it before a planned restart or maintenance of the leader node so the
/// cluster elects the new leader immediately instead of waiting for the
/// election timeout. `demote` and `remove-peer` do this automatically when
/// their target is the leader. Without `NODE_ID` the lowest-id other voter is
/// chosen. The command returns once the target is the leader.
#[derive(Parser)]
pub(super) struct TransferLeaderCommand {
    /// Cluster member to contact first (e.g. `https://127.0.0.1:50051`).
    /// Defaults to this host's `node_cluster_addr`.
    #[arg(long)]
    pub cluster_addr: Option<Uri>,

    /// Voter that becomes the leader.
    #[arg()]
    pub node_id: Option<u64>,
}

#[async_trait]
impl PerformAction for TransferLeaderCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        if super::ds_config(config).is_none() {
            return Err(eyre!("no distributed_storage configuration"));
        }
        let (_, metrics) = connect_leader(config, self.cluster_addr.clone()).await?;
        let leader = metrics.current_leader;
        let target = match self.node_id {
            Some(id) => id,
            None => voters(&metrics)
                .into_iter()
                .find(|id| Some(*id) != leader)
                .ok_or_else(|| eyre!("the cluster has no other voter to transfer to"))?,
        };
        if leader == Some(target) {
            println!("Node {target} is already the leader; nothing to do.");
            return Ok(());
        }
        call_leader(config, self.cluster_addr, false, |mut client| async move {
            client
                .transfer_leader(pb::raft::TransferLeaderAdminRequest { node_id: target })
                .await
        })
        .await?;
        println!("Node {target} is now the leader.");
        Ok(())
    }
}
