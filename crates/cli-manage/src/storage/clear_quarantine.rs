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

use openstack_keystone_config::LoadedConfig;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::call_leader;
use crate::PerformAction;

/// Clear a quarantined keyspace partition.
///
/// A partition is automatically quarantined after three AES-256-GCM tag
/// verification failures within 60 seconds. This command issues a Raft
/// proposal that propagates the clearance to all cluster members and removes
/// the persistent quarantine marker.
///
/// Only use this command after investigating the root cause of the GCM
/// failures — quarantine protects against data corruption or active tampering.
/// `storage status` lists the quarantine markers each node holds.
///
/// The proposal must be made on the Raft leader; when `--cluster-addr` (or
/// this host's node) is a follower the command retries against the leader.
#[derive(Parser)]
pub(super) struct ClearQuarantineCommand {
    /// Cluster member to contact first (e.g. `https://127.0.0.1:50051`).
    /// Defaults to this host's `node_cluster_addr`.
    #[arg(long)]
    pub cluster_addr: Option<Uri>,

    /// The keyspace partition to un-quarantine.
    ///
    /// Common values: "data" (default application data), "meta", "index".
    #[arg(long, default_value = "data")]
    pub partition: String,
}

#[async_trait]
impl PerformAction for ClearQuarantineCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        call_leader(config, self.cluster_addr, false, |mut client| {
            let request = pb::raft::ClearQuarantineRequest {
                partition: self.partition.clone(),
            };
            async move { client.clear_quarantine(request).await }
        })
        .await?;

        println!(
            "Quarantine cleared for partition '{}'. The partition is now writable on all nodes.",
            self.partition
        );
        Ok(())
    }
}
