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
use openstack_keystone_distributed_storage::protobuf as pb;

use super::get_grpc_client;
use crate::PerformAction;

/// Clear a quarantined keyspace partition.
///
/// A partition is automatically quarantined after three AES-256-GCM tag
/// verification failures within 60 seconds.  This command issues a Raft
/// proposal that propagates the clearance to all cluster members and removes
/// the persistent quarantine marker.
///
/// Only use this command after investigating the root cause of the GCM
/// failures — quarantine protects against data corruption or active tampering.
#[derive(Parser)]
pub(super) struct ClearQuarantineCommand {
    /// Cluster member to contact (e.g. `https://127.0.0.1:50051`).
    #[arg(long)]
    pub addr: Option<Uri>,

    /// The keyspace partition to un-quarantine.
    ///
    /// Common values: "data" (default application data), "meta", "index".
    #[arg(default_value = "data")]
    pub partition: String,
}

#[async_trait]
impl PerformAction for ClearQuarantineCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let mut client = get_grpc_client(config, self.addr).await?;

        client
            .clear_quarantine(pb::raft::ClearQuarantineRequest {
                partition: self.partition.clone(),
            })
            .await?;

        println!(
            "Quarantine cleared for partition '{}'. The partition is now writable on all nodes.",
            self.partition
        );
        Ok(())
    }
}
