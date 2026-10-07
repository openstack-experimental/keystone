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

use super::{get_grpc_client, rpc_error};
use crate::PerformAction;

/// Reconcile a node-local, quorum-bypass emergency DEK rotation candidate
/// into Raft-replicated state (ADR 0028 §6).
///
/// Must be run against the Raft leader, which must hold `rotation_id` (staged
/// there or adopted through gossip; check with
/// `list-dek-local-emergency-candidates --cluster-addr <leader>`) --
/// reconciliation does not fan out across the cluster. The command does not
/// follow leader redirects: a follower answers with the leader's address so
/// the operator can verify the candidate on the leader first. Installs the
/// candidate's DEK via the normal Raft transaction path, which requires quorum
/// to be available again. The
/// confirming operator must differ from the one who staged the candidate
/// (dual-control, same as `confirm-rotate-dek`). On success, the candidate
/// is cleared from this node and any other active candidate on this node is
/// revoked.
#[derive(Parser)]
pub(super) struct ReconcileDekLocalEmergencyCommand {
    /// Address of the target cluster node (e.g. `https://127.0.0.1:50051`).
    #[arg(long)]
    pub cluster_addr: Option<Uri>,

    /// The rotation_id to promote, from `list-dek-local-emergency-candidates`.
    #[arg(long)]
    pub rotation_id: String,
}

#[async_trait]
impl PerformAction for ReconcileDekLocalEmergencyCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let mut client = get_grpc_client(config, self.cluster_addr, false).await?;

        client
            .reconcile_dek_local_emergency(pb::raft::ReconcileDekLocalEmergencyRequest {
                rotation_id: self.rotation_id.clone(),
            })
            .await
            .map_err(rpc_error)?;

        println!(
            "Local emergency DEK rotation {} reconciled. The new DEK is now active.",
            self.rotation_id
        );
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
        inner: ReconcileDekLocalEmergencyCommand,
    }

    #[test]
    fn test_parses_rotation_id() {
        let wrapper = Wrapper::parse_from(["storage", "--rotation-id", "rot-1"]);
        assert_eq!(wrapper.inner.rotation_id, "rot-1");
        assert!(wrapper.inner.cluster_addr.is_none());
    }
}
