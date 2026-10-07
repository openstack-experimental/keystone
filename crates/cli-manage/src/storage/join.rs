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
//! Keystone manage executable.

use async_trait::async_trait;
use clap::Parser;
use color_eyre::{Report, eyre::eyre};
use tonic::transport::Uri;

use openstack_keystone_config::LoadedConfig;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::call_leader;
use crate::PerformAction;

/// Join the current node as a peer to the Raft cluster.
///
/// This command is used to join a new node as a peer to the Raft cluster. In
/// order to join, there must be at least one existing member of the cluster.
///
/// Always announces *this host's* node (`node_id` and `node_cluster_addr`
/// from the config file) as a learner, authenticating with the node's own
/// identity. `cluster_addr` may be any member: the learner is added on the
/// Raft leader, and the command follows the redirect when the contacted
/// member is a follower. Joining is idempotent for the same address; it
/// fails when the node id is already registered at a different address.
#[derive(Parser)]
pub(super) struct JoinCommand {
    /// Address of any initialized cluster member (e.g.
    /// `https://127.0.0.1:50051`).
    #[arg()]
    pub cluster_addr: Uri,
}

#[async_trait]
impl PerformAction for JoinCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        if let Some(cfg) = super::ds_config(config) {
            if let (Some(host), Some(port)) =
                (cfg.node_cluster_addr.host(), cfg.node_cluster_addr.port())
            {
                let node = pb::raft::Node {
                    node_id: cfg.node_id,
                    rpc_addr: format!("{host}:{port}"),
                };
                // Re-adding the same (node_id, address) succeeds, so a node
                // that already auto-joined through `retry_join_nodes` is fine.
                // `AlreadyExists` means the id is registered at a *different*
                // address -- a node-id collision (ADR 0016-v2 §4.3), which
                // must fail.
                call_leader(config, Some(self.cluster_addr), true, |mut client| {
                    let request = pb::raft::AddLearnerRequest {
                        node: Some(node.clone()),
                    };
                    async move { client.add_learner(request).await }
                })
                .await
                .map_err(|e| eyre!("add_learner failed: {e}"))?;
                Ok(())
            } else {
                Err(eyre!(
                    "cannot determine the host:port of the current node to announce to the cluster"
                ))
            }
        } else {
            Err(eyre!("no distributed_storage configuration"))
        }
    }
}
