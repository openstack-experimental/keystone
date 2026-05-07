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

use openstack_keystone_config::Config;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::get_grpc_client;
use crate::PerformAction;

/// Join the current node as a peer to the Raft cluster.
///
/// This command is used to join a new node as a peer to the Raft cluster. In
/// order to join, there must be at least one existing member of the cluster.
#[derive(Parser)]
pub(super) struct JoinCommand {
    /// Initialized cluster address (e.g. `127.0.0.1:50051`).
    #[arg()]
    pub cluster_addr: Uri,
}

#[async_trait]
impl PerformAction for JoinCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        if let Some(cfg) = &config.distributed_storage {
            if let (Some(host), Some(port)) =
                (cfg.node_cluster_addr.host(), cfg.node_cluster_addr.port())
            {
                let mut client = get_grpc_client(config, Some(self.cluster_addr)).await?;

                client
                    .add_learner(pb::raft::AddLearnerRequest {
                        node: Some(pb::raft::Node {
                            node_id: cfg.node_id,
                            rpc_addr: format!("{host}:{port}"),
                        }),
                    })
                    .await?;
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
