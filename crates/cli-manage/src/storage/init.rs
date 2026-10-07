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

use openstack_keystone_config::LoadedConfig;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::get_grpc_client;
use crate::PerformAction;

/// Initialize a new storage cluster.
///
/// This command initializes new distributed storage cluster consisting of
/// *this host's* node only (`node_id` and `node_cluster_addr` from the config
/// file), which it contacts at `node_cluster_addr`. Add further nodes with
/// `join` and `promote`.
#[derive(Parser)]
pub(super) struct InitCommand {}

#[async_trait]
impl PerformAction for InitCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        if let Some(cfg) = super::ds_config(config) {
            if let (Some(host), Some(port)) =
                (cfg.node_cluster_addr.host(), cfg.node_cluster_addr.port())
            {
                let mut client = get_grpc_client(config, None, false).await?;

                client
                    .init(pb::raft::InitRequest {
                        nodes: vec![pb::raft::Node {
                            node_id: cfg.node_id,
                            rpc_addr: format!("{host}:{port}"),
                        }],
                    })
                    .await?;
                Ok(())
            } else {
                Err(eyre!(
                    "cannot determine the host:port of the current node to initialize the cluster"
                ))
            }
        } else {
            Err(eyre!("no distributed_storage configuration"))
        }
    }
}
