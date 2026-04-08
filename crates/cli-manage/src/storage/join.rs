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
use tonic::transport::Channel;

use openstack_keystone_config::{Config, DistributedStorageConfiguration};
use openstack_keystone_distributed_storage::protobuf as pb;
use openstack_keystone_distributed_storage::protobuf::raft::cluster_admin_service_client::ClusterAdminServiceClient;

use super::get_grpc_client_tls_config;
use crate::PerformAction;

/// Join the current node as a peer to the Raft cluster.
///
/// This command is used to join a new node as a peer to the Raft cluster. In
/// order to join, there must be at least one existing member of the cluster.
#[derive(Parser)]
pub(super) struct JoinCommand {
    /// Initialized cluster address (e.g. `127.0.0.1:50051`).
    #[arg()]
    pub cluster_addr: String,
}

#[async_trait]
impl PerformAction for JoinCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        if let Some(cfg) = &config.distributed_storage {
            let mut client = get_grpc_client(self.cluster_addr, cfg).await?;

            client
                .add_learner(pb::raft::AddLearnerRequest {
                    node: Some(pb::raft::Node {
                        node_id: cfg.node_id,
                        rpc_addr: cfg.cluster_addr.clone(),
                    }),
                })
                .await?;
            Ok(())
        } else {
            Err(eyre!("no distributed_storage configuration"))
        }
    }
}

async fn get_grpc_client(
    addr: String,
    cfg: &DistributedStorageConfiguration,
) -> Result<ClusterAdminServiceClient<Channel>, Report> {
    let channel = if let Some(tls_config) = get_grpc_client_tls_config(cfg).await? {
        Channel::builder(format!("https://{}", addr).parse()?).tls_config(tls_config)?
    } else {
        Channel::builder(format!("http://{}", addr).parse()?)
    };
    let client = ClusterAdminServiceClient::new(channel.connect().await?);
    Ok(client)
}
