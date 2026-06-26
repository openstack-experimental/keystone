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
use color_eyre::eyre::eyre;
use tonic::transport::Uri;

use openstack_keystone_config::Config;

use super::get_grpc_client;
use crate::PerformAction;

/// Show raw cluster metrics from a Raft node.
///
/// Displays the current leader, membership configuration, and the full
/// OpenRaft metrics string. Useful for a quick health check or when
/// diagnosing replication lag, leader elections, or quarantine state.
///
/// For a tabular view of cluster peers use `list-peers` instead.
#[derive(Parser)]
pub(super) struct MetricsCommand {
    /// Address of the target cluster node (e.g. `https://127.0.0.1:50051`).
    #[arg(long)]
    pub cluster_addr: Option<Uri>,
}

#[async_trait]
impl PerformAction for MetricsCommand {
    #[allow(clippy::print_stdout)]
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        if config.distributed_storage.is_none() {
            return Err(eyre!("no distributed_storage configuration"));
        }

        let mut client = get_grpc_client(config, self.cluster_addr).await?;
        let metrics = client.metrics(()).await?.into_inner();

        let leader = match metrics.current_leader {
            Some(id) => format!("node {id}"),
            None => "none (election in progress?)".to_string(),
        };
        println!("Current leader : {leader}");

        if let Some(membership) = &metrics.membership {
            let voters: Vec<String> = membership
                .configs
                .iter()
                .flat_map(|s| s.node_ids.keys())
                .map(|id| id.to_string())
                .collect();
            println!("Voters         : [{}]", voters.join(", "));

            let all_nodes: Vec<String> = membership
                .nodes
                .values()
                .map(|n| format!("{}={}", n.node_id, n.rpc_addr))
                .collect();
            println!("All nodes      : [{}]", all_nodes.join(", "));
        }

        println!("\nRaw metrics:\n{}", metrics.other_metrics);
        Ok(())
    }
}
