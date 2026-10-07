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
use std::collections::BTreeSet;

use async_trait::async_trait;
use clap::Parser;
use color_eyre::{Report, eyre::eyre};
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL};
use tonic::transport::Uri;

use openstack_keystone_config::LoadedConfig;

use super::{get_grpc_client, rpc_error};
use crate::PerformAction;

/// Provides the details of all the peers in the Raft cluster.
///
/// This command is used to list the full set of peers in the Raft cluster, as
/// seen by the contacted node.
#[derive(Parser)]
pub(super) struct ListPeersCommand {
    /// Cluster member to ask (e.g. `https://127.0.0.1:50051`). Defaults to
    /// this host's `node_cluster_addr`.
    #[arg(long)]
    pub cluster_addr: Option<Uri>,
}

#[async_trait]
impl PerformAction for ListPeersCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        if super::ds_config(config).is_some() {
            let mut client = get_grpc_client(config, self.cluster_addr, false).await?;

            let metrics = client.metrics(()).await.map_err(rpc_error)?.into_inner();
            let membership = metrics.membership.unwrap_or_default();
            let members = membership
                .configs
                .into_iter()
                .flat_map(|nodeidset| nodeidset.node_ids.into_keys())
                .collect::<BTreeSet<_>>();
            let mut table = Table::new();
            table
                .load_style(UTF8_FULL.with_rounded_corners())
                .set_content_arrangement(ContentArrangement::Dynamic);
            table.set_header(vec!["Address", "Node ID", "Leader", "Voter"]);
            for node in membership.nodes.values() {
                table.add_row(vec![
                    node.rpc_addr.clone(),
                    node.node_id.to_string(),
                    if metrics.current_leader.is_some_and(|x| x == node.node_id) {
                        "yes".to_string()
                    } else {
                        "no".to_string()
                    },
                    if members.contains(&node.node_id) {
                        "yes".to_string()
                    } else {
                        "no".to_string()
                    },
                ]);
            }
            println!("{table}");
            println!("Metrics {:?}", metrics.other_metrics);
            Ok(())
        } else {
            Err(eyre!("no distributed_storage configuration"))
        }
    }
}
