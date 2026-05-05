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
use comfy_table::{ContentArrangement, Table, modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL};

use openstack_keystone_config::Config;

use super::get_grpc_client;
use crate::PerformAction;

/// Provides the details of all the peers in the Raft cluster.
///
/// This command is used to list the full set of peers in the Raft cluster.
#[derive(Parser)]
pub(super) struct ListPeersCommand {}

#[async_trait]
impl PerformAction for ListPeersCommand {
    #[allow(clippy::print_stdout)]
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        if config.distributed_storage.is_some() {
            let mut client = get_grpc_client(config, None).await?;

            let metrics = client.metrics(()).await?.into_inner();
            let membership = metrics.membership.unwrap_or_default();
            let members = membership
                .configs
                .into_iter()
                .flat_map(|nodeidset| nodeidset.node_ids.into_keys())
                .collect::<BTreeSet<_>>();
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
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
