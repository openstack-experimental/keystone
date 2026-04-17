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

use openstack_keystone_config::Config;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::get_grpc_client;
use crate::PerformAction;

/// Promote a node to a voter.
///
/// This command is used to promote a permanent non-voter to a voter in the Raft
/// cluster.
#[derive(Parser)]
pub(super) struct PromoteCommand {
    /// Node ID to be promoted.
    #[arg()]
    pub node_id: u64,
}

#[async_trait]
impl PerformAction for PromoteCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        if let Some(cfg) = &config.distributed_storage {
            let mut client = get_grpc_client(cfg, None).await?;

            let membership = client
                .metrics(())
                .await?
                .into_inner()
                .membership
                .unwrap_or_default();
            let all_node_ids = membership.nodes.keys().cloned().collect::<BTreeSet<_>>();
            let mut members = membership
                .configs
                .into_iter()
                .flat_map(|nodeidset| nodeidset.node_ids.into_keys())
                .collect::<BTreeSet<_>>();

            if all_node_ids.contains(&self.node_id) {
                members.insert(self.node_id);

                client
                    .change_membership(pb::raft::ChangeMembershipRequest {
                        members: Vec::from_iter(members.into_iter()),
                        retain: false,
                    })
                    .await?;
            }
            Ok(())
        } else {
            Err(eyre!("no distributed_storage configuration"))
        }
    }
}
