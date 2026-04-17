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
//! # Demote raft node from member to learner
use std::collections::BTreeSet;

use async_trait::async_trait;
use clap::Parser;
use color_eyre::{Report, eyre::eyre};

use openstack_keystone_config::Config;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::get_grpc_client;
use crate::PerformAction;

/// Demotes voter to a permanent non-voter.
///
/// This command is used to demote a voter to a permanent non-voter in the Raft
/// cluster.
#[derive(Parser)]
pub(super) struct DemoteCommand {
    /// Node ID to be demoted to a non-voter.
    #[arg()]
    pub node_id: u64,
}

#[async_trait]
impl PerformAction for DemoteCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        if let Some(cfg) = &config.distributed_storage {
            let mut client = get_grpc_client(cfg, None).await?;

            let membership = client
                .metrics(())
                .await?
                .into_inner()
                .membership
                .unwrap_or_default();
            let mut members = membership
                .configs
                .into_iter()
                .flat_map(|nodeidset| nodeidset.node_ids.into_keys())
                .collect::<BTreeSet<_>>();

            if members.contains(&self.node_id) {
                members.remove(&self.node_id);

                client
                    .change_membership(pb::raft::ChangeMembershipRequest {
                        members: Vec::from_iter(members.into_iter()),
                        retain: true,
                    })
                    .await?;
            }
            Ok(())
        } else {
            Err(eyre!("no distributed_storage configuration"))
        }
    }
}
