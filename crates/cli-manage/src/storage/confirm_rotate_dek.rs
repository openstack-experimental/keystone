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

use openstack_keystone_config::Config;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::get_grpc_client;
use crate::PerformAction;

/// Confirm a pending emergency DEK rotation (dual-control second factor).
///
/// Must be invoked by a *different* `storage-operator` than the one who ran
/// `rotate-dek --emergency`, within 5 minutes of that command. Both operator
/// identities are recorded in the audit log.
///
/// If the 5-minute window has already expired, the pending rotation has been
/// automatically aborted and this command will return an error.
#[derive(Parser)]
pub(super) struct ConfirmRotateDekCommand {
    /// Cluster member to contact (e.g. `https://127.0.0.1:50051`).
    #[arg(long)]
    pub addr: Option<Uri>,

    /// The rotation_id printed by `rotate-dek --emergency`.
    #[arg(long)]
    pub rotation_id: String,
}

#[async_trait]
impl PerformAction for ConfirmRotateDekCommand {
    #[allow(clippy::print_stdout)]
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let mut client = get_grpc_client(config, self.addr).await?;

        client
            .confirm_rotate_dek(pb::raft::ConfirmRotateDekRequest {
                rotation_id: self.rotation_id.clone(),
            })
            .await?;

        println!(
            "Emergency DEK rotation {} confirmed. The compromised DEK is now revoked.",
            self.rotation_id
        );
        Ok(())
    }
}
