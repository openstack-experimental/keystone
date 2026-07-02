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

/// Rotate the Data Encryption Key (DEK).
///
/// Triggers a live background DEK rotation with no cluster downtime. All new
/// Raft log writes use the fresh DEK immediately; a background task re-encrypts
/// existing Fjall state entries using optimistic CAS-on-version.
///
/// Use `--emergency` when the current DEK is suspected or confirmed
/// compromised. Emergency rotation requires dual-control: a second
/// `storage-operator` must run `confirm-rotate-dek` with the returned
/// rotation-id within 5 minutes, or the rotation is automatically aborted.
#[derive(Parser)]
pub(super) struct RotateDekCommand {
    /// Address of the target cluster node (e.g. `https://127.0.0.1:50051`).
    #[arg(long)]
    pub cluster_addr: Option<Uri>,

    /// Initiate an emergency rotation (dual-control required).
    ///
    /// The current DEK will be marked revoked (not retired) once a second
    /// operator confirms via `confirm-rotate-dek`. If no confirmation arrives
    /// within 5 minutes the rotation is automatically aborted.
    #[arg(long, default_value_t = false)]
    pub emergency: bool,
}

#[async_trait]
impl PerformAction for RotateDekCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let mut client = get_grpc_client(config, self.cluster_addr).await?;

        let resp = client
            .rotate_dek(pb::raft::RotateDekRequest {
                emergency: self.emergency,
            })
            .await?
            .into_inner();

        if self.emergency {
            if resp.pending_rotation_id.is_empty() {
                println!("Emergency DEK rotation staged but no rotation_id returned.");
            } else {
                println!(
                    "Emergency DEK rotation staged.\n\
                     rotation_id={}\n\n\
                     A second storage-operator must confirm within 5 minutes:\n\
                     \n  keystone-manage storage confirm-rotate-dek \\\n\
                       \t--rotation-id {}",
                    resp.pending_rotation_id, resp.pending_rotation_id,
                );
            }
        } else {
            println!("DEK rotation committed. Monitor the audit log for DEK_ROTATION events.");
        }

        Ok(())
    }
}
