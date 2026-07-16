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
use color_eyre::{Report, eyre::eyre};
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
///
/// Use `--local-quorum-bypass` (with `--justification`) instead of
/// `--emergency` when the cluster has lost Raft quorum and the ordinary
/// emergency path -- itself a Raft proposal -- would block forever
/// (ADR 0028 §3). The candidate is written only to the responding node's
/// local emergency store; it must be explicitly reconciled once quorum
/// returns (not yet implemented). Refused unless that node's
/// `[local_emergency]` guardrail currently permits it.
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

    /// Stage a node-local, quorum-bypass emergency rotation instead
    /// (ADR 0028 §3). Mutually exclusive in effect with `--emergency`: when
    /// set, `--emergency` is ignored. Requires `--justification`.
    #[arg(long, default_value_t = false)]
    pub local_quorum_bypass: bool,

    /// Required with `--local-quorum-bypass`: the operator's reason for
    /// invoking the bypass, recorded with the candidate for audit.
    #[arg(long)]
    pub justification: Option<String>,
}

#[async_trait]
impl PerformAction for RotateDekCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        if self.local_quorum_bypass && self.justification.is_none() {
            return Err(eyre!(
                "--justification is required when --local-quorum-bypass is set"
            ));
        }

        let mut client = get_grpc_client(config, self.cluster_addr).await?;

        if self.local_quorum_bypass {
            let resp = client
                .rotate_dek_local_emergency(pb::raft::RotateDekLocalEmergencyRequest {
                    justification: self.justification.clone().unwrap_or_default(),
                })
                .await?
                .into_inner();
            println!(
                "Local quorum-bypass DEK rotation staged on the responding node.\n\
                 rotation_id={}\n\n\
                 This candidate is NOT yet replicated. Once quorum returns, an operator \
                 must explicitly reconcile it.",
                resp.rotation_id,
            );
            return Ok(());
        }

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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        inner: RotateDekCommand,
    }

    #[test]
    fn test_parses_local_quorum_bypass_and_justification() {
        let wrapper = Wrapper::parse_from([
            "storage",
            "--local-quorum-bypass",
            "--justification",
            "suspected key compromise",
        ]);
        assert!(wrapper.inner.local_quorum_bypass);
        assert_eq!(
            wrapper.inner.justification.as_deref(),
            Some("suspected key compromise")
        );
    }

    #[test]
    fn test_local_quorum_bypass_defaults_to_false() {
        let wrapper = Wrapper::parse_from(["storage"]);
        assert!(!wrapper.inner.local_quorum_bypass);
        assert!(wrapper.inner.justification.is_none());
    }

    #[tokio::test]
    async fn test_take_action_rejects_local_quorum_bypass_without_justification() {
        let cfg = Config::default();
        let command = RotateDekCommand {
            cluster_addr: None,
            emergency: false,
            local_quorum_bypass: true,
            justification: None,
        };

        let err = command.take_action(&cfg).await.unwrap_err();
        assert!(
            err.to_string().contains("--justification is required"),
            "unexpected error: {err}"
        );
    }
}
