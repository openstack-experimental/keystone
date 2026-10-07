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

//! # Show a node's storage status

use async_trait::async_trait;
use clap::Parser;
use color_eyre::{Report, eyre::eyre};
use tonic::transport::Uri;

use openstack_keystone_config::LoadedConfig;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::{get_grpc_client, rpc_error};
use crate::PerformAction;

/// Show a node's Raft role and storage-encryption state.
///
/// Reports what the operator runbooks say to monitor: the active DEK version,
/// retired and revoked DEK epochs, emergency rotations awaiting
/// `confirm-rotate-dek`, quarantined partitions and the log-encryption nonce
/// counter. DEK and quarantine state can differ per node (a follower may not
/// have applied the latest rotation yet, and quarantine blocks reads only on
/// the reporting node), so run it against each node of interest with
/// `--cluster-addr`.
#[derive(Parser)]
pub(super) struct StatusCommand {
    /// Cluster member to ask (e.g. `https://127.0.0.1:50051`). Defaults to
    /// this host's `node_cluster_addr`.
    #[arg(long)]
    pub cluster_addr: Option<Uri>,
}

#[async_trait]
impl PerformAction for StatusCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        if super::ds_config(config).is_none() {
            return Err(eyre!("no distributed_storage configuration"));
        }

        let mut client = get_grpc_client(config, self.cluster_addr, false).await?;
        let status = client
            .storage_status(())
            .await
            .map_err(rpc_error)?
            .into_inner();
        print!("{}", render(&status));
        Ok(())
    }
}

fn join<T: ToString>(items: impl IntoIterator<Item = T>) -> String {
    let items: Vec<String> = items.into_iter().map(|i| i.to_string()).collect();
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

fn opt<T: ToString>(v: Option<T>) -> String {
    v.map_or_else(|| "none".to_string(), |v| v.to_string())
}

/// Formats a status response as aligned `key : value` lines.
fn render(s: &pb::raft::StorageStatusResponse) -> String {
    let mut out = String::new();
    let mut line = |k: &str, v: String| out.push_str(&format!("{k:<22}: {v}\n"));
    line("Node", s.node_id.to_string());
    line("State", s.state.clone());
    line("Current leader", opt(s.current_leader));
    line("Current term", s.current_term.to_string());
    line("Last log index", opt(s.last_log_index));
    line("Last applied index", opt(s.last_applied_index));
    line("DEK version", s.dek_version.to_string());
    line("Retired DEK versions", join(&s.retired_dek_versions));
    line("Revoked DEK versions", join(&s.revoked_dek_versions));
    line(
        "Pending rotations",
        join(s.pending_rotations.iter().map(|p| {
            format!(
                "{} (dek_version={}, initiator={}, expires_at={})",
                p.rotation_id, p.dek_version, p.initiator, p.expires_at
            )
        })),
    );
    line("Quarantined (local)", join(&s.quarantined_partitions));
    line(
        "Quarantine records",
        join(
            s.quarantine_records
                .iter()
                .map(|r| format!("{} (node {})", r.partition, r.node_id)),
        ),
    );
    let pct = if s.nonce_threshold == 0 {
        0.0
    } else {
        s.nonce_counter as f64 * 100.0 / s.nonce_threshold as f64
    };
    line(
        "Nonce counter",
        format!("{} / {} ({pct:.2}%)", s.nonce_counter, s.nonce_threshold),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_lists_all_fields() {
        let out = render(&pb::raft::StorageStatusResponse {
            node_id: 2,
            state: "Follower".into(),
            current_leader: Some(1),
            current_term: 3,
            last_log_index: Some(10),
            last_applied_index: Some(9),
            dek_version: 4,
            retired_dek_versions: vec![2, 3],
            revoked_dek_versions: vec![],
            pending_rotations: vec![pb::raft::PendingDekRotation {
                rotation_id: "rot-1".into(),
                dek_version: 5,
                expires_at: 100,
                initiator: "op-a".into(),
            }],
            quarantined_partitions: vec!["data".into()],
            quarantine_records: vec![pb::raft::QuarantineRecord {
                partition: "data".into(),
                node_id: 2,
            }],
            nonce_counter: 1 << 30,
            nonce_threshold: 1 << 31,
        });
        assert!(out.contains("State                 : Follower"), "{out}");
        assert!(out.contains("Retired DEK versions  : 2, 3"), "{out}");
        assert!(out.contains("Revoked DEK versions  : none"), "{out}");
        assert!(out.contains("rot-1 (dek_version=5"), "{out}");
        assert!(out.contains("data (node 2)"), "{out}");
        assert!(out.contains("(50.00%)"), "{out}");
    }
}
