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

use std::path::PathBuf;

use async_trait::async_trait;
use clap::Parser;
use color_eyre::Report;
use color_eyre::eyre::eyre;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tonic::transport::Uri;

use openstack_keystone_config::LoadedConfig;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::call_leader;
use crate::PerformAction;

/// Create an encrypted operator backup (Fjall snapshot).
///
/// Triggers a fresh snapshot on the Raft leader, then streams the AES-256-GCM
/// encrypted bytes to `--output`. The backup is bound to the current DEK epoch
/// via the Backup DEK (BDEK) and the snapshot timestamp — it cannot be replayed
/// against a different cluster or epoch without the corresponding KMS key.
/// When the contacted node is a follower the command retries against the
/// leader.
///
/// Restoring requires the KEK that protected the backup's DEKs. Retain this
/// file and the KMS keys for at least 365 days per ADR 0016-v2 §7.
#[derive(Parser)]
pub(super) struct BackupCommand {
    /// Cluster member to contact first (e.g. `https://127.0.0.1:50051`).
    /// Defaults to this host's `node_cluster_addr`.
    #[arg(long)]
    pub cluster_addr: Option<Uri>,

    /// Output file path for the encrypted snapshot.
    #[arg(long)]
    pub output: PathBuf,
}

#[async_trait]
impl PerformAction for BackupCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        if super::ds_config(config).is_none() {
            return Err(eyre!("no distributed_storage configuration"));
        }

        let mut stream = call_leader(config, self.cluster_addr, false, |mut client| async move {
            client
                .backup(pb::raft::BackupRequest {})
                .await
                .map(tonic::Response::into_inner)
        })
        .await?;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.output)
            .await
            .map_err(|e| eyre!("cannot create output file {:?}: {e}", self.output))?;

        let mut total_bytes = 0usize;
        let mut snapshot_utc_epoch: Option<u64> = None;
        let mut dek_version: Option<u32> = None;

        while let Some(chunk) = stream.message().await? {
            total_bytes += chunk.data.len();
            file.write_all(&chunk.data).await?;
            if chunk.snapshot_utc_epoch.is_some() {
                snapshot_utc_epoch = chunk.snapshot_utc_epoch;
                dek_version = chunk.dek_version;
            }
        }

        file.flush().await?;

        println!(
            "Backup written to {:?} ({} bytes)",
            self.output, total_bytes
        );
        if let (Some(epoch), Some(ver)) = (snapshot_utc_epoch, dek_version) {
            println!("  snapshot_utc_epoch={epoch}  dek_version={ver}");
        }

        Ok(())
    }
}
