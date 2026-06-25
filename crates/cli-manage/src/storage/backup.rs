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

use openstack_keystone_config::Config;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::get_grpc_client;
use crate::PerformAction;

/// Create an encrypted operator backup (Fjall snapshot).
///
/// Triggers a fresh snapshot on the target node, then streams the AES-256-GCM
/// encrypted bytes to `--output`. The backup is bound to the current DEK epoch
/// via the Backup DEK (BDEK) and the snapshot timestamp — it cannot be replayed
/// against a different cluster or epoch without the corresponding KMS key.
///
/// The final output includes a DEK manifest covering any retired DEKs required
/// for offline decryption. Retain this file and the KMS keys for at least 365
/// days per ADR 0016-v2 §7.
#[derive(Parser)]
pub(super) struct BackupCommand {
    /// Cluster member to contact (e.g. `https://127.0.0.1:50051`).
    #[arg(long)]
    pub addr: Option<Uri>,

    /// Output file path for the encrypted snapshot.
    #[arg(long)]
    pub output: PathBuf,
}

#[async_trait]
impl PerformAction for BackupCommand {
    #[allow(clippy::print_stdout)]
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let mut client = get_grpc_client(config, self.addr).await?;

        let mut stream = client
            .backup(pb::raft::BackupRequest {})
            .await?
            .into_inner();

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
