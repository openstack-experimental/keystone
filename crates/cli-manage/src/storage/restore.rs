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
use tonic::transport::Uri;

use openstack_keystone_config::Config;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::get_grpc_client;
use crate::PerformAction;

/// Restore an encrypted operator backup to a freshly-bootstrapped cluster.
///
/// Streams the backup file produced by `backup` to the leader, which validates
/// the AES-256-GCM envelope (Backup DEK + AD binding), decrypts it, and
/// installs the snapshot into the Raft state machine.
///
/// **Prerequisites (see ADR 0016-v2 §7):**
/// 1. Bootstrap a fresh single-node cluster (`storage init`).
/// 2. Run this command against the leader.
/// 3. Add remaining nodes as learners (`storage join`) and promote them.
///
/// The KMS must hold the Backup DEK (`backup_dek` role) for the DEK epoch
/// indicated by the snapshot's `dek_version` field.
#[derive(Parser)]
pub(super) struct RestoreCommand {
    /// Leader address to contact (e.g. `https://127.0.0.1:50051`).
    #[arg(long)]
    pub addr: Option<Uri>,

    /// Path to the encrypted snapshot file produced by `backup`.
    #[arg(long)]
    pub snapshot: PathBuf,
}

#[async_trait]
impl PerformAction for RestoreCommand {
    #[allow(clippy::print_stdout)]
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let raw = fs::read(&self.snapshot)
            .await
            .map_err(|e| eyre!("cannot read snapshot file {:?}: {e}", self.snapshot))?;

        let file_size = raw.len();

        // Stream in 256 KiB chunks.
        const CHUNK_SIZE: usize = 256 * 1024;
        let chunks: Vec<pb::raft::RestoreChunk> = raw
            .chunks(CHUNK_SIZE)
            .map(|s| pb::raft::RestoreChunk { data: s.to_vec() })
            .collect();

        let mut client = get_grpc_client(config, self.addr).await?;

        client.restore(futures::stream::iter(chunks)).await?;

        println!(
            "Restore complete ({} bytes from {:?}).",
            file_size, self.snapshot
        );
        println!(
            "Next steps:\n  \
             1. Add remaining nodes as learners:  keystone-manage storage join ...\n  \
             2. Promote learners to voters:        keystone-manage storage promote ..."
        );

        Ok(())
    }
}
