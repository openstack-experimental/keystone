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
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tonic::transport::Uri;

use openstack_keystone_config::LoadedConfig;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::call_leader;
use crate::PerformAction;

const CHUNK_SIZE: usize = 256 * 1024;

fn file_chunk_stream(
    file: File,
    elect: bool,
    total_len: u64,
) -> impl futures::Stream<Item = pb::raft::RestoreChunk> {
    futures::stream::unfold(
        (file, elect, total_len),
        |(mut f, elect, total_len)| async move {
            let mut buf = vec![0u8; CHUNK_SIZE];
            let n = match f.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    // Ending the stream early is safe: the server compares
                    // the bytes received with the declared size and rejects
                    // a short upload.
                    tracing::error!(error = %e, "reading the backup file failed");
                    return None;
                }
            };
            if n == 0 {
                return None;
            }
            buf.truncate(n);
            // The flag and the size are read from the first chunk only.
            Some((
                pb::raft::RestoreChunk {
                    data: buf,
                    elect,
                    total_len,
                },
                (f, false, 0),
            ))
        },
    )
}

/// Restore an encrypted operator backup.
///
/// Streams the backup file produced by `backup` to the node, which validates
/// the AES-256-GCM envelope (Backup DEK + AD binding) and decrypts it. The
/// KMS must hold the KEK that protected the backup's DEKs.
///
/// **Into a running cluster** (the usual case): the backup must reach the
/// Raft leader; when `--cluster-addr` (or this host's node) is a follower the
/// command retries against the leader. It is committed through the Raft log
/// and replaces the data on every node. Cluster membership is unchanged.
///
/// **Disaster recovery** (the cluster is gone): start every node with
/// `auto_bootstrap = false` so they stay uninitialized, then run this command
/// with the same backup against *each* node, passing `--elect` on exactly one.
/// The backup's Raft state, including its membership, is installed (OpenRaft
/// "restore from snapshot"), so the original node ids and addresses must be
/// reachable again. Nodes that are not in the backup's membership stay
/// learners.
#[derive(Parser)]
pub(super) struct RestoreCommand {
    /// Address of the target node (e.g. `https://127.0.0.1:50051`).
    #[arg(long)]
    pub cluster_addr: Option<Uri>,

    /// Path to the encrypted snapshot file produced by `backup`.
    #[arg(long)]
    pub snapshot: PathBuf,

    /// Disaster recovery only: start an election on this node after the
    /// backup is installed. Pass it for exactly one of the restored nodes.
    #[arg(long)]
    pub elect: bool,
}

#[async_trait]
impl PerformAction for RestoreCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let file_size = File::open(&self.snapshot)
            .await
            .map_err(|e| eyre!("cannot open snapshot file {:?}: {e}", self.snapshot))?
            .metadata()
            .await
            .map(|m| m.len())
            .unwrap_or(0);

        call_leader(config, self.cluster_addr, false, |mut client| {
            let path = self.snapshot.clone();
            let elect = self.elect;
            async move {
                // Re-opened per attempt: a leader redirect needs the stream
                // again from the start.
                let file = File::open(&path).await.map_err(|e| {
                    tonic::Status::internal(format!("cannot open snapshot file {path:?}: {e}"))
                })?;
                // Stream in 256 KiB chunks; at most one chunk is resident in
                // memory at a time.
                client
                    .restore(file_chunk_stream(file, elect, file_size))
                    .await
            }
        })
        .await?;

        println!(
            "Restore complete ({} bytes from {:?}).",
            file_size, self.snapshot
        );
        println!(
            "Into a running cluster the restore is already active on every node.\n\
             For disaster recovery, repeat this command with the same backup on each \
             remaining node (`--elect` on exactly one); the original membership is restored."
        );

        Ok(())
    }
}
