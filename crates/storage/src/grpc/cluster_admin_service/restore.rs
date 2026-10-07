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

//! Restore of operator backups.

use super::*;

/// Size of the slices a live restore commits through the Raft log. A lagging
/// follower receives a batch of entries in one AppendEntries message; at
/// this size a full batch stays within [`crate::RAFT_MAX_MESSAGE_SIZE`].
pub(super) const RESTORE_CHUNK_SIZE: usize = 256 * 1024;

use crate::store::state_machine::MAX_LIVE_RESTORE_SIZE;

/// Largest backup accepted by the disaster recovery path, which holds it in
/// memory because OpenRaft installs a full in-memory snapshot.
pub(super) const MAX_DR_RESTORE_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Most the disaster recovery path reserves up front from a declared size.
pub(super) const MAX_DR_PREALLOC: u64 = 64 * 1024 * 1024;

/// How long an upload may stall between messages. It holds the restore lock
/// when it targets a running cluster.
pub(super) const RESTORE_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Reads the next upload message, giving up on a stalled client.
pub(super) async fn next_restore_message(
    stream: &mut Streaming<pb::raft::RestoreChunk>,
) -> Result<Option<pb::raft::RestoreChunk>, Status> {
    tokio::time::timeout(RESTORE_IDLE_TIMEOUT, stream.message())
        .await
        .map_err(|_| Status::deadline_exceeded("restore upload stalled"))?
}

/// Rejects an upload whose size differs from the one it declared (0 means
/// undeclared), e.g. because the client stopped reading its file early.
pub(super) fn check_declared_len(declared: u64, received: u64) -> Result<(), Status> {
    if declared != 0 && declared != received {
        return Err(Status::invalid_argument(format!(
            "upload declared {declared} bytes but {received} were received"
        )));
    }
    Ok(())
}

/// `(dek_version, utc_epoch)` from the clear-text header of a backup blob.
pub(super) fn backup_header(blob: &[u8]) -> Option<(u32, u64)> {
    let version = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?);
    let utc_epoch = u64::from_be_bytes(blob.get(4..12)?.try_into().ok()?);
    Some((version, utc_epoch))
}

impl ClusterAdminServiceImpl {
    /// Restores an uninitialized node following OpenRaft's documented
    /// restore-from-snapshot procedure: the vote is derived from the
    /// snapshot's last log id and the snapshot -- membership included -- is
    /// installed. Run it with the same backup on every node, then pass
    /// `elect` on exactly one.
    pub(super) async fn restore_uninitialized(
        &self,
        snapshot: Snapshot,
        elect: bool,
    ) -> Result<(), Status> {
        let term = snapshot
            .meta
            .last_log_id
            .as_ref()
            .map(|log_id| log_id.leader_id)
            .ok_or_else(|| {
                Status::failed_precondition(
                    "backup has no Raft log position (its cluster never committed an entry) \
                     and cannot be installed into an uninitialized node",
                )
            })?;
        let vote = <pb::raft::Vote as RaftVote>::from_leader_id(
            <LeaderId as RaftLeaderId>::new(term, self.node_id),
            true,
        );
        self.raft_node
            .install_full_snapshot(vote, snapshot)
            .await
            .map_err(|e| Status::internal(format!("backup install failed: {e}")))?;
        if elect {
            self.raft_node
                .trigger()
                .elect(false)
                .await
                .map_err(|e| Status::internal(format!("election trigger failed: {e}")))?;
        }
        Ok(())
    }

    /// Restores into an initialized cluster by committing the backup
    /// through the Raft log: it is staged in chunks as the upload arrives
    /// (the upload is never buffered here), then a single entry swaps it in
    /// on every node at the same index. Cluster membership is unchanged.
    /// Must run on the leader.
    ///
    /// Returns the `(dek_version, utc_epoch)` read from the backup header,
    /// if the first chunk was long enough to carry one.
    pub(super) async fn restore_into_cluster(
        &self,
        first: pb::raft::RestoreChunk,
        stream: &mut Streaming<pb::raft::RestoreChunk>,
    ) -> Result<Option<(u32, u64)>, Status> {
        let declared_len = first.total_len;
        let _serialized = self
            .restore_lock
            .try_lock()
            .map_err(|_| Status::failed_precondition("another restore is already in progress"))?;
        let restore_id = uuid::Uuid::new_v4().to_string();
        let mut staged = false;
        let outcome = self
            .stage_and_apply(&restore_id, declared_len, first, stream, &mut staged)
            .await;
        if outcome.is_err() && staged {
            // Best effort: the chunks that did commit are otherwise staged
            // on every node until the next restore.
            if let Err(e) = self
                .propose_restore(StoreCommand::RestoreAbort {
                    restore_id: restore_id.clone(),
                })
                .await
            {
                tracing::warn!(restore_id, error = %e, "could not discard staged restore chunks");
            }
        }
        outcome
    }

    pub(super) async fn stage_and_apply(
        &self,
        restore_id: &str,
        declared_len: u64,
        first: pb::raft::RestoreChunk,
        stream: &mut Streaming<pb::raft::RestoreChunk>,
        staged: &mut bool,
    ) -> Result<Option<(u32, u64)>, Status> {
        let mut pending: Vec<u8> = Vec::with_capacity(RESTORE_CHUNK_SIZE);
        let mut seq = 0u32;
        let mut total_len = 0u64;
        let mut header = None;
        let mut next = Some(first);
        while let Some(message) = next {
            total_len += message.data.len() as u64;
            if total_len > MAX_LIVE_RESTORE_SIZE {
                return Err(Status::resource_exhausted(
                    "backup is too large to restore into a running cluster (1 GiB limit); \
                     use the disaster recovery procedure instead",
                ));
            }
            let mut data = message.data.as_slice();
            while !data.is_empty() {
                let take = (RESTORE_CHUNK_SIZE - pending.len()).min(data.len());
                let (head, rest) = data.split_at(take);
                pending.extend_from_slice(head);
                data = rest;
                if pending.len() == RESTORE_CHUNK_SIZE {
                    self.stage_chunk(restore_id, &mut seq, &mut pending, &mut header)
                        .await?;
                    *staged = true;
                }
            }
            next = next_restore_message(stream).await?;
        }
        if !pending.is_empty() {
            self.stage_chunk(restore_id, &mut seq, &mut pending, &mut header)
                .await?;
            *staged = true;
        }
        if total_len == 0 {
            return Err(Status::invalid_argument("restore stream was empty"));
        }
        check_declared_len(declared_len, total_len)?;
        let response = self
            .propose_restore(StoreCommand::RestoreApply {
                restore_id: restore_id.to_string(),
                chunks: seq,
                total_len,
            })
            .await?;
        // The upload was not validated before it was proposed; the apply
        // does that on every node and reports a bad backup as a violation.
        if let Some(violation) = response.violations.first() {
            return Err(Status::failed_precondition(format!(
                "restore rejected by the cluster: {}",
                violation.description
            )));
        }
        Ok(header)
    }

    /// Proposes `pending` as chunk `*seq` and leaves `pending` empty.
    pub(super) async fn stage_chunk(
        &self,
        restore_id: &str,
        seq: &mut u32,
        pending: &mut Vec<u8>,
        header: &mut Option<(u32, u64)>,
    ) -> Result<(), Status> {
        if *seq == 0 {
            *header = backup_header(pending);
        }
        let data = std::mem::replace(pending, Vec::with_capacity(RESTORE_CHUNK_SIZE));
        self.propose_restore(StoreCommand::RestoreChunk {
            restore_id: restore_id.to_string(),
            seq: *seq,
            data,
        })
        .await?;
        *seq = seq
            .checked_add(1)
            .ok_or_else(|| Status::resource_exhausted("backup has too many chunks"))?;
        Ok(())
    }

    pub(super) async fn propose_restore(
        &self,
        cmd: StoreCommand,
    ) -> Result<crate::ZeroizingResponse, Status> {
        let payload =
            pb::api::CommandRequest::try_from(cmd).map_err(|e| Status::internal(e.to_string()))?;
        match self.raft_node.client_write(payload).await {
            Ok(resp) => Ok(resp.data),
            // Restore into an initialized cluster must be sent to the
            // leader; the redirect carries its address.
            Err(e) => Err(raft_write_status("Raft write failed", e)),
        }
    }
}

impl ClusterAdminServiceImpl {
    pub(super) async fn handle_restore(
        &self,
        request: Request<Streaming<pb::raft::RestoreChunk>>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let actor = require_operator(&request, &self.authz)?;
        trace!(actor, "operator restore requested");

        let mut stream = request.into_inner();
        let first = stream
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("restore stream was empty"))?;
        let elect = first.elect;
        let declared_len = first.total_len;

        let initialized = self
            .raft_node
            .is_initialized()
            .await
            .map_err(|e| Status::internal(format!("cannot determine Raft state: {e}")))?;
        if initialized && elect {
            return Err(Status::failed_precondition(
                "this node is already initialized; --elect is only valid for disaster recovery \
                 into uninitialized nodes",
            ));
        }
        if initialized {
            self.ensure_leader()?;
        }
        let limit = if initialized {
            MAX_LIVE_RESTORE_SIZE
        } else {
            MAX_DR_RESTORE_SIZE
        };
        if declared_len > limit {
            return Err(Status::resource_exhausted(format!(
                "backup of {declared_len} bytes exceeds the {limit} byte restore limit"
            )));
        }

        let (mode, utc_epoch, dek_version) = if initialized {
            let header = self.restore_into_cluster(first, &mut stream).await?;
            (
                "cluster",
                header.map(|(_, epoch)| epoch),
                header.map(|(version, _)| version),
            )
        } else {
            // The declared size is the client's word: reserve a bounded
            // amount and let the buffer grow with what actually arrives.
            let mut buf: Vec<u8> =
                Vec::with_capacity(usize::try_from(declared_len.min(MAX_DR_PREALLOC)).unwrap_or(0));
            let mut next = Some(first);
            while let Some(chunk) = next {
                if buf.len() as u64 + chunk.data.len() as u64 > limit {
                    return Err(Status::resource_exhausted(format!(
                        "restore stream exceeds the {limit} byte restore limit"
                    )));
                }
                buf.extend_from_slice(&chunk.data);
                next = next_restore_message(&mut stream).await?;
            }
            check_declared_len(declared_len, buf.len() as u64)?;
            let (snapshot, utc_epoch, dek_version) = self
                .sm
                .decode_backup_blob(&buf)
                .map_err(|e| Status::invalid_argument(format!("invalid backup blob: {e}")))?;
            // The decrypted snapshot is all that is installed.
            drop(buf);
            // Reject a backup this node cannot install before anything is
            // written.
            self.sm
                .validate_backup_payload(&snapshot.snapshot)
                .map_err(|e| Status::invalid_argument(format!("backup cannot be restored: {e}")))?;
            self.restore_uninitialized(snapshot, elect).await?;
            ("disaster_recovery", Some(utc_epoch), Some(dek_version))
        };

        let dek_ver_for_audit = self
            .current_dek
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .version;
        self.audit.emit(AuditRecord::now(
            "BACKUP_RESTORED",
            &actor,
            self.node_id,
            dek_ver_for_audit,
            serde_json::json!({
                "snapshot_utc_epoch": utc_epoch,
                "backup_dek_version": dek_version,
                "mode": mode,
            }),
        ));

        tracing::info!(
            actor,
            utc_epoch,
            dek_version,
            mode,
            "backup restore complete"
        );
        Ok(Response::new(pb::raft::AdminResponse::default()))
    }
}
