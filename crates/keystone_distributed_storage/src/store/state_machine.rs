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
//! # Fjall DB based `openraft` state machine implementation.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode, Readable};
use futures::Stream;
use futures::TryStreamExt;
use openraft::LogId;
use openraft::OptionalSend;
use openraft::RaftSnapshotBuilder;
use openraft::SnapshotMeta;
use openraft::StorageError;
use openraft::StoredMembership;
use openraft::alias::{LogIdOf, SnapshotDataOf};
use openraft::entry::RaftEntry;
use openraft::storage::EntryResponder;
use openraft::storage::RaftStateMachine;
use openraft::storage::Snapshot;
use openraft::type_config::TypeConfigExt;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;

use crate::StoreError;
use crate::TypeConfig;
use crate::protobuf as pb;

const KEY_LAST_APPLIED_LOG: &[u8] = b"last_applied_log";
const KEY_LAST_MEMBERSHIP: &[u8] = b"last_membership";

/// Snapshot file format: metadata + data stored together.
#[derive(Serialize, Deserialize)]
struct SnapshotFile {
    meta: SnapshotMeta<TypeConfig>,
    data: Vec<(Vec<u8>, Vec<u8>)>,
}

/// State machine backed by FjallDB for full persistence.
/// All application data is stored directly in the `data` column family.
/// Snapshots are persisted to the `snapshot_dir` directory.
#[derive(Clone)]
pub struct FjallStateMachine {
    db: Arc<Database>,
    meta: Keyspace,
    data: Keyspace,
    snapshot_dir: PathBuf,
}

impl FjallStateMachine {
    #[allow(clippy::result_large_err)]
    pub fn new(db: Arc<Database>, snapshot_dir: PathBuf) -> Result<Self, StoreError> {
        let meta = db.keyspace("meta", KeyspaceCreateOptions::default)?;
        let data = db.keyspace("data", KeyspaceCreateOptions::default)?;

        fs::create_dir_all(&snapshot_dir)?;

        Ok(Self {
            db,
            snapshot_dir,
            meta,
            data,
        })
    }

    pub fn data(&self) -> &Keyspace {
        &self.data
    }

    #[allow(clippy::result_large_err)]
    #[tracing::instrument(skip(self))]
    fn get_meta(
        &self,
    ) -> Result<(Option<LogId<TypeConfig>>, StoredMembership<TypeConfig>), StoreError> {
        let last_applied_log = self
            .meta
            .get(KEY_LAST_APPLIED_LOG)?
            .map(|x| deserialize(&x))
            .transpose()?;
        let last_membership = self
            .meta
            .get(KEY_LAST_MEMBERSHIP)?
            .map(|x| deserialize(&x))
            .transpose()?
            .unwrap_or_default();
        Ok((last_applied_log, last_membership))
    }
}

fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, StorageError<TypeConfig>> {
    serde_json::to_vec(value).map_err(|e| StorageError::write(TypeConfig::err_from_error(&e)))
}

fn deserialize<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, StorageError<TypeConfig>> {
    serde_json::from_slice(bytes).map_err(|e| StorageError::read(TypeConfig::err_from_error(&e)))
}

impl RaftSnapshotBuilder<TypeConfig> for Arc<FjallStateMachine> {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, io::Error> {
        //// 1. Get the last applied log ID from the snapshot view
        let (last_applied_log, last_membership) = self.get_meta()?;

        // Generate a random snapshot index.
        let snapshot_idx: u64 = rand::rng().random_range(0..1000);

        let snapshot_id = if let Some(last) = last_applied_log {
            format!(
                "{}-{}-{}",
                last.committed_leader_id(),
                last.index(),
                snapshot_idx
            )
        } else {
            format!("--{}", snapshot_idx)
        };

        let meta = SnapshotMeta {
            last_log_id: last_applied_log,
            last_membership,
            snapshot_id: snapshot_id.clone(),
        };

        tracing::trace!("snapshot metadata: {:?}", meta);

        // 2. Capture a point-in-time view of the entire database
        let snapshot = self.db.snapshot();

        // 3. Serialize all KV pairs in the 'data' keyspace from the snapshot
        let mut data_buffer = Vec::new();
        for item in snapshot.iter(&self.data) {
            let (key, value) = item
                .into_inner()
                .map_err(|e| io::Error::other(e.to_string()))?;
            data_buffer.push((key.to_vec(), value.to_vec()));
        }

        // Serialize both metadata and data together
        let snapshot_file = SnapshotFile {
            meta: meta.clone(),
            data: data_buffer.clone(),
        };

        let file_bytes = serialize(&snapshot_file).map_err(|e| {
            StorageError::write_snapshot(Some(meta.signature()), TypeConfig::err_from_error(&e))
        })?;

        // Write complete snapshot to file
        let snapshot_path = self.snapshot_dir.join(&snapshot_id);
        fs::write(&snapshot_path, &file_bytes).map_err(|e| {
            StorageError::write_snapshot(Some(meta.signature()), TypeConfig::err_from_error(&e))
        })?;

        // Return snapshot with data-only for backward compatibility with the data field
        let data_bytes = serialize(&data_buffer).map_err(|e| {
            StorageError::write_snapshot(Some(meta.signature()), TypeConfig::err_from_error(&e))
        })?;
        tracing::trace!("snapshot written to {:?}", snapshot_path);

        Ok(Snapshot {
            meta,
            //snapshot: Cursor::new(data_bytes),
            snapshot: data_bytes,
        })
    }
}

impl RaftStateMachine<TypeConfig> for Arc<FjallStateMachine> {
    type SnapshotBuilder = Self;

    #[tracing::instrument(skip(self))]
    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogIdOf<TypeConfig>>, StoredMembership<TypeConfig>), io::Error> {
        self.get_meta().map_err(|e| io::Error::other(e.to_string()))
    }

    #[tracing::instrument(skip(self))]
    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    #[tracing::instrument(skip(self))]
    async fn begin_receiving_snapshot(&mut self) -> Result<SnapshotDataOf<TypeConfig>, io::Error> {
        Ok(Vec::new())
    }

    #[tracing::instrument(skip(self))]
    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<TypeConfig>,
        snapshot: SnapshotDataOf<TypeConfig>,
    ) -> Result<(), io::Error> {
        tracing::info!(
            { snapshot_size = snapshot.len() },
            "decoding snapshot for installation"
        );

        // Deserialize snapshot data
        let snapshot_data: Vec<(Vec<u8>, Vec<u8>)> = deserialize(snapshot.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Clone data for file writing later
        let snapshot_data_clone = snapshot_data.clone();

        // Prepare metadata to restore
        let last_applied_bytes = meta
            .last_log_id
            .as_ref()
            .map(|log_id| {
                serialize(log_id)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
            })
            .transpose()?;

        let last_membership_bytes = serialize(&meta.last_membership)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let mut batch = self.db.batch();

        for current in self.data.iter() {
            if let Ok(k) = current.key() {
                batch.remove(&self.data, k);
            }
        }

        for (key, value) in snapshot_data {
            batch.insert(&self.data, key, value);
        }

        if let Some(bytes) = last_applied_bytes {
            batch.insert(&self.meta, KEY_LAST_APPLIED_LOG, bytes);
        }
        batch.insert(&self.meta, KEY_LAST_MEMBERSHIP, last_membership_bytes);

        batch
            .commit()
            .map_err(|e| io::Error::other(e.to_string()))?;

        self.db
            .persist(PersistMode::SyncAll)
            .map_err(|e| io::Error::other(e.to_string()))?;

        // Write snapshot file with metadata for get_current_snapshot
        let snapshot_file = SnapshotFile {
            meta: meta.clone(),
            data: snapshot_data_clone,
        };
        let file_bytes = serialize(&snapshot_file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let snapshot_path = self.snapshot_dir.join(&meta.snapshot_id);
        fs::write(&snapshot_path, &file_bytes)?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot<TypeConfig>>, io::Error> {
        // Find the latest snapshot file by comparing filenames lexicographically
        let mut latest_snapshot_id: Option<String> = None;

        for entry in fs::read_dir(&self.snapshot_dir)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                let snapshot_id = filename.to_string();

                // Update latest if this is the first snapshot or if it's newer
                if latest_snapshot_id
                    .as_ref()
                    .is_none_or(|current| snapshot_id > *current)
                {
                    latest_snapshot_id = Some(snapshot_id);
                }
            }
        }

        let Some(snapshot_id) = latest_snapshot_id else {
            return Ok(None);
        };

        let snapshot_path = self.snapshot_dir.join(&snapshot_id);

        // Read and deserialize snapshot file
        let file_bytes = fs::read(&snapshot_path)?;
        let snapshot_file: SnapshotFile = serde_json::from_slice(&file_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Serialize data for snapshot field
        let data_bytes = serde_json::to_vec(&snapshot_file.data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(Some(Snapshot {
            meta: snapshot_file.meta,
            snapshot: data_bytes,
        }))
    }

    #[tracing::instrument(skip(self, entries))]
    async fn apply<Strm>(&mut self, mut entries: Strm) -> Result<(), io::Error>
    where
        Strm: Stream<Item = Result<EntryResponder<TypeConfig>, io::Error>> + Unpin + OptionalSend,
    {
        let mut last_applied_log = None;
        let mut last_membership = None;
        let mut batch = self.db.batch();

        while let Some((entry, responder)) = entries.try_next().await? {
            last_applied_log = Some(entry.log_id());
            let response = if let Some(req) = entry.app_data {
                batch.insert(&self.data, req.key.as_bytes(), req.value.as_bytes());
                Some(req.value.clone())
            } else if let Some(mem) = entry.membership {
                last_membership = Some(StoredMembership::new(last_applied_log, mem.try_into()?));
                None
            } else {
                None
            };
            if let Some(responder) = responder {
                responder.send(pb::api::Response { value: response });
            }
        }
        if let Some(val) = last_membership {
            batch.insert(
                &self.meta,
                KEY_LAST_MEMBERSHIP,
                serde_json::to_vec(&val).map_err(|e| io::Error::other(e.to_string()))?,
            );
        }
        if let Some(val) = last_applied_log {
            batch.insert(
                &self.meta,
                KEY_LAST_APPLIED_LOG,
                serde_json::to_vec(&val).map_err(|e| io::Error::other(e.to_string()))?,
            );
        }

        batch
            .commit()
            .map_err(|e| io::Error::other(e.to_string()))?;

        self.db
            .persist(PersistMode::SyncAll)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(())
    }
}
