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

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode, Readable};
use futures::Stream;
use futures::TryStreamExt;
use openraft::OptionalSend;
use openraft::RaftSnapshotBuilder;
use openraft::SnapshotMeta;
use openraft::StorageError;
use openraft::alias::SnapshotMetaOf;
use openraft::alias::SnapshotOf;
use openraft::alias::StoredMembershipOf;
use openraft::alias::{LogIdOf, SnapshotDataOf};
use openraft::entry::RaftEntry;
use openraft::storage::EntryResponder;
use openraft::storage::RaftStateMachine;
use openraft::storage::Snapshot;
use openraft::type_config::TypeConfigExt;
use openstack_keystone_storage_crypto::{DekEpoch, state_decrypt, state_encrypt};
use rand::RngExt;
use serde::Deserialize;
use serde::Serialize;

use crate::DataTier;
use crate::StoreError;
use crate::TypeConfig;
use crate::protobuf as pb;
use crate::protobuf::api::response::Violation;
use crate::store_command::*;
use crate::types::Metadata;

const KEY_LAST_APPLIED_LOG: &[u8] = b"last_applied_log";
const KEY_LAST_MEMBERSHIP: &[u8] = b"last_membership";

/// Fjall meta key prefix for persisted quarantine markers.
const QUARANTINE_META_PREFIX: &str = "_meta:quarantine:";

/// Sliding window for GCM failure counting.
const QUARANTINE_WINDOW: Duration = Duration::from_secs(60);

/// Number of GCM failures within `QUARANTINE_WINDOW` that triggers quarantine.
const QUARANTINE_THRESHOLD: usize = 3;

/// Per-partition GCM decryption failure tracker with automatic quarantine.
///
/// A partition accumulates failure `Instant`s in a 60-second sliding window.
/// At three failures the partition is marked quarantined and the marker is
/// persisted to Fjall `meta` so it survives restarts.
///
/// Quarantine can be cleared by an operator via `FjallStateMachine::clear_quarantine`.
#[derive(Default)]
struct QuarantineTracker {
    failures: Mutex<HashMap<String, VecDeque<Instant>>>,
    quarantined: Mutex<HashSet<String>>,
}

impl QuarantineTracker {
    /// Initialise from Fjall meta, loading any persisted quarantine markers.
    fn from_meta(meta: &Keyspace) -> Result<Self, crate::StoreError> {
        let mut quarantined = HashSet::new();
        for item in meta.prefix(QUARANTINE_META_PREFIX.as_bytes()) {
            let (key_bytes, _) = item.into_inner()?;
            if let Ok(key_str) = String::from_utf8(key_bytes.to_vec()) {
                if let Some(partition) = key_str.strip_prefix(QUARANTINE_META_PREFIX) {
                    quarantined.insert(partition.to_string());
                    tracing::error!(
                        partition,
                        "SECURITY: partition is quarantined (loaded from persistent state)"
                    );
                }
            }
        }
        Ok(Self {
            failures: Mutex::new(HashMap::new()),
            quarantined: Mutex::new(quarantined),
        })
    }

    fn is_quarantined(&self, partition: &str) -> bool {
        self.quarantined
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(partition)
    }

    /// Records a GCM failure for a partition; returns `true` if newly quarantined.
    fn record_failure(&self, partition: &str) -> bool {
        if self.is_quarantined(partition) {
            return false;
        }

        let now = Instant::now();
        let mut failures = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        let window = failures.entry(partition.to_string()).or_default();

        // Evict timestamps outside the sliding window.
        window.retain(|&t| now.duration_since(t) < QUARANTINE_WINDOW);
        window.push_back(now);
        let count = window.len();

        match count {
            1 => {
                tracing::warn!(
                    partition,
                    "SECURITY: GCM tag verification failure (1/{QUARANTINE_THRESHOLD}); \
                     possible data corruption or tampering"
                );
            }
            2 => {
                tracing::error!(
                    partition,
                    "SECURITY: GCM tag verification failure (2/{QUARANTINE_THRESHOLD}); \
                     possible active attack"
                );
            }
            _ => {
                tracing::error!(
                    partition,
                    count,
                    "SECURITY: GCM failures reached threshold — quarantining partition"
                );
                drop(failures);
                self.quarantined
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(partition.to_string());
                return true;
            }
        }
        false
    }

    /// Clears quarantine state for a partition (operator-initiated recovery).
    fn clear(&self, partition: &str) {
        self.quarantined
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(partition);
        self.failures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(partition);
    }
}

/// Snapshot file format: metadata + data stored together.
#[derive(Serialize, Deserialize)]
struct SnapshotFile {
    meta: SnapshotMetaOf<TypeConfig>,
    data: Vec<(Vec<u8>, Vec<u8>)>,
}

/// State machine backed by FjallDB for full persistence.
///
/// All application data is AES-256-GCM encrypted at rest via `state_encrypt`
/// before writing to the `data` keyspace.  The `dek` field holds the current
/// DEK epoch; encryption uses the `StateDek` sub-key derived from it.
#[derive(Clone)]
pub struct FjallStateMachine {
    db: Arc<Database>,
    meta: Keyspace,
    data: Keyspace,
    index: Keyspace,
    snapshot_dir: PathBuf,
    dek: Arc<DekEpoch>,
    quarantine: Arc<QuarantineTracker>,
}

impl FjallStateMachine {
    #[allow(clippy::result_large_err)]
    /// Create a new `FjallStateMachine`.
    ///
    /// # Parameters
    /// - `db`: Database instance.
    /// - `snapshot_dir`: Directory to store snapshots.
    /// - `dek`: Data Encryption Key epoch for state encryption.
    ///
    /// # Returns
    /// A `Result` containing the `FjallStateMachine`, or a `StoreError`.
    pub fn new(
        db: Arc<Database>,
        snapshot_dir: PathBuf,
        dek: Arc<DekEpoch>,
    ) -> Result<Self, StoreError> {
        let meta = db.keyspace("meta", KeyspaceCreateOptions::default)?;
        let data = db.keyspace("data", KeyspaceCreateOptions::default)?;
        let index = db.keyspace("index", KeyspaceCreateOptions::default)?;

        fs::create_dir_all(&snapshot_dir)?;

        let quarantine = Arc::new(QuarantineTracker::from_meta(&meta)?);

        Ok(Self {
            db,
            snapshot_dir,
            meta,
            data,
            index,
            dek,
            quarantine,
        })
    }

    /// Get the database handle.
    pub fn db(&self) -> &Arc<Database> {
        &self.db
    }

    /// Get the data `keyspace` handle.
    pub fn data(&self) -> &Keyspace {
        &self.data
    }

    /// Get the index `keyspace` handle.
    pub fn index(&self) -> &Keyspace {
        &self.index
    }

    /// Get the metadata `keyspace` handle.
    pub fn meta(&self) -> &Keyspace {
        &self.meta
    }

    /// Get the Fjall `keyspace` handle by name.
    pub fn keyspace<S: AsRef<str>>(&self, name: S) -> Result<Keyspace, StoreError> {
        Ok(match name.as_ref() {
            "data" => self.data.clone(),
            "meta" => self.meta.clone(),
            "index" => self.index.clone(),
            other => self
                .db
                .keyspace(other.as_ref(), KeyspaceCreateOptions::default)?,
        })
    }

    /// Decrypt state bytes previously written by [`state_encrypt`].
    ///
    /// `tier`, `keyspace`, and `pk` must match the values used at write time;
    /// any mismatch causes GCM tag verification to fail and returns an error.
    ///
    /// Returns `StoreError::Quarantined` if the keyspace partition is quarantined.
    /// GCM tag failures are tracked; three failures within 60 s quarantine the
    /// partition and persist the marker to Fjall meta for restart durability.
    pub fn decrypt_state(
        &self,
        stored: &[u8],
        tier: u8,
        keyspace: &[u8],
        pk: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        let partition = String::from_utf8_lossy(keyspace).into_owned();

        if self.quarantine.is_quarantined(&partition) {
            return Err(StoreError::Quarantined(partition));
        }

        match state_decrypt(self.dek.state_dek(), stored, tier, keyspace, pk) {
            Ok((plaintext, _next_version)) => Ok(plaintext.to_vec()),
            Err(e) => {
                if matches!(e, openstack_keystone_storage_crypto::CryptoError::AesDecrypt) {
                    if self.quarantine.record_failure(&partition) {
                        // Newly quarantined — persist so the marker survives restarts.
                        let key = format!("{QUARANTINE_META_PREFIX}{partition}");
                        // Best-effort: non-fatal if Fjall write fails here.
                        let _ = self.meta.insert(key, b"1");
                    }
                }
                Err(StoreError::Crypto { source: e })
            }
        }
    }

    /// Returns `true` if the given keyspace partition is currently quarantined.
    pub fn is_quarantined(&self, partition: &str) -> bool {
        self.quarantine.is_quarantined(partition)
    }

    /// Clears quarantine for a partition (operator-initiated recovery).
    ///
    /// Removes the quarantine marker from Fjall meta so the partition becomes
    /// accessible again after a restart as well.
    pub fn clear_quarantine(&self, partition: &str) -> Result<(), StoreError> {
        self.quarantine.clear(partition);
        let key = format!("{QUARANTINE_META_PREFIX}{partition}");
        self.meta.remove(key)?;
        Ok(())
    }

    /// Encrypt and write state bytes for a given key.
    ///
    /// Reads the current encrypted record (if present) to extract the stored
    /// version, increments it, then calls `state_encrypt` with the new version.
    ///
    /// Returns `StoreError::Quarantined` if the keyspace partition is quarantined.
    fn encrypt_and_store(
        &self,
        ks: &Keyspace,
        key: &[u8],
        keyspace: &[u8],
        tier: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        let partition = String::from_utf8_lossy(keyspace).into_owned();
        if self.quarantine.is_quarantined(&partition) {
            return Err(StoreError::Quarantined(partition));
        }

        // Read existing version (0 for new keys).
        let next_version = if let Some(existing) = ks.get(key)? {
            state_decrypt(self.dek.state_dek(), existing.as_ref(), tier, keyspace, key)
                .map(|(_, v)| v)
                .unwrap_or(0)
        } else {
            0
        };

        let encrypted =
            state_encrypt(self.dek.state_dek(), plaintext, tier, keyspace, key, next_version)?;
        Ok(encrypted)
    }

    #[allow(clippy::result_large_err)]
    #[tracing::instrument(skip(self))]
    fn get_meta(
        &self,
    ) -> Result<(Option<LogIdOf<TypeConfig>>, StoredMembershipOf<TypeConfig>), StoreError> {
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
    rmp_serde::to_vec(value).map_err(|e| StorageError::write(TypeConfig::err_from_error(&e)))
}

fn deserialize<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, StorageError<TypeConfig>> {
    rmp_serde::from_slice(bytes).map_err(|e| StorageError::read(TypeConfig::err_from_error(&e)))
}

impl RaftSnapshotBuilder<TypeConfig> for Arc<FjallStateMachine> {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn build_snapshot(&mut self) -> Result<SnapshotOf<TypeConfig>, io::Error> {
        let (last_applied_log, last_membership) = self.get_meta()?;

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

        let snapshot = self.db.snapshot();

        let mut data_buffer = Vec::new();
        for item in snapshot.iter(&self.data) {
            let (key, value) = item
                .into_inner()
                .map_err(|e| io::Error::other(e.to_string()))?;
            data_buffer.push((key.to_vec(), value.to_vec()));
        }

        let snapshot_file = SnapshotFile {
            meta: meta.clone(),
            data: data_buffer.clone(),
        };

        let file_bytes = serialize(&snapshot_file).map_err(|e| {
            StorageError::<TypeConfig>::write_snapshot(
                Some(meta.signature()),
                TypeConfig::err_from_error(&e),
            )
        })?;

        let snapshot_path = self.snapshot_dir.join(&snapshot_id);
        fs::write(&snapshot_path, &file_bytes).map_err(|e| {
            StorageError::<TypeConfig>::write_snapshot(
                Some(meta.signature()),
                TypeConfig::err_from_error(&e),
            )
        })?;

        let data_bytes = serialize(&data_buffer).map_err(|e| {
            StorageError::<TypeConfig>::write_snapshot(
                Some(meta.signature()),
                TypeConfig::err_from_error(&e),
            )
        })?;
        tracing::trace!("snapshot written to {:?}", snapshot_path);

        Ok(Snapshot {
            meta,
            snapshot: data_bytes,
        })
    }
}

impl RaftStateMachine<TypeConfig> for Arc<FjallStateMachine> {
    type SnapshotBuilder = Self;

    #[tracing::instrument(skip(self))]
    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogIdOf<TypeConfig>>, StoredMembershipOf<TypeConfig>), io::Error> {
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
        meta: &SnapshotMetaOf<TypeConfig>,
        snapshot: SnapshotDataOf<TypeConfig>,
    ) -> Result<(), io::Error> {
        tracing::info!(
            { snapshot_size = snapshot.len() },
            "decoding snapshot for installation"
        );

        let snapshot_data: Vec<(Vec<u8>, Vec<u8>)> = deserialize(snapshot.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let snapshot_data_clone = snapshot_data.clone();

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
    async fn get_current_snapshot(&mut self) -> Result<Option<SnapshotOf<TypeConfig>>, io::Error> {
        let mut latest_snapshot_id: Option<String> = None;

        for entry in fs::read_dir(&self.snapshot_dir)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                let snapshot_id = filename.to_string();

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

        let file_bytes = fs::read(&snapshot_path)?;
        let snapshot_file: SnapshotFile = rmp_serde::from_slice(&file_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let data_bytes = rmp_serde::to_vec(&snapshot_file.data)
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
        let mut last_membership = None;

        while let Some((entry, responder)) = entries.try_next().await? {
            let last_applied_log = entry.log_id();
            let mut batch = self.db.batch();
            let mut has_violations = false;

            let response = if let Some(store_req) = entry.app_data {
                match StoreCommand::unpack(&store_req)? {
                    StoreCommand::Transaction(mutations) => {
                        let mut violations: Vec<Violation> = Vec::new();
                        for mutation in mutations {
                            match mutation {
                                MutationInner::Remove {
                                    key,
                                    keyspace,
                                    expected_revision,
                                } => {
                                    if keyspace == "meta" && key == KEY_LAST_MEMBERSHIP
                                        || key == KEY_LAST_APPLIED_LOG
                                    {
                                        return Err(io::Error::other(
                                            "not allowed to delete system data",
                                        ));
                                    }

                                    if let Some(expected_revision) = expected_revision {
                                        let curr_meta = self
                                            .meta()
                                            .get(&key)
                                            .map_err(|e| io::Error::other(e.to_string()))?
                                            .map(|x| Metadata::unpack(x.as_ref()))
                                            .transpose()
                                            .map_err(|e| io::Error::other(e.to_string()))?;
                                        if curr_meta
                                            .as_ref()
                                            .is_none_or(|x| x.revision != expected_revision)
                                        {
                                            violations.push(Violation {
                                                r#type: "CONFLICT".to_string(),
                                                subject: String::from_utf8_lossy(&key).to_string(),
                                                description: format!(
                                                    "Current revision is {:?} while {} was expected",
                                                    curr_meta.map(|x| x.revision),
                                                    expected_revision,
                                                ),
                                            });
                                        }
                                    }

                                    let ks = &self.keyspace(keyspace)?;
                                    batch.remove(ks, key.clone());
                                    batch.remove(&self.meta, key.clone());
                                }
                                MutationInner::RemoveIndex { key } => {
                                    batch.remove(&self.index, key.clone());
                                }
                                MutationInner::Set {
                                    key,
                                    keyspace,
                                    cipher,
                                    metadata,
                                    tier,
                                    expected_revision,
                                } => {
                                    if keyspace == "meta" && key == KEY_LAST_MEMBERSHIP
                                        || key == KEY_LAST_APPLIED_LOG
                                    {
                                        return Err(io::Error::other(
                                            "not allowed to overwrite system data",
                                        ));
                                    }

                                    if let Some(expected_revision) = expected_revision {
                                        let curr_meta = self
                                            .meta()
                                            .get(&key)
                                            .map_err(|e| io::Error::other(e.to_string()))?
                                            .map(|x| Metadata::unpack(x.as_ref()))
                                            .transpose()
                                            .map_err(|e| io::Error::other(e.to_string()))?;
                                        if curr_meta
                                            .as_ref()
                                            .is_none_or(|x| x.revision != expected_revision)
                                        {
                                            violations.push(Violation {
                                                r#type: "CONFLICT".to_string(),
                                                subject: String::from_utf8_lossy(&key).to_string(),
                                                description: format!(
                                                    "Current revision is {:?} while {} was expected",
                                                    curr_meta.map(|x| x.revision),
                                                    expected_revision,
                                                ),
                                            });
                                        }
                                    }

                                    let ks = self
                                        .keyspace(&keyspace)
                                        .map_err(|e| io::Error::other(e.to_string()))?;
                                    match self.encrypt_and_store(
                                        &ks,
                                        &key,
                                        keyspace.as_bytes(),
                                        tier,
                                        &cipher,
                                    ) {
                                        Ok(encrypted) => {
                                            batch.insert(&ks, key.clone(), encrypted);
                                            let mut meta_with_tier = metadata.clone();
                                            meta_with_tier.tier = DataTier::from(tier);
                                            batch.insert(
                                                &self.meta,
                                                key.clone(),
                                                meta_with_tier
                                                    .pack()
                                                    .map_err(|e| io::Error::other(e.to_string()))?,
                                            );
                                        }
                                        Err(StoreError::Quarantined(p)) => {
                                            violations.push(Violation {
                                                r#type: "QUARANTINED".to_string(),
                                                subject: String::from_utf8_lossy(&key).to_string(),
                                                description: format!(
                                                    "partition '{p}' is quarantined"
                                                ),
                                            });
                                        }
                                        Err(e) => {
                                            return Err(io::Error::other(e.to_string()));
                                        }
                                    }
                                }
                                MutationInner::CreateIfAbsent {
                                    key,
                                    keyspace,
                                    cipher,
                                    metadata,
                                    tier,
                                } => {
                                    let exists = self
                                        .meta()
                                        .get(&key)
                                        .map_err(|e| io::Error::other(e.to_string()))?
                                        .is_some();
                                    if exists {
                                        violations.push(Violation {
                                            r#type: "CONFLICT".to_string(),
                                            subject: String::from_utf8_lossy(&key).to_string(),
                                            description: "key already exists (create_if_absent)"
                                                .to_string(),
                                        });
                                    }

                                    let ks = self
                                        .keyspace(&keyspace)
                                        .map_err(|e| io::Error::other(e.to_string()))?;
                                    match self.encrypt_and_store(
                                        &ks,
                                        &key,
                                        keyspace.as_bytes(),
                                        tier,
                                        &cipher,
                                    ) {
                                        Ok(encrypted) => {
                                            batch.insert(&ks, key.clone(), encrypted);
                                            let mut meta_with_tier = metadata.clone();
                                            meta_with_tier.tier = DataTier::from(tier);
                                            batch.insert(
                                                &self.meta,
                                                key.clone(),
                                                meta_with_tier
                                                    .pack()
                                                    .map_err(|e| io::Error::other(e.to_string()))?,
                                            );
                                        }
                                        Err(StoreError::Quarantined(p)) => {
                                            violations.push(Violation {
                                                r#type: "QUARANTINED".to_string(),
                                                subject: String::from_utf8_lossy(&key).to_string(),
                                                description: format!(
                                                    "partition '{p}' is quarantined"
                                                ),
                                            });
                                        }
                                        Err(e) => {
                                            return Err(io::Error::other(e.to_string()));
                                        }
                                    }
                                }
                                MutationInner::SetIndex { key } => {
                                    batch.insert(&self.index, key, vec![]);
                                }
                            }
                        }
                        has_violations = !violations.is_empty();
                        (None, violations)
                    }
                }
            } else if let Some(mem) = entry.membership {
                last_membership = Some(StoredMembershipOf::<TypeConfig>::new(
                    Some(last_applied_log),
                    mem.try_into()?,
                ));
                (None, vec![])
            } else {
                (None, vec![])
            };

            if !has_violations {
                batch
                    .commit()
                    .map_err(|e| io::Error::other(e.to_string()))?;
            }

            self.meta
                .insert(
                    KEY_LAST_APPLIED_LOG,
                    rmp_serde::to_vec(&last_applied_log)
                        .map_err(|e| io::Error::other(e.to_string()))?,
                )
                .map_err(|e| io::Error::other(e.to_string()))?;

            self.db
                .persist(PersistMode::SyncAll)
                .map_err(|e| io::Error::other(e.to_string()))?;

            if let Some(responder) = responder {
                responder.send(pb::api::Response {
                    value: response.0,
                    violations: response.1,
                });
            }
        }

        let mut meta_batch = self.db.batch();
        if let Some(val) = last_membership {
            meta_batch.insert(
                &self.meta,
                KEY_LAST_MEMBERSHIP,
                rmp_serde::to_vec(&val).map_err(|e| io::Error::other(e.to_string()))?,
            );
        }
        meta_batch
            .commit()
            .map_err(|e| io::Error::other(e.to_string()))?;

        self.db
            .persist(PersistMode::SyncAll)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(())
    }
}
