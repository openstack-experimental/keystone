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

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
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
use openstack_keystone_storage_crypto::{
    DekEpoch, KekProvider, LockedKey, backup_decrypt, backup_encrypt, state_decrypt, state_encrypt,
};
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

/// Maximum per-key write version before a DEK rotation is required (ADR 0016-v2
/// §10).
const WRITE_RATE_THRESHOLD: u32 = 1u32 << 30;
/// Warn when per-key write count reaches 90% of the threshold.
const WRITE_RATE_WARN_THRESHOLD: u32 = WRITE_RATE_THRESHOLD / 10 * 9;

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
/// Quarantine can be cleared by an operator via
/// `FjallStateMachine::clear_quarantine`.
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
            if let Ok(key_str) = String::from_utf8(key_bytes.to_vec())
                && let Some(partition) = key_str.strip_prefix(QUARANTINE_META_PREFIX)
            {
                quarantined.insert(partition.to_string());
                tracing::error!(
                    partition,
                    "SECURITY: partition is quarantined (loaded from persistent state)"
                );
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

    /// Records a GCM failure for a partition; returns `true` if newly
    /// quarantined.
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

/// Fjall meta key prefix for retired DEK epochs.
const DEK_RETIRED_PREFIX: &str = "_meta:dek:retired:";
/// Fjall meta key for the current wrapped DEK.
const META_DEK_CURRENT: &[u8] = b"_meta:dek:current";
/// Fjall meta key prefix for pending emergency rotations.
const PENDING_ROTATION_PREFIX: &str = "_meta:rotation:pending:";
/// Dual-control confirmation window in seconds (5 minutes).
pub const PENDING_ROTATION_TTL_SECS: u64 = 300;

/// Maximum number of revoked DEK versions tracked in memory.
///
/// Revoked versions accumulate only on emergency rotations.  Exceeding this
/// cap is operationally impossible under normal conditions (it would require
/// more than 1024 security incidents), but the cap prevents unbounded growth
/// and triggers an ERROR log so operators can investigate.
const MAX_REVOKED_DEKS: usize = 1024;

/// Load any pending emergency rotations from Fjall meta on startup.
///
/// Entries that are already expired are logged and skipped — they cannot be
/// confirmed and will be cleaned up on the next `CreatePendingRotation`.
pub fn load_pending_rotations(
    meta: &Keyspace,
) -> Result<HashMap<String, PendingRotation>, crate::StoreError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut map = HashMap::new();
    for item in meta.prefix(PENDING_ROTATION_PREFIX.as_bytes()) {
        let (_, value_bytes) = item.into_inner()?;
        match rmp_serde::from_slice::<PendingRotation>(&value_bytes) {
            Ok(entry) => {
                if entry.expires_at <= now {
                    tracing::info!(
                        rotation_id = %entry.rotation_id,
                        "skipping expired pending rotation on startup"
                    );
                    continue;
                }
                map.insert(entry.rotation_id.clone(), entry);
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to deserialise pending rotation entry");
            }
        }
    }
    Ok(map)
}

/// State machine backed by FjallDB for full persistence.
///
/// All application data is AES-256-GCM encrypted at rest via `state_encrypt`
/// before writing to the `data` keyspace.  The `dek` field holds the current
/// DEK epoch; encryption uses the `StateDek` sub-key derived from it.
///
/// `old_dek` is set during a DEK rotation transition.  Reads that fail with the
/// current DEK automatically fall back to `old_dek` so data written before the
/// rotation completes remains readable until background re-encryption finishes.
#[derive(Clone)]
pub struct FjallStateMachine {
    db: Arc<Database>,
    meta: Keyspace,
    data: Keyspace,
    index: Keyspace,
    snapshot_dir: PathBuf,
    /// Current active DEK epoch (shared with FjallLogStore via Arc).
    dek: Arc<RwLock<Arc<DekEpoch>>>,
    /// Retired DEK epochs held during re-encryption transition (shared with
    /// FjallLogStore).
    old_deks: Arc<Mutex<BTreeMap<u32, Arc<DekEpoch>>>>,
    /// Revoked DEK versions — shared with FjallLogStore for immediate rejection
    /// (H3).
    revoked_deks: Arc<Mutex<HashSet<u32>>>,
    /// Key Encryption Key used to unwrap new DEKs on InstallDek apply.
    kek: Arc<dyn KekProvider>,
    /// Channel to trigger background re-encryption after DEK rotation.
    reencrypt_tx: tokio::sync::mpsc::Sender<Arc<DekEpoch>>,
    quarantine: Arc<QuarantineTracker>,
    /// Pending emergency DEK rotations awaiting dual-control confirmation.
    /// Shared with `ClusterAdminServiceImpl` so the gRPC handler can inspect
    /// the map without going through Raft.
    pub pending_rotations: Arc<Mutex<HashMap<String, PendingRotation>>>,
}

impl FjallStateMachine {
    #[allow(clippy::result_large_err)]
    /// Create a new `FjallStateMachine`.
    ///
    /// # Parameters
    /// - `db`: Database instance.
    /// - `snapshot_dir`: Directory to store snapshots.
    /// - `dek`: Shared current DEK epoch (also held by `FjallLogStore`).
    /// - `kek`: Key Encryption Key used to unwrap new DEKs on `InstallDek`.
    /// - `reencrypt_tx`: Channel for signalling the background re-encryption
    ///   task with the old DEK epoch that needs re-encryption.
    ///
    /// # Returns
    /// A `Result` containing the `FjallStateMachine`, or a `StoreError`.
    pub fn new(
        db: Arc<Database>,
        snapshot_dir: PathBuf,
        dek: Arc<RwLock<Arc<DekEpoch>>>,
        old_deks: Arc<Mutex<BTreeMap<u32, Arc<DekEpoch>>>>,
        revoked_deks: Arc<Mutex<HashSet<u32>>>,
        kek: Arc<dyn KekProvider>,
        reencrypt_tx: tokio::sync::mpsc::Sender<Arc<DekEpoch>>,
        pending_rotations: Arc<Mutex<HashMap<String, PendingRotation>>>,
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
            old_deks,
            revoked_deks,
            kek,
            reencrypt_tx,
            quarantine,
            pending_rotations,
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
    /// Returns `StoreError::Quarantined` if the keyspace partition is
    /// quarantined. GCM tag failures are tracked; three failures within 60
    /// s quarantine the partition and persist the marker to Fjall meta for
    /// restart durability.
    ///
    /// During DEK rotation, if decryption with the current DEK fails the method
    /// transparently retries with the previous epoch (`old_dek`) to serve reads
    /// of keys not yet re-encrypted.
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

        let result = {
            let guard = self.dek.read().unwrap_or_else(|p| p.into_inner());
            state_decrypt(guard.state_dek(), stored, tier, keyspace, pk)
        };

        match result {
            Ok((plaintext, _next_version)) => Ok(plaintext.to_vec()),
            Err(openstack_keystone_storage_crypto::CryptoError::AesDecrypt) => {
                // ALWAYS record failure first, even if retired DEK succeeds (M6 fix).
                // The retired DEK fallback is only for reading pre-rotation data,
                // but the GCM failure with the current DEK still counts toward
                // quarantine threshold.
                let failed = self.quarantine.record_failure(&partition);

                // Try retired DEK epochs if in a rotation transition.
                let old_map = self.old_deks.lock().unwrap_or_else(|p| p.into_inner());
                for (_, old) in old_map.iter() {
                    if let Ok((pt, _)) = state_decrypt(old.state_dek(), stored, tier, keyspace, pk)
                    {
                        tracing::warn!(
                            partition,
                            epoch_version = old.version,
                            "record decrypted with retired DEK epoch — re-encryption required"
                        );
                        return Ok(pt.to_vec());
                    }
                }
                drop(old_map);

                // Persist quarantine marker if threshold was reached.
                if failed {
                    let key = format!("{QUARANTINE_META_PREFIX}{partition}");
                    let _ = self.meta.insert(key, b"1");
                }
                Err(StoreError::Crypto {
                    source: openstack_keystone_storage_crypto::CryptoError::AesDecrypt,
                })
            }
            Err(e) => Err(StoreError::Crypto { source: e }),
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
    /// Returns `StoreError::Quarantined` if the keyspace partition is
    /// quarantined.
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
            let guard = self.dek.read().unwrap_or_else(|p| p.into_inner());
            state_decrypt(guard.state_dek(), existing.as_ref(), tier, keyspace, key)
                .map(|(_, v)| v)
                .unwrap_or(0)
        } else {
            0
        };

        // Enforce per-record write rate limit (ADR 0016-v2 §10 / invariant 9).
        if next_version >= WRITE_RATE_THRESHOLD {
            let key_str = String::from_utf8_lossy(key).into_owned();
            tracing::error!(
                key = %key_str,
                version = next_version,
                threshold = WRITE_RATE_THRESHOLD,
                "CRITICAL: per-record write rate threshold reached; DEK rotation required",
            );
            return Err(StoreError::WriteRateExceeded(key_str, next_version));
        } else if next_version >= WRITE_RATE_WARN_THRESHOLD {
            tracing::warn!(
                key = %String::from_utf8_lossy(key),
                version = next_version,
                threshold = WRITE_RATE_THRESHOLD,
                "per-record write count at 90% of threshold; schedule DEK rotation",
            );
        }

        let encrypted = {
            let guard = self.dek.read().unwrap_or_else(|p| p.into_inner());
            state_encrypt(
                guard.state_dek(),
                plaintext,
                tier,
                keyspace,
                key,
                next_version,
            )?
        };
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

/// Decrypt and deserialize a snapshot file from disk.
///
/// On-disk format:
/// `[dek_version_u32_BE; 4] ++ [utc_epoch_u64_BE; 8] ++
/// backup_encrypt(rmp_serde(SnapshotFile))`.
fn decrypt_snapshot_file(
    disk_bytes: &[u8],
    current_dek: &std::sync::Arc<std::sync::RwLock<std::sync::Arc<DekEpoch>>>,
    old_deks: &std::sync::Arc<std::sync::Mutex<BTreeMap<u32, std::sync::Arc<DekEpoch>>>>,
) -> Result<SnapshotFile, crate::StoreError> {
    use openstack_keystone_storage_crypto::dek::BackupDek;

    const HEADER_LEN: usize = 4 + 8; // version + epoch
    if disk_bytes.len() < HEADER_LEN {
        return Err(crate::StoreError::Other(eyre::eyre!(
            "snapshot file too short: {} bytes",
            disk_bytes.len()
        )));
    }
    let dek_version = u32::from_be_bytes(
        disk_bytes[..4]
            .try_into()
            .map_err(|_| crate::StoreError::Other(eyre::eyre!("invalid snapshot version")))?,
    );
    let utc_epoch = u64::from_be_bytes(
        disk_bytes[4..12]
            .try_into()
            .map_err(|_| crate::StoreError::Other(eyre::eyre!("invalid snapshot epoch")))?,
    );
    let encrypted = &disk_bytes[HEADER_LEN..];

    let try_decrypt = |epoch: &DekEpoch, counter: u64| -> Option<Vec<u8>> {
        if epoch.version != dek_version {
            return None;
        }
        let bdek = BackupDek::from_raw(*epoch.backup_dek().as_bytes());
        backup_decrypt(&bdek, encrypted, dek_version, utc_epoch, counter)
            .ok()
            .map(|z| z.to_vec())
    };

    let file_bytes = {
        let guard = current_dek.read().unwrap_or_else(|p| p.into_inner());
        (0u64..1024).find_map(|c| try_decrypt(&guard, c))
    }
    .or_else(|| {
        let old = old_deks.lock().unwrap_or_else(|p| p.into_inner());
        old.values()
            .flat_map(|epoch| (0u64..1024).filter_map(move |c| try_decrypt(epoch, c)))
            .next()
    })
    .ok_or_else(|| {
        crate::StoreError::Other(eyre::eyre!(
            "no DEK epoch matching snapshot version {dek_version}"
        ))
    })?;

    rmp_serde::from_slice(&file_bytes)
        .map_err(|e| crate::StoreError::Other(eyre::eyre!("snapshot deserialize: {e}")))
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

        // Encrypt snapshot file at rest with BackupDek (ADR §7).
        let (dek_version, backup_dek_ref, counter) = {
            let guard = self.dek.read().unwrap_or_else(|p| p.into_inner());
            (
                guard.version,
                guard.backup_dek().as_bytes().to_owned(),
                guard.next_backup_counter(),
            )
        };
        use openstack_keystone_storage_crypto::dek::BackupDek;
        let bdek = BackupDek::from_raw(backup_dek_ref);
        let utc_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let encrypted = backup_encrypt(&bdek, &file_bytes, dek_version, utc_epoch, counter)
            .map_err(|e| {
                StorageError::<TypeConfig>::write_snapshot(
                    Some(meta.signature()),
                    TypeConfig::err_from_error(&e),
                )
            })?;
        // On-disk: [dek_version_u32_BE; 4] ++ [utc_epoch_u64_BE; 8] ++ encrypted_blob
        let mut disk_bytes = Vec::with_capacity(12 + encrypted.len());
        disk_bytes.extend_from_slice(&dek_version.to_be_bytes());
        disk_bytes.extend_from_slice(&utc_epoch.to_be_bytes());
        disk_bytes.extend_from_slice(&encrypted);

        let snapshot_path = self.snapshot_dir.join(&snapshot_id);
        fs::write(&snapshot_path, &disk_bytes).map_err(|e| {
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

        // Encrypt the snapshot file at rest with the current BackupDek.
        let (dek_version, backup_dek_ref, counter) = {
            let guard = self.dek.read().unwrap_or_else(|p| p.into_inner());
            (
                guard.version,
                guard.backup_dek().as_bytes().to_owned(),
                guard.next_backup_counter(),
            )
        };
        use openstack_keystone_storage_crypto::dek::BackupDek;
        let bdek = BackupDek::from_raw(backup_dek_ref);
        let utc_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let encrypted = backup_encrypt(&bdek, &file_bytes, dek_version, utc_epoch, counter)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let mut disk_bytes = Vec::with_capacity(12 + encrypted.len());
        disk_bytes.extend_from_slice(&dek_version.to_be_bytes());
        disk_bytes.extend_from_slice(&utc_epoch.to_be_bytes());
        disk_bytes.extend_from_slice(&encrypted);

        let snapshot_path = self.snapshot_dir.join(&meta.snapshot_id);
        fs::write(&snapshot_path, &disk_bytes)?;

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

        let disk_bytes = fs::read(&snapshot_path)?;
        let snapshot_file = decrypt_snapshot_file(&disk_bytes, &self.dek, &self.old_deks)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let data_bytes = rmp_serde::to_vec(&snapshot_file.data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(Some(Snapshot {
            meta: snapshot_file.meta,
            snapshot: data_bytes,
        }))
    }

    #[tracing::instrument(skip(self, entries))]
    async fn apply<Strm>(&mut self, entries: Strm) -> Result<(), io::Error>
    where
        Strm: Stream<Item = Result<EntryResponder<TypeConfig>, io::Error>> + Unpin + OptionalSend,
    {
        let mut last_membership = None;
        let mut entries = entries;

        while let Some((entry, responder)) = entries.try_next().await? {
            let last_applied_log = entry.log_id();
            let mut batch = self.db.batch();
            let mut has_violations = false;
            let mut pending_dek_swap: Option<(Arc<DekEpoch>, bool)> = None;

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
                                        Err(StoreError::WriteRateExceeded(k, v)) => {
                                            violations.push(Violation {
                                                r#type: "WRITE_RATE_EXCEEDED".to_string(),
                                                subject: k,
                                                description: format!(
                                                    "write version {v} reached threshold \
                                                     {WRITE_RATE_THRESHOLD}; DEK rotation required"
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
                                        Err(StoreError::WriteRateExceeded(k, v)) => {
                                            violations.push(Violation {
                                                r#type: "WRITE_RATE_EXCEEDED".to_string(),
                                                subject: k,
                                                description: format!(
                                                    "write version {v} reached threshold \
                                                     {WRITE_RATE_THRESHOLD}; DEK rotation required"
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
                                MutationInner::ClearQuarantine { partition } => {
                                    // Clear in-memory tracker first so reads are
                                    // unblocked as soon as the batch commits.
                                    self.quarantine.clear(&partition);
                                    let key = format!("{QUARANTINE_META_PREFIX}{partition}");
                                    batch.remove(&self.meta, key.as_bytes());
                                    tracing::info!(partition, "quarantine cleared by operator");
                                }
                                MutationInner::InstallDek {
                                    wrapped_dek,
                                    dek_version,
                                    is_emergency,
                                } => {
                                    let raw_dek = self
                                        .kek
                                        .unwrap_dek(&wrapped_dek)
                                        .map_err(|e| io::Error::other(e.to_string()))?;
                                    let locked_dek = LockedKey::from_raw(*raw_dek);
                                    let new_epoch = Arc::new(
                                        DekEpoch::from_raw(locked_dek, dek_version)
                                            .map_err(|e| io::Error::other(e.to_string()))?,
                                    );
                                    // Persist new DEK: [version_u32_BE; 4] ++ wrapped_bytes.
                                    let mut persisted = dek_version.to_be_bytes().to_vec();
                                    persisted.extend_from_slice(&wrapped_dek);
                                    batch.insert(&self.meta, META_DEK_CURRENT, persisted);
                                    let old_version = {
                                        let g = self.dek.read().unwrap_or_else(|p| p.into_inner());
                                        g.version
                                    };
                                    // Only persist retired DEK if not emergency (emergency
                                    // revokes).
                                    if !is_emergency {
                                        let retired_key =
                                            format!("{DEK_RETIRED_PREFIX}{old_version}");
                                        match self.meta.get(META_DEK_CURRENT) {
                                            Ok(Some(cur)) if cur.len() > 4 => {
                                                batch.insert(
                                                    &self.meta,
                                                    retired_key.as_bytes(),
                                                    &cur[4..],
                                                );
                                            }
                                            _ => {
                                                tracing::warn!(
                                                    old_version,
                                                    "could not read current DEK bytes for \
                                                     retirement record; pre-rotation ciphertext \
                                                     may be unreadable after restart"
                                                );
                                            }
                                        }
                                    }
                                    pending_dek_swap = Some((new_epoch, is_emergency));
                                    tracing::info!(
                                        old_version,
                                        new_version = dek_version,
                                        is_emergency,
                                        "DEK rotation: epoch swap queued"
                                    );
                                }
                                MutationInner::CreatePendingRotation {
                                    rotation_id,
                                    wrapped_dek,
                                    dek_version,
                                    expires_at,
                                    initiator,
                                } => {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    // Remove any pre-existing expired entries first.
                                    let mut pending = self
                                        .pending_rotations
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner());
                                    pending.retain(|_, v| v.expires_at > now);

                                    if !pending.is_empty() {
                                        violations.push(Violation {
                                            r#type: "CONFLICT".to_string(),
                                            subject: rotation_id.clone(),
                                            description: "another emergency rotation is already \
                                                          pending; confirm or wait for it to expire"
                                                .to_string(),
                                        });
                                    } else {
                                        let entry = PendingRotation {
                                            rotation_id: rotation_id.clone(),
                                            wrapped_dek: wrapped_dek.clone(),
                                            dek_version,
                                            expires_at,
                                            initiator: initiator.clone(),
                                        };
                                        let serialised = rmp_serde::to_vec(&entry)
                                            .map_err(|e| io::Error::other(e.to_string()))?;
                                        let meta_key =
                                            format!("{PENDING_ROTATION_PREFIX}{rotation_id}");
                                        batch.insert(&self.meta, meta_key.as_bytes(), serialised);
                                        pending.insert(rotation_id.clone(), entry);
                                        tracing::info!(
                                            rotation_id,
                                            dek_version,
                                            initiator,
                                            expires_at,
                                            "emergency DEK rotation staged; awaiting confirmation"
                                        );
                                    }
                                }
                                MutationInner::ConfirmPendingRotation {
                                    rotation_id,
                                    confirmer,
                                } => {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    let entry = {
                                        let mut pending = self
                                            .pending_rotations
                                            .lock()
                                            .unwrap_or_else(|p| p.into_inner());
                                        pending.remove(&rotation_id)
                                    };
                                    match entry {
                                        None => {
                                            violations.push(Violation {
                                                r#type: "NOT_FOUND".to_string(),
                                                subject: rotation_id.clone(),
                                                description: format!(
                                                    "no pending emergency rotation with id \
                                                     {rotation_id}"
                                                ),
                                            });
                                        }
                                        Some(ref e) if e.expires_at <= now => {
                                            violations.push(Violation {
                                                r#type: "EXPIRED".to_string(),
                                                subject: rotation_id.clone(),
                                                description: format!(
                                                    "pending rotation {rotation_id} expired at \
                                                     {} ({}s ago)",
                                                    e.expires_at,
                                                    now.saturating_sub(e.expires_at)
                                                ),
                                            });
                                        }
                                        Some(ref e) if e.initiator == confirmer => {
                                            // Re-insert so it can still be confirmed by someone
                                            // else within the window.
                                            self.pending_rotations
                                                .lock()
                                                .unwrap_or_else(|p| p.into_inner())
                                                .insert(rotation_id.clone(), e.clone());
                                            violations.push(Violation {
                                                r#type: "UNAUTHORIZED".to_string(),
                                                subject: rotation_id.clone(),
                                                description: "the confirming operator must be \
                                                              different from the initiator \
                                                              (dual-control requirement)"
                                                    .to_string(),
                                            });
                                        }
                                        Some(entry) => {
                                            // Dual-control satisfied — execute DEK install.
                                            let meta_key =
                                                format!("{PENDING_ROTATION_PREFIX}{rotation_id}");
                                            batch.remove(&self.meta, meta_key.as_bytes());

                                            let raw_dek =
                                                self.kek
                                                    .unwrap_dek(&entry.wrapped_dek)
                                                    .map_err(|e| io::Error::other(e.to_string()))?;
                                            let locked_dek = LockedKey::from_raw(*raw_dek);
                                            let new_epoch = Arc::new(
                                                DekEpoch::from_raw(locked_dek, entry.dek_version)
                                                    .map_err(|e| io::Error::other(e.to_string()))?,
                                            );
                                            let mut persisted =
                                                entry.dek_version.to_be_bytes().to_vec();
                                            persisted.extend_from_slice(&entry.wrapped_dek);
                                            batch.insert(&self.meta, META_DEK_CURRENT, persisted);
                                            let old_version = {
                                                let g = self
                                                    .dek
                                                    .read()
                                                    .unwrap_or_else(|p| p.into_inner());
                                                g.version
                                            };
                                            pending_dek_swap = Some((new_epoch, true));
                                            tracing::warn!(
                                                rotation_id,
                                                old_version,
                                                new_version = entry.dek_version,
                                                initiator = entry.initiator,
                                                confirmer,
                                                "SECURITY: emergency DEK rotation confirmed \
                                                 (dual-control); epoch swap queued"
                                            );
                                        }
                                    }
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

                // Swap the active DEK epoch after a successful InstallDek commit.
                if let Some((new_epoch, is_emergency_rotation)) = pending_dek_swap {
                    let old_epoch = {
                        let mut guard = self.dek.write().unwrap_or_else(|p| p.into_inner());
                        std::mem::replace(&mut *guard, new_epoch)
                    };
                    if is_emergency_rotation {
                        // Emergency: old DEK is revoked, not retired
                        let mut revoked =
                            self.revoked_deks.lock().unwrap_or_else(|p| p.into_inner());
                        if revoked.len() >= MAX_REVOKED_DEKS {
                            tracing::error!(
                                capacity = MAX_REVOKED_DEKS,
                                "revoked_deks set is full; this node has had an extraordinary \
                                 number of emergency rotations — operator review required"
                            );
                        }
                        revoked.insert(old_epoch.version);
                        drop(revoked);
                        tracing::warn!(
                            version = old_epoch.version,
                            "SECURITY: emergency DEK rotation — old DEK version revoked"
                        );
                    } else {
                        // Register old epoch for state/log read fallback during re-encryption.
                        self.old_deks
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .insert(old_epoch.version, old_epoch.clone());
                    }
                    // Signal background re-encryption task (non-fatal on channel full).
                    let _ = self.reencrypt_tx.try_send(old_epoch);
                    tracing::info!("DEK epoch swapped");
                }
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
