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
///
/// Full key layout is `_meta:quarantine:<partition>:<node_id>`: partition
/// comes first so that `ClearQuarantine` can prefix-scan and remove every
/// reporting node's entry for a partition in one pass.
const QUARANTINE_META_PREFIX: &str = "_meta:quarantine:";

/// Sliding window for GCM failure counting.
const QUARANTINE_WINDOW: Duration = Duration::from_secs(60);

/// Number of GCM failures within `QUARANTINE_WINDOW` that triggers quarantine.
const QUARANTINE_THRESHOLD: usize = 3;

/// Builds the Fjall meta key for a quarantine marker.
fn quarantine_meta_key(partition: &str, node_id: u64) -> String {
    format!("{QUARANTINE_META_PREFIX}{partition}:{node_id}")
}

/// Per-partition GCM decryption failure tracker with automatic quarantine.
///
/// A partition accumulates failure `Instant`s in a 60-second sliding window.
/// At three failures the partition is marked quarantined locally and — best
/// effort — the fact is proposed via Raft so it is committed cluster-wide
/// (ADR 0016-v2 §10 invariant 5). The in-memory `quarantined` set (which
/// gates local reads) only ever reflects *this* node's own quarantine state;
/// records reported by other nodes are persisted for audit visibility but
/// never block local reads, since GCM failures reflect node-local storage
/// corruption, not a cluster-wide data problem.
struct QuarantineTracker {
    failures: Mutex<HashMap<String, VecDeque<Instant>>>,
    quarantined: Mutex<HashSet<String>>,
}

impl QuarantineTracker {
    /// Initialise from Fjall meta, loading any persisted quarantine markers.
    ///
    /// Only markers reported by `node_id` (this node) are loaded into the
    /// blocking `quarantined` set; markers from other nodes are logged for
    /// visibility but otherwise ignored.
    fn from_meta(meta: &Keyspace, node_id: u64) -> Result<Self, crate::StoreError> {
        let mut quarantined = HashSet::new();

        // Collect first, then mutate: `insert`/`remove` below (legacy-key
        // migration) must not run against a live prefix iterator.
        let entries: Vec<Vec<u8>> = meta
            .prefix(QUARANTINE_META_PREFIX.as_bytes())
            .filter_map(|item| item.into_inner().ok())
            .map(|(k, _)| k.to_vec())
            .collect();

        for key_bytes in entries {
            let Ok(key_str) = String::from_utf8(key_bytes.clone()) else {
                continue;
            };
            let Some(rest) = key_str.strip_prefix(QUARANTINE_META_PREFIX) else {
                continue;
            };

            let (partition, reporting_node) = match rest.rsplit_once(':') {
                Some((partition, node_id_str)) => {
                    let Ok(reporting_node) = node_id_str.parse::<u64>() else {
                        continue;
                    };
                    (partition.to_string(), reporting_node)
                }
                None => {
                    // Pre-migration marker (`_meta:quarantine:<partition>`,
                    // no node-id suffix). These predate cluster-wide
                    // quarantine propagation and were always node-local
                    // (each node owns its own Fjall DB), so treat this as
                    // this node's own marker and rewrite it to the
                    // node-scoped key format. Left as-is it would silently
                    // fail to load on every future restart (no colon to
                    // split on), quietly ending a quarantine that's still
                    // supposed to be in effect.
                    tracing::warn!(
                        partition = rest,
                        "migrating pre-upgrade quarantine marker to node-scoped key format"
                    );
                    let _ = meta.insert(quarantine_meta_key(rest, node_id), b"1");
                    let _ = meta.remove(&key_bytes);
                    (rest.to_string(), node_id)
                }
            };

            if reporting_node == node_id {
                quarantined.insert(partition.clone());
                tracing::error!(
                    partition,
                    "SECURITY: partition is quarantined (loaded from persistent state)"
                );
            } else {
                tracing::info!(
                    partition,
                    reporting_node,
                    "quarantine record from another cluster node (informational only)"
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

    /// Directly marks a partition quarantined without threshold bookkeeping.
    ///
    /// Used when applying a Raft-committed `Quarantine` mutation reported by
    /// this node itself — idempotent with respect to `record_failure`, which
    /// already set the same in-memory state synchronously.
    fn force_quarantine(&self, partition: &str) {
        self.quarantined
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(partition.to_string());
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
/// Fjall meta key prefix for revoked DEK epochs (emergency rotation).  Only
/// the version and revocation timestamp are stored here — never the wrapped
/// key bytes — so the compromised DEK material remains genuinely discarded
/// (ADR 0016-v2 §6.2 step 5).
pub(crate) const DEK_REVOKED_PREFIX: &str = "_meta:dek:revoked:";
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
    /// This node's Raft ID — tags Quarantine mutations proposed by this node
    /// and scopes which persisted quarantine markers block local reads.
    node_id: u64,
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
    /// Channel signalling `(node_id, partition)` quarantine events for
    /// best-effort Raft propagation (ADR 0016-v2 §10 invariant 5).
    quarantine_tx: tokio::sync::mpsc::Sender<(u64, String)>,
    quarantine: Arc<QuarantineTracker>,
    /// Pending emergency DEK rotations awaiting dual-control confirmation.
    /// Shared with `ClusterAdminServiceImpl` so the gRPC handler can inspect
    /// the map without going through Raft.
    pub pending_rotations: Arc<Mutex<HashMap<String, PendingRotation>>>,
    /// Serializes non-core keyspace lifecycle changes (`drop_keyspace`)
    /// against `apply()`'s writes.
    ///
    /// `apply()` holds the read side for its whole call (writes are
    /// inherently sequential per node, so this never contends against
    /// itself); `drop_keyspace` takes the write side for its
    /// exists/is-empty/delete sequence. Without this, a keyspace's
    /// emptiness check and physical deletion race a concurrent, still
    /// in-flight `apply()` write to that same keyspace: Fjall's batch
    /// commit path writes directly to the tree and does not consult the
    /// `is_deleted` flag the single-item API checks, so the write would
    /// silently land in an already-deregistered, soon-to-be-discarded
    /// partition — applied per Raft, invisible to every future read.
    keyspace_lifecycle: Arc<RwLock<()>>,
}

impl FjallStateMachine {
    #[allow(clippy::result_large_err, clippy::too_many_arguments)]
    /// Create a new `FjallStateMachine`.
    ///
    /// # Parameters
    /// - `db`: Database instance.
    /// - `snapshot_dir`: Directory to store snapshots.
    /// - `node_id`: This node's Raft ID.
    /// - `dek`: Shared current DEK epoch (also held by `FjallLogStore`).
    /// - `kek`: Key Encryption Key used to unwrap new DEKs on `InstallDek`.
    /// - `reencrypt_tx`: Channel for signalling the background re-encryption
    ///   task with the old DEK epoch that needs re-encryption.
    /// - `quarantine_tx`: Channel for signalling the background quarantine
    ///   forwarding task with `(node_id, partition)` to propose via Raft.
    ///
    /// # Returns
    /// A `Result` containing the `FjallStateMachine`, or a `StoreError`.
    pub fn new(
        db: Arc<Database>,
        snapshot_dir: PathBuf,
        node_id: u64,
        dek: Arc<RwLock<Arc<DekEpoch>>>,
        old_deks: Arc<Mutex<BTreeMap<u32, Arc<DekEpoch>>>>,
        revoked_deks: Arc<Mutex<HashSet<u32>>>,
        kek: Arc<dyn KekProvider>,
        reencrypt_tx: tokio::sync::mpsc::Sender<Arc<DekEpoch>>,
        quarantine_tx: tokio::sync::mpsc::Sender<(u64, String)>,
        pending_rotations: Arc<Mutex<HashMap<String, PendingRotation>>>,
    ) -> Result<Self, StoreError> {
        let meta = db.keyspace("meta", KeyspaceCreateOptions::default)?;
        let data = db.keyspace("data", KeyspaceCreateOptions::default)?;
        let index = db.keyspace("index", KeyspaceCreateOptions::default)?;

        fs::create_dir_all(&snapshot_dir)?;

        let quarantine = Arc::new(QuarantineTracker::from_meta(&meta, node_id)?);

        Ok(Self {
            db,
            snapshot_dir,
            node_id,
            meta,
            data,
            index,
            dek,
            old_deks,
            revoked_deks,
            kek,
            reencrypt_tx,
            quarantine_tx,
            quarantine,
            pending_rotations,
            keyspace_lifecycle: Arc::new(RwLock::new(())),
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

    /// Return the path to the snapshot directory.
    pub(crate) fn snapshot_dir(&self) -> &std::path::Path {
        &self.snapshot_dir
    }

    /// Validate and decrypt an operator backup blob (produced by the `Backup`
    /// gRPC RPC) and return an OpenRaft `Snapshot` ready for
    /// `Raft::install_full_snapshot`.
    ///
    /// The blob format is `[dek_version_u32_BE; 4] ++ [utc_epoch_u64_BE; 8] ++
    /// AES-256-GCM(snapshot_file_msgpack)`.  Returns the decoded `Snapshot`
    /// together with the (utc_epoch, dek_version) pair for audit logging.
    pub fn decode_backup_blob(
        &self,
        bytes: &[u8],
    ) -> Result<(crate::types::Snapshot, u64, u32), crate::StoreError> {
        let (snapshot_file, dek_version, utc_epoch) =
            decrypt_snapshot_file(bytes, &self.dek, &self.old_deks)?;

        let data_bytes = rmp_serde::to_vec(&snapshot_file.data)
            .map_err(|e| crate::StoreError::Other(eyre::eyre!("snapshot re-serialize: {e}")))?;

        let snapshot = openraft::storage::Snapshot {
            meta: snapshot_file.meta,
            snapshot: data_bytes,
        };
        Ok((snapshot, utc_epoch, dek_version))
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

    /// Returns `true` if `name` names a keyspace that currently exists.
    ///
    /// Unlike [`Self::keyspace`], this never auto-vivifies an empty
    /// partition — safe to call speculatively when probing for
    /// garbage-collection candidates.
    pub fn keyspace_exists<S: AsRef<str>>(&self, name: S) -> bool {
        matches!(name.as_ref(), "data" | "meta" | "index") || self.db.keyspace_exists(name.as_ref())
    }

    /// Permanently deletes an empty, non-core keyspace/partition.
    ///
    /// Returns an error, without deleting anything, if the keyspace still
    /// has entries or if it names one of the core `"data"` / `"meta"` /
    /// `"index"` keyspaces. A no-op if the keyspace does not exist.
    ///
    /// Not part of the replicated Raft log: dropping an already-empty
    /// partition has no effect observable through `StorageApi`, so every
    /// node may reclaim it independently once it locally observes the
    /// keyspace is drained (analogous to local LSM compaction).
    pub fn drop_keyspace<S: AsRef<str>>(&self, name: S) -> Result<(), StoreError> {
        let name = name.as_ref();
        if matches!(name, "data" | "meta" | "index") {
            return Err(StoreError::Other(eyre::eyre!(
                "refusing to drop core keyspace '{name}'"
            )));
        }
        // Excludes any concurrent `apply()` call for the whole
        // exists/is-empty/delete sequence, so a write that `apply()` is
        // mid-way through queuing into this keyspace's batch can't be
        // silently discarded by a delete that lands between the emptiness
        // check and the physical drop.
        let _lifecycle_guard = self
            .keyspace_lifecycle
            .write()
            .unwrap_or_else(|p| p.into_inner());
        if !self.db.keyspace_exists(name) {
            return Ok(());
        }
        let ks = self.db.keyspace(name, KeyspaceCreateOptions::default)?;
        if !ks.is_empty()? {
            return Err(StoreError::Other(eyre::eyre!(
                "refusing to drop non-empty keyspace '{name}'"
            )));
        }
        self.db.delete_keyspace(ks)?;
        Ok(())
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
    /// `dek_version_hint` should be `Metadata::dek_version` for the record.
    /// When present, the read selects that exact DEK epoch deterministically
    /// and never falls back to another key on a tag-verification failure
    /// (ADR 0016-v2 §6 step 6). `None` indicates a legacy record written
    /// before per-record DEK version tracking existed; such records fall
    /// back to the previous try-current-then-probe-retired behavior for
    /// backward-compatible reads only — every write now populates
    /// `dek_version`, so this path serves only pre-migration data.
    pub fn decrypt_state(
        &self,
        stored: &[u8],
        tier: u8,
        keyspace: &[u8],
        pk: &[u8],
        dek_version_hint: Option<u32>,
    ) -> Result<Vec<u8>, StoreError> {
        let partition = String::from_utf8_lossy(keyspace).into_owned();

        if self.quarantine.is_quarantined(&partition) {
            return Err(StoreError::Quarantined(partition));
        }

        match dek_version_hint {
            Some(hint) => {
                self.decrypt_state_by_version(stored, tier, keyspace, pk, &partition, hint)
            }
            None => self.decrypt_state_legacy_probe(stored, tier, keyspace, pk, &partition),
        }
    }

    /// Deterministic-epoch decryption: selects the exact DEK epoch named by
    /// `hint` and never probes another key on failure (ADR 0016-v2 §6 step
    /// 6). An unknown epoch (already discarded/revoked, or corrupt
    /// metadata) is treated as ambiguous and quarantined rather than
    /// silently trying other keys.
    fn decrypt_state_by_version(
        &self,
        stored: &[u8],
        tier: u8,
        keyspace: &[u8],
        pk: &[u8],
        partition: &str,
        hint: u32,
    ) -> Result<Vec<u8>, StoreError> {
        // Single read of `self.dek`, reused for both the version comparison
        // and the decrypt call. Reading `.version` and then re-acquiring the
        // lock in a second `self.dek.read()` would be a TOCTOU race: a DEK
        // rotation landing between the two reads could swap in a different
        // epoch than the one `hint` was compared against, causing a
        // legitimate record to fail GCM verification and spuriously
        // quarantine the partition.
        let guard = self.dek.read().unwrap_or_else(|p| p.into_inner());
        let result = if hint == guard.version {
            state_decrypt(guard.state_dek(), stored, tier, keyspace, pk)
        } else {
            drop(guard);
            let old_map = self.old_deks.lock().unwrap_or_else(|p| p.into_inner());
            let Some(epoch) = old_map.get(&hint).cloned() else {
                drop(old_map);
                self.record_quarantine_failure(partition);
                return Err(crate::StoreError::Other(eyre::eyre!(
                    "record references unknown DEK epoch {hint}; treated as corrupt \
                     per ADR 0016-v2 §6 step 6 (no key-probing fallback) — partition \
                     '{partition}' quarantined"
                )));
            };
            drop(old_map);
            state_decrypt(epoch.state_dek(), stored, tier, keyspace, pk)
        };

        match result {
            Ok((plaintext, _next_version)) => Ok(plaintext.to_vec()),
            Err(openstack_keystone_storage_crypto::CryptoError::AesDecrypt) => {
                self.record_quarantine_failure(partition);
                Err(StoreError::Crypto {
                    source: openstack_keystone_storage_crypto::CryptoError::AesDecrypt,
                })
            }
            Err(e) => Err(StoreError::Crypto { source: e }),
        }
    }

    /// Legacy fallback for records written before per-record DEK version
    /// tracking (`Metadata::dek_version == None`). Retained only for
    /// backward-compatible reads of pre-migration data; every write now
    /// populates `dek_version`, so new records always use
    /// `decrypt_state_by_version` instead.
    fn decrypt_state_legacy_probe(
        &self,
        stored: &[u8],
        tier: u8,
        keyspace: &[u8],
        pk: &[u8],
        partition: &str,
    ) -> Result<Vec<u8>, StoreError> {
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
                let failed = self.quarantine.record_failure(partition);

                // Try retired DEK epochs — legacy records have no recorded
                // dek_version, so this is the only way to locate the right key.
                let old_map = self.old_deks.lock().unwrap_or_else(|p| p.into_inner());
                for (_, old) in old_map.iter() {
                    if let Ok((pt, _)) = state_decrypt(old.state_dek(), stored, tier, keyspace, pk)
                    {
                        tracing::warn!(
                            partition,
                            epoch_version = old.version,
                            "legacy record decrypted with retired DEK epoch — \
                             re-encryption required"
                        );
                        return Ok(pt.to_vec());
                    }
                }
                drop(old_map);

                if failed {
                    self.persist_and_signal_quarantine(partition);
                }
                Err(StoreError::Crypto {
                    source: openstack_keystone_storage_crypto::CryptoError::AesDecrypt,
                })
            }
            Err(e) => Err(StoreError::Crypto { source: e }),
        }
    }

    /// Records a GCM tag-verification failure and, if the failure count just
    /// crossed the quarantine threshold, persists and signals it.
    fn record_quarantine_failure(&self, partition: &str) {
        if self.quarantine.record_failure(partition) {
            self.persist_and_signal_quarantine(partition);
        }
    }

    /// Persists the quarantine marker to local Fjall meta (synchronous,
    /// restart-durable on this node) and signals the background forwarding
    /// task to propose the same fact via Raft for cluster-wide visibility
    /// (ADR 0016-v2 §10 invariant 5).
    fn persist_and_signal_quarantine(&self, partition: &str) {
        let key = quarantine_meta_key(partition, self.node_id);
        let _ = self.meta.insert(key, b"1");
        let _ = self
            .quarantine_tx
            .try_send((self.node_id, partition.to_string()));
    }

    /// Returns `true` if the given keyspace partition is currently quarantined.
    pub fn is_quarantined(&self, partition: &str) -> bool {
        self.quarantine.is_quarantined(partition)
    }

    /// Encrypt and write state bytes for a given key.
    ///
    /// Reads the current encrypted record (if present) to extract the stored
    /// version, increments it, then calls `state_encrypt` with the new version.
    ///
    /// Returns the ciphertext bytes and the DEK epoch version used, so the
    /// caller can record it in `Metadata::dek_version` (ADR 0016-v2 §6 step
    /// 6) — reads select the correct key deterministically instead of
    /// probing multiple epochs.
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
    ) -> Result<(Vec<u8>, u32), StoreError> {
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

        let (encrypted, dek_version) = {
            let guard = self.dek.read().unwrap_or_else(|p| p.into_inner());
            let encrypted = state_encrypt(
                guard.state_dek(),
                plaintext,
                tier,
                keyspace,
                key,
                next_version,
            )?;
            (encrypted, guard.version)
        };
        Ok((encrypted, dek_version))
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
) -> Result<(SnapshotFile, u32, u64), crate::StoreError> {
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

    let file = rmp_serde::from_slice(&file_bytes)
        .map_err(|e| crate::StoreError::Other(eyre::eyre!("snapshot deserialize: {e}")))?;
    Ok((file, dek_version, utc_epoch))
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
        let (snapshot_file, _, _) =
            decrypt_snapshot_file(&disk_bytes, &self.dek, &self.old_deks)
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
            // Held for this entry's whole processing+commit (there is no
            // further `.await` in this loop body until the next iteration),
            // so a concurrent `drop_keyspace` can't observe a keyspace as
            // empty mid-write and delete it out from under this commit.
            let _lifecycle_guard = self
                .keyspace_lifecycle
                .read()
                .unwrap_or_else(|p| p.into_inner());
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
                                        Ok((encrypted, dek_version)) => {
                                            batch.insert(&ks, key.clone(), encrypted);
                                            let mut meta_with_tier = metadata.clone();
                                            meta_with_tier.tier = DataTier::from(tier);
                                            meta_with_tier.dek_version = Some(dek_version);
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
                                        Ok((encrypted, dek_version)) => {
                                            batch.insert(&ks, key.clone(), encrypted);
                                            let mut meta_with_tier = metadata.clone();
                                            meta_with_tier.tier = DataTier::from(tier);
                                            meta_with_tier.dek_version = Some(dek_version);
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
                                    // Harmless no-op on nodes that were never
                                    // quarantined for this partition.
                                    self.quarantine.clear(&partition);
                                    // Remove every reporting node's marker for
                                    // this partition — the operator clears the
                                    // partition cluster-wide, not just the node
                                    // they happened to connect to.
                                    let scan_prefix =
                                        format!("{QUARANTINE_META_PREFIX}{partition}:");
                                    let keys_to_remove: Vec<Vec<u8>> = self
                                        .meta
                                        .prefix(scan_prefix.as_bytes())
                                        .filter_map(|item| item.into_inner().ok())
                                        .map(|(k, _)| k.to_vec())
                                        .collect();
                                    for key in &keys_to_remove {
                                        batch.remove(&self.meta, key.as_slice());
                                    }
                                    tracing::info!(partition, "quarantine cleared by operator");
                                }
                                MutationInner::Quarantine {
                                    node_id: reporting_node,
                                    partition,
                                } => {
                                    // Applied uniformly on every node. Only
                                    // the reporting node updates its own
                                    // blocking in-memory state; other nodes
                                    // persist the record for audit
                                    // visibility only (ADR 0016-v2 §10
                                    // invariant 5).
                                    let key = quarantine_meta_key(&partition, reporting_node);
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    batch.insert(&self.meta, key.as_bytes(), now.to_be_bytes());
                                    if reporting_node == self.node_id {
                                        self.quarantine.force_quarantine(&partition);
                                    }
                                    tracing::info!(
                                        partition,
                                        reporting_node,
                                        "quarantine committed via Raft"
                                    );
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
                                    } else {
                                        // Emergency rotation: durably record the revoked
                                        // marker in the same atomic batch as the DEK swap,
                                        // so revocation survives a restart (ADR 0016-v2
                                        // §6.2 step 5). Only the revocation timestamp is
                                        // stored — never the wrapped key bytes — so the
                                        // compromised DEK material remains discarded.
                                        let revoked_key =
                                            format!("{DEK_REVOKED_PREFIX}{old_version}");
                                        let now = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();
                                        batch.insert(
                                            &self.meta,
                                            revoked_key.as_bytes(),
                                            now.to_be_bytes(),
                                        );
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
                        // Emergency: old DEK is revoked, not retired, and —
                        // unlike a normal rotation — is never forwarded to
                        // the re-encryption channel below. The point of
                        // revocation is that this key material must not be
                        // used again for anything, including internal
                        // re-encryption of other records (ADR 0016-v2 §6.2
                        // step 5); `old_epoch` is simply dropped (and
                        // zeroized by `LockedKey`'s `Drop`) at the end of
                        // this block.
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
                        // Signal background re-encryption task (non-fatal on channel full).
                        let _ = self.reencrypt_tx.try_send(old_epoch);
                    }
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

#[cfg(test)]
mod quarantine_tests {
    use super::*;

    fn open_meta() -> (fjall::Keyspace, Arc<Database>, tempfile::TempDir) {
        let td = tempfile::TempDir::new().expect("tempdir");
        let db = Arc::new(Database::builder(td.path()).open().expect("open db"));
        let meta = db
            .keyspace("meta", KeyspaceCreateOptions::default)
            .expect("meta keyspace");
        (meta, db, td)
    }

    #[test]
    fn quarantine_meta_key_puts_partition_before_node_id() {
        assert_eq!(quarantine_meta_key("data", 7), "_meta:quarantine:data:7");
    }

    #[test]
    fn from_meta_only_blocks_matching_node_id() {
        let (meta, db, _td) = open_meta();
        // Node 1's own record blocks; node 2's record is informational only.
        meta.insert(quarantine_meta_key("data", 1), 0u64.to_be_bytes())
            .expect("insert node 1 marker");
        meta.insert(quarantine_meta_key("data", 2), 0u64.to_be_bytes())
            .expect("insert node 2 marker");
        db.persist(PersistMode::SyncAll).expect("persist");

        let tracker = QuarantineTracker::from_meta(&meta, 1).expect("load tracker");
        assert!(tracker.is_quarantined("data"));

        let tracker_other = QuarantineTracker::from_meta(&meta, 2).expect("load tracker");
        assert!(tracker_other.is_quarantined("data"));

        let tracker_uninvolved = QuarantineTracker::from_meta(&meta, 3).expect("load tracker");
        assert!(!tracker_uninvolved.is_quarantined("data"));
    }

    /// Pre-upgrade quarantine markers (`_meta:quarantine:<partition>`, no
    /// node-id suffix) must still block reads after loading, and must be
    /// migrated to the node-scoped key format so they survive a *second*
    /// restart too — not just silently dropped on `rsplit_once` failure.
    #[test]
    fn from_meta_migrates_legacy_marker_without_node_id() {
        let (meta, db, _td) = open_meta();
        let legacy_key = format!("{QUARANTINE_META_PREFIX}data");
        meta.insert(legacy_key.as_bytes(), b"1")
            .expect("insert legacy marker");
        db.persist(PersistMode::SyncAll).expect("persist");

        let tracker = QuarantineTracker::from_meta(&meta, 1).expect("load tracker");
        assert!(
            tracker.is_quarantined("data"),
            "legacy marker must still block reads on the node that owns it"
        );

        // The legacy key must have been rewritten to the node-scoped format
        // so a *second* restart doesn't depend on this migration running
        // again.
        assert!(
            meta.get(legacy_key.as_bytes())
                .expect("read legacy key")
                .is_none(),
            "legacy key should have been removed after migration"
        );
        assert!(
            meta.get(quarantine_meta_key("data", 1))
                .expect("read migrated key")
                .is_some(),
            "migrated node-scoped key should now be present"
        );

        let tracker_again = QuarantineTracker::from_meta(&meta, 1).expect("reload tracker");
        assert!(
            tracker_again.is_quarantined("data"),
            "quarantine must still be in effect on a second restart, via the migrated key"
        );
    }

    #[test]
    fn force_quarantine_is_idempotent_with_record_failure() {
        let tracker = QuarantineTracker {
            failures: Mutex::new(HashMap::new()),
            quarantined: Mutex::new(HashSet::new()),
        };
        assert!(!tracker.is_quarantined("data"));
        tracker.force_quarantine("data");
        assert!(tracker.is_quarantined("data"));
        // Calling again is a harmless no-op.
        tracker.force_quarantine("data");
        assert!(tracker.is_quarantined("data"));
    }

    #[test]
    fn clear_removes_quarantine_state() {
        let tracker = QuarantineTracker {
            failures: Mutex::new(HashMap::new()),
            quarantined: Mutex::new(HashSet::new()),
        };
        tracker.force_quarantine("data");
        assert!(tracker.is_quarantined("data"));
        tracker.clear("data");
        assert!(!tracker.is_quarantined("data"));
    }
}

#[cfg(test)]
mod dek_version_tests {
    use openstack_keystone_storage_crypto::EnvKek;

    use super::*;

    fn test_epoch(seed: u8, version: u32) -> Arc<DekEpoch> {
        Arc::new(DekEpoch::from_raw(LockedKey::from_raw([seed; 32]), version).expect("epoch"))
    }

    /// Builds a `FjallStateMachine` with directly controllable `dek` /
    /// `old_deks` state, so tests can simulate a rotation transition without
    /// going through the full Raft apply path.
    fn make_sm(current: Arc<DekEpoch>) -> (FjallStateMachine, tempfile::TempDir) {
        let td = tempfile::TempDir::new().expect("tempdir");
        let db = Arc::new(Database::builder(td.path()).open().expect("open db"));
        let kek: Arc<dyn KekProvider> = Arc::new(EnvKek::from_bytes([0x42u8; 32]));
        let (reencrypt_tx, reencrypt_rx) = tokio::sync::mpsc::channel(1);
        drop(reencrypt_rx);
        let (quarantine_tx, quarantine_rx) = tokio::sync::mpsc::channel(1);
        drop(quarantine_rx);

        let sm = FjallStateMachine::new(
            db,
            td.path().join("snapshots"),
            1, // node_id
            Arc::new(RwLock::new(current)),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(HashSet::new())),
            kek,
            reencrypt_tx,
            quarantine_tx,
            Arc::new(Mutex::new(HashMap::new())),
        )
        .expect("construct state machine");
        (sm, td)
    }

    #[test]
    fn decrypt_with_matching_current_version_succeeds() {
        let epoch = test_epoch(0x01, 1);
        let (sm, _td) = make_sm(epoch);

        let ks = sm.data().clone();
        let (ciphertext, version) = sm
            .encrypt_and_store(&ks, b"k1", b"data", DataTier::Internal as u8, b"hello")
            .expect("encrypt");
        assert_eq!(version, 1);

        let plaintext = sm
            .decrypt_state(
                &ciphertext,
                DataTier::Internal as u8,
                b"data",
                b"k1",
                Some(version),
            )
            .expect("decrypt with correct hint");
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn decrypt_with_retired_epoch_hint_succeeds_without_probing() {
        let old_epoch = test_epoch(0x02, 1);
        let (sm, _td) = make_sm(old_epoch.clone());

        let ks = sm.data().clone();
        let (ciphertext, old_version) = sm
            .encrypt_and_store(&ks, b"k2", b"data", DataTier::Internal as u8, b"hello")
            .expect("encrypt under epoch 1");
        assert_eq!(old_version, 1);

        // Simulate a rotation: swap in a new current epoch, retire the old one.
        let new_epoch = test_epoch(0x03, 2);
        *sm.dek.write().unwrap() = new_epoch;
        sm.old_deks.lock().unwrap().insert(1, old_epoch);

        // Old records still decrypt via the exact retired epoch named by hint.
        let plaintext = sm
            .decrypt_state(
                &ciphertext,
                DataTier::Internal as u8,
                b"data",
                b"k2",
                Some(old_version),
            )
            .expect("decrypt via retired epoch hint");
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn decrypt_with_wrong_version_hint_fails_without_probing() {
        let epoch1 = test_epoch(0x04, 1);
        let (sm, _td) = make_sm(epoch1.clone());

        let ks = sm.data().clone();
        let (ciphertext, _version) = sm
            .encrypt_and_store(&ks, b"k3", b"data", DataTier::Internal as u8, b"hello")
            .expect("encrypt under epoch 1");

        // Rotate so epoch 1 becomes retired (and decryptable, if probed).
        let epoch2 = test_epoch(0x05, 2);
        *sm.dek.write().unwrap() = epoch2;
        sm.old_deks.lock().unwrap().insert(1, epoch1);

        // A hint naming a version that exists in neither current nor
        // old_deks must fail outright — never silently fall back to
        // probing epoch 1, even though epoch 1 would actually decrypt it
        // (ADR 0016-v2 §6 step 6).
        let err = sm
            .decrypt_state(
                &ciphertext,
                DataTier::Internal as u8,
                b"data",
                b"k3",
                Some(99),
            )
            .expect_err("unknown dek_version hint must not silently probe other keys");
        assert!(!matches!(err, StoreError::Quarantined(_)));
    }

    #[test]
    fn decrypt_legacy_none_hint_still_probes_retired_epochs() {
        let epoch1 = test_epoch(0x06, 1);
        let (sm, _td) = make_sm(epoch1.clone());

        let ks = sm.data().clone();
        let (ciphertext, _version) = sm
            .encrypt_and_store(&ks, b"k4", b"data", DataTier::Internal as u8, b"hello")
            .expect("encrypt under epoch 1");

        let epoch2 = test_epoch(0x07, 2);
        *sm.dek.write().unwrap() = epoch2;
        sm.old_deks.lock().unwrap().insert(1, epoch1);

        // Legacy records (no dek_version recorded) still fall back to
        // try-current-then-probe-retired for backward compatibility.
        let plaintext = sm
            .decrypt_state(&ciphertext, DataTier::Internal as u8, b"data", b"k4", None)
            .expect("legacy probe path should still find the retired epoch");
        assert_eq!(plaintext, b"hello");
    }
}

#[cfg(test)]
mod keyspace_gc_tests {
    use openstack_keystone_storage_crypto::EnvKek;

    use super::*;

    /// Builds a `FjallStateMachine` for exercising `keyspace_exists` /
    /// `drop_keyspace` against the real Fjall backend (as opposed to
    /// `mock::MockStorage`, which models the same contract in-memory for
    /// driver-level tests).
    fn make_sm() -> (FjallStateMachine, tempfile::TempDir) {
        let td = tempfile::TempDir::new().expect("tempdir");
        let db = Arc::new(Database::builder(td.path()).open().expect("open db"));
        let kek: Arc<dyn KekProvider> = Arc::new(EnvKek::from_bytes([0x42u8; 32]));
        let epoch =
            Arc::new(DekEpoch::from_raw(LockedKey::from_raw([0x09; 32]), 1).expect("epoch"));
        let (reencrypt_tx, reencrypt_rx) = tokio::sync::mpsc::channel(1);
        drop(reencrypt_rx);
        let (quarantine_tx, quarantine_rx) = tokio::sync::mpsc::channel(1);
        drop(quarantine_rx);

        let sm = FjallStateMachine::new(
            db,
            td.path().join("snapshots"),
            1,
            Arc::new(RwLock::new(epoch)),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(HashSet::new())),
            kek,
            reencrypt_tx,
            quarantine_tx,
            Arc::new(Mutex::new(HashMap::new())),
        )
        .expect("construct state machine");
        (sm, td)
    }

    #[test]
    fn keyspace_exists_is_false_until_first_access_and_never_auto_vivifies() {
        let (sm, _td) = make_sm();
        assert!(!sm.keyspace_exists("rotating_bucket_1"));
        // Checking existence must not have created it as a side effect.
        assert!(!sm.keyspace_exists("rotating_bucket_1"));

        let _ks = sm.keyspace("rotating_bucket_1").expect("create keyspace");
        assert!(sm.keyspace_exists("rotating_bucket_1"));
    }

    #[test]
    fn keyspace_exists_is_always_true_for_core_keyspaces() {
        let (sm, _td) = make_sm();
        assert!(sm.keyspace_exists("data"));
        assert!(sm.keyspace_exists("meta"));
        assert!(sm.keyspace_exists("index"));
    }

    #[test]
    fn drop_keyspace_is_noop_when_never_created() {
        let (sm, _td) = make_sm();
        sm.drop_keyspace("never_created").expect("no-op drop");
        assert!(!sm.keyspace_exists("never_created"));
    }

    #[test]
    fn drop_keyspace_reclaims_an_empty_partition() {
        let (sm, _td) = make_sm();
        sm.keyspace("rotating_bucket_2").expect("create keyspace");
        assert!(sm.keyspace_exists("rotating_bucket_2"));

        sm.drop_keyspace("rotating_bucket_2")
            .expect("drop empty keyspace");
        assert!(!sm.keyspace_exists("rotating_bucket_2"));
    }

    #[test]
    fn drop_keyspace_refuses_non_empty_partition() {
        let (sm, _td) = make_sm();
        let ks = sm.keyspace("rotating_bucket_3").expect("create keyspace");
        ks.insert(b"leftover-key", b"leftover-value")
            .expect("insert");

        let err = sm
            .drop_keyspace("rotating_bucket_3")
            .expect_err("must refuse to drop a non-empty keyspace");
        assert!(matches!(err, StoreError::Other(_)));
        assert!(sm.keyspace_exists("rotating_bucket_3"));
    }

    #[test]
    fn drop_keyspace_refuses_core_keyspaces() {
        let (sm, _td) = make_sm();
        for core in ["data", "meta", "index"] {
            let err = sm
                .drop_keyspace(core)
                .expect_err("must refuse to drop a core keyspace");
            assert!(matches!(err, StoreError::Other(_)));
            assert!(sm.keyspace_exists(core));
        }
    }

    /// Regression test for the TOCTOU race between `drop_keyspace` and a
    /// concurrent `apply()` write: `apply()` holds `keyspace_lifecycle`'s
    /// read side for an entry's whole processing+commit, so `drop_keyspace`
    /// (which takes the write side) must not be able to proceed while any
    /// such read guard is outstanding — otherwise a keyspace could be
    /// deleted mid-write, and Fjall's batch-commit path would silently
    /// write into the now-deregistered, soon-to-be-discarded partition
    /// (it does not consult the `is_deleted` flag the single-item API
    /// checks).
    #[test]
    fn keyspace_lifecycle_lock_excludes_concurrent_readers_and_writer() {
        let (sm, _td) = make_sm();
        sm.keyspace("rotating_bucket_race")
            .expect("create keyspace");

        // Simulate an in-flight apply() holding the read guard for the
        // duration of a batch commit.
        let _apply_guard = sm.keyspace_lifecycle.read().expect("acquire read guard");

        // A concurrent drop_keyspace call must be excluded, not race the
        // in-flight write — try_write proves it would block rather than
        // proceed and silently discard that write.
        assert!(
            sm.keyspace_lifecycle.try_write().is_err(),
            "drop_keyspace's write lock must not be obtainable while apply() holds the read side"
        );
    }
}
