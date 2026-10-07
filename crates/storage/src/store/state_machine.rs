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
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode, Readable};
use futures::Stream;
use futures::TryStreamExt;
use openraft::OptionalSend;
use openraft::RaftSnapshotBuilder;
use openraft::SnapshotMeta;
use openraft::StorageError;
use openraft::alias::LogIdOf;
use openraft::alias::SnapshotMetaOf;
use openraft::alias::SnapshotOf;
use openraft::alias::StoredMembershipOf;
use openraft::entry::RaftEntry;
use openraft::storage::EntryResponder;
use openraft::storage::RaftStateMachine;
use openraft::storage::Snapshot;
use openraft::type_config::TypeConfigExt;
use openstack_keystone_storage_crypto::nonce::nonce_meta_prefix;
use openstack_keystone_storage_crypto::{
    DekEpoch, KekProvider, LockedKey, backup_decrypt, backup_encrypt, state_decrypt, state_encrypt,
};
use rand::RngExt;
use serde::Deserialize;
use serde::Serialize;

use crate::DataTier;
use crate::StoreError;
use crate::TypeConfig;
use crate::protobuf::api::response::Violation;
use crate::store::log_store::{KEY_PURGED, KEY_VOTE};
use crate::store_command::*;
use crate::types::Metadata;

mod dek;
mod quarantine;
mod raft_sm;
mod restore;
mod rotation;
mod snapshot;
mod snapshot_file;
mod status;

pub(crate) use self::restore::MAX_LIVE_RESTORE_SIZE;
pub(crate) use self::rotation::{DEK_REVOKED_PENDING_PREFIX, DEK_REVOKED_PREFIX, unix_now};
pub use self::rotation::{PENDING_ROTATION_TTL_SECS, ReencryptReport, load_pending_rotations};
pub use self::status::EncryptionStatus;

use self::quarantine::*;
use self::restore::*;
use self::rotation::*;
use self::snapshot_file::*;

const KEY_LAST_APPLIED_LOG: &[u8] = b"last_applied_log";
const KEY_LAST_MEMBERSHIP: &[u8] = b"last_membership";

/// Default maximum per-key write version (ADR 0016-v2 §10); overridden by
/// `[distributed_storage] write_rate_threshold`.
pub const DEFAULT_WRITE_RATE_THRESHOLD: u32 = 1u32 << 30;

/// Keyspace names reserved for the state machine's own storage.
///
/// A `StorageApi` caller must never be able to write into these directly
/// (GitHub #1294): `"meta"` backs per-record [`Metadata`], DEK material and
/// other engine bookkeeping; `"logs"` backs the Raft log store;
/// `"index"` backs the secondary index; `"local_emergency"` is a
/// node-local, non-Raft keyspace. `apply()` rejects any mutation whose
/// caller-supplied keyspace is one of these before it touches storage.
const RESERVED_KEYSPACES: &[&str] = &["meta", "logs", "index", "local_emergency"];

/// Returns an error if `keyspace` names a keyspace reserved for internal
/// state machine storage (see [`RESERVED_KEYSPACES`]).
fn check_keyspace_allowed(keyspace: &str) -> Result<(), io::Error> {
    if RESERVED_KEYSPACES.contains(&keyspace) {
        return Err(io::Error::other(format!(
            "keyspace '{keyspace}' is reserved for internal state machine storage"
        )));
    }
    Ok(())
}

/// Builds the namespaced key under which a user record's [`Metadata`] is
/// stored in the `meta` keyspace: `<keyspace>\0<key>`.
///
/// Per-record metadata used to be stored under the bare record key, with no
/// keyspace component, so two records with the same key in different
/// keyspaces shared one `Metadata` entry (GitHub #1294) — a `Remove` of key
/// `K` in keyspace `A` deleted the metadata of key `K` in keyspace `B` too,
/// after which reads of `B`'s record found ciphertext with no matching
/// `dek_version` hint and treated it as corruption. The `\0` separator can
/// never collide with the engine's own bare system keys (`_meta:*`,
/// `last_applied_log`, `last_membership`), none of which contain a NUL
/// byte, and `keyspace` itself can never be `"meta"` here since
/// [`check_keyspace_allowed`] rejects that before any caller-supplied
/// keyspace reaches this function.
pub fn meta_key(keyspace: &str, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(keyspace.len() + 1 + key.len());
    out.extend_from_slice(keyspace.as_bytes());
    out.push(0);
    out.extend_from_slice(key);
    out
}

/// Cipher (or, for ephemeral records, plaintext) bytes plus metadata for one
/// key inside an ephemeral keyspace.
type EphemeralValue = (Vec<u8>, Metadata);

/// The in-memory contents of one ephemeral keyspace, keyed by record key.
type EphemeralKeyspace = DashMap<Vec<u8>, EphemeralValue>;

/// One `(key, value, metadata)` entry returned from an ephemeral prefix scan.
type EphemeralEntry = (Vec<u8>, Vec<u8>, Metadata);

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
    /// DEK epochs displaced by a live restore, tried by version after
    /// `old_deks` when reading pre-restore log entries and snapshot files
    /// (see [`DEK_SHADOW_PREFIX`]). Shared with the log store.
    shadow_deks: Arc<Mutex<Vec<Arc<DekEpoch>>>>,
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
    /// Ephemeral (non-Fjall-backed) keyspaces, keyed by keyspace name.
    ///
    /// Populated the first time `apply()` sees a `Set`/`CreateIfAbsent`
    /// mutation whose `Metadata::is_ephemeral` is `true` for that keyspace
    /// name; every node derives the same population independently since
    /// `apply()` runs identically, in the same log order, everywhere — no
    /// separate consensus needed (same principle `drop_keyspace` already
    /// relies on for non-core keyspace lifecycle). A keyspace is either
    /// always ephemeral or always Fjall-backed for the life of its name; an
    /// outer entry existing (even with an empty inner map) is equivalent to
    /// a Fjall partition existing.
    ephemeral: DashMap<String, EphemeralKeyspace>,
    /// ADR 0031 Raft Prometheus metrics. Owned here (rather than only on
    /// `app::Storage`) because `apply_duration_seconds` must be recorded at
    /// the actual per-entry apply call site below; `app::Storage` reaches
    /// the same instance via `raft_prometheus_metrics()` to also render the
    /// `openraft`-snapshot-derived gauges for `/metrics`.
    raft_prometheus_metrics: Arc<crate::prometheus_metrics::KeystoneRaftPrometheusMetrics>,
    /// Audit forwarder, set once after construction. Receives the new audit
    /// HMAC key on every DEK epoch swap and the apply-side audit records
    /// (ADR 0016-v2 §3.1). Unset in unit tests that do not exercise audit.
    audit: std::sync::OnceLock<crate::audit::AuditForwarder>,
    /// Per-key write version at which further writes to the key are
    /// rejected (`[distributed_storage] write_rate_threshold`).
    write_rate_threshold: Arc<AtomicU32>,
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

        let mut shadow_entries = Vec::new();
        for item in meta.prefix(DEK_SHADOW_PREFIX.as_bytes()) {
            let (key, value) = item.into_inner()?;
            shadow_entries.push((key.to_vec(), value.to_vec()));
        }
        let shadow_deks = Arc::new(Mutex::new(shadow_epochs(
            shadow_entries
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice())),
            kek.as_ref(),
        )));

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
            shadow_deks,
            kek,
            reencrypt_tx,
            quarantine_tx,
            quarantine,
            pending_rotations,
            keyspace_lifecycle: Arc::new(RwLock::new(())),
            ephemeral: DashMap::new(),
            raft_prometheus_metrics: Arc::new(
                crate::prometheus_metrics::KeystoneRaftPrometheusMetrics::new(),
            ),
            audit: std::sync::OnceLock::new(),
            write_rate_threshold: Arc::new(AtomicU32::new(DEFAULT_WRITE_RATE_THRESHOLD)),
        })
    }

    /// Set the per-key write version threshold. Values of `0` are ignored.
    pub fn set_write_rate_threshold(&self, threshold: u32) {
        if threshold > 0 {
            self.write_rate_threshold
                .store(threshold, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Current per-key write version threshold.
    pub(crate) fn write_rate_threshold(&self) -> u32 {
        self.write_rate_threshold
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Attach the audit forwarder. First call wins; later calls are ignored.
    ///
    /// Re-syncs the forwarder's key with the current DEK epoch: a swap
    /// applied before the forwarder was attached could not rotate its key.
    pub fn set_audit_forwarder(&self, forwarder: crate::audit::AuditForwarder) {
        if self.audit.set(forwarder).is_err() {
            return;
        }
        let epoch = self.dek.read().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some(audit) = self.audit.get() {
            match epoch.derive_audit_key(self.node_id) {
                Ok(key) => audit.rotate_key(epoch.version, key),
                Err(e) => tracing::error!(
                    error = %e,
                    version = epoch.version,
                    "AUDIT: failed to derive audit key for current DEK epoch"
                ),
            }
        }
    }

    /// This node's ADR 0031 Raft Prometheus metrics. Shared (via `Arc`)
    /// with `app::Storage`, which reads it to render `/metrics` output
    /// alongside a fresh `openraft::RaftMetrics` snapshot.
    pub fn raft_prometheus_metrics(
        &self,
    ) -> &Arc<crate::prometheus_metrics::KeystoneRaftPrometheusMetrics> {
        &self.raft_prometheus_metrics
    }

    /// Point-in-time node state for the `/metrics` endpoint (GitHub
    /// #1306). The log nonce counter lives in the log store and is left
    /// unset here.
    pub fn node_status(&self) -> crate::prometheus_metrics::RaftNodeStatus {
        let (snapshot_size_bytes, snapshot_age_seconds) = self
            .latest_snapshot_path()
            .ok()
            .flatten()
            .and_then(|path| fs::metadata(path).ok())
            .map(|meta| {
                let age = meta
                    .modified()
                    .ok()
                    .and_then(|m| m.elapsed().ok())
                    .map(|d| d.as_secs());
                (Some(meta.len()), age)
            })
            .unwrap_or((None, None));
        let log_disk_space_bytes = self
            .db
            .keyspace_exists("logs")
            .then(|| {
                self.db
                    .keyspace("logs", KeyspaceCreateOptions::default)
                    .ok()
            })
            .flatten()
            .map(|ks| ks.disk_space());
        crate::prometheus_metrics::RaftNodeStatus {
            quarantined_partitions: self.quarantined_partitions(),
            dek_version: self.dek.read().unwrap_or_else(|p| p.into_inner()).version,
            dek_retired_epochs: self
                .old_deks
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .len(),
            dek_revoked_epochs: self
                .revoked_deks
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .len(),
            dek_pending_rotations: self
                .pending_rotations
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .len(),
            log_nonce_counter: None,
            log_nonce_remaining: None,
            snapshot_size_bytes,
            snapshot_age_seconds,
            disk_space_bytes: self.db.disk_space().ok(),
            log_disk_space_bytes,
        }
    }

    /// The displaced-DEK list, to share with the log store.
    pub fn shadow_deks(&self) -> Arc<Mutex<Vec<Arc<DekEpoch>>>> {
        self.shadow_deks.clone()
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

    /// Returns `true` if `name` is a registered ephemeral (in-memory,
    /// non-Fjall) keyspace.
    pub fn is_ephemeral_keyspace<S: AsRef<str>>(&self, name: S) -> bool {
        self.ephemeral.contains_key(name.as_ref())
    }

    /// Reads a single key from an ephemeral keyspace.
    ///
    /// Returns `None` both when `keyspace` is not ephemeral and when the
    /// key is absent — callers that need to distinguish "not an ephemeral
    /// keyspace" (fall through to Fjall) from "no such key" (return `None`
    /// to the caller) must check [`Self::is_ephemeral_keyspace`] first.
    pub fn ephemeral_get<S: AsRef<str>>(
        &self,
        keyspace: S,
        key: &[u8],
    ) -> Option<(Vec<u8>, Metadata)> {
        self.ephemeral
            .get(keyspace.as_ref())?
            .get(key)
            .map(|e| e.value().clone())
    }

    /// Lists all entries in an ephemeral keyspace whose key starts with
    /// `prefix`. Returns `None` if `keyspace` is not ephemeral.
    pub fn ephemeral_prefix<S: AsRef<str>>(
        &self,
        keyspace: S,
        prefix: &[u8],
    ) -> Option<Vec<EphemeralEntry>> {
        let ks = self.ephemeral.get(keyspace.as_ref())?;
        Some(
            ks.iter()
                .filter(|entry| entry.key().starts_with(prefix))
                .map(|entry| {
                    let (cipher, metadata) = entry.value().clone();
                    (entry.key().clone(), cipher, metadata)
                })
                .collect(),
        )
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
        matches!(name.as_ref(), "data" | "meta" | "index")
            || self.ephemeral.contains_key(name.as_ref())
            || self.db.keyspace_exists(name.as_ref())
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
        // Ephemeral keyspaces live purely in memory: no on-disk emptiness
        // check or `keyspace_lifecycle` coordination with `apply()` is
        // needed, since `DashMap::remove` is atomic per-entry and `apply()`
        // only ever inserts into a *different* per-keyspace inner map, not
        // this outer registry.
        if let Some((_, inner)) = self.ephemeral.remove(name) {
            if !inner.is_empty() {
                self.ephemeral.insert(name.to_string(), inner);
                return Err(StoreError::Other(eyre::eyre!(
                    "refusing to drop non-empty keyspace '{name}'"
                )));
            }
            return Ok(());
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

/// Persists `raw` as the node's current DEK in the `meta` keyspace exactly
/// like `bootstrap_dek` does, which hand-built test state machines skip but
/// snapshot building now requires (the snapshot's DEK manifest is derived
/// from it).
#[cfg(test)]
fn seed_current_dek(sm: &FjallStateMachine, raw: [u8; 32], version: u32) {
    let wrapped = sm.kek.wrap_dek(&raw).expect("wrap dek");
    let mut persisted = version.to_be_bytes().to_vec();
    persisted.extend_from_slice(&wrapped);
    sm.meta
        .insert(META_DEK_CURRENT, &persisted)
        .expect("persist current dek");
}

/// A manifest naming the state machine's persisted current DEK.
#[cfg(test)]
fn current_manifest(sm: &FjallStateMachine) -> DekManifest {
    DekManifest {
        current: sm.current_dek_wrapped().expect("current dek"),
        retired: Vec::new(),
    }
}

#[cfg(test)]
mod quarantine_tests;

#[cfg(test)]
mod dek_version_tests;

#[cfg(test)]
mod keyspace_isolation_tests;

#[cfg(test)]
mod reencrypt_tests;

#[cfg(test)]
mod keyspace_gc_tests;

#[cfg(test)]
mod ephemeral_tests;

#[cfg(test)]
mod snapshot_tests;
