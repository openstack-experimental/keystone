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
pub(crate) fn meta_key(keyspace: &str, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(keyspace.len() + 1 + key.len());
    out.extend_from_slice(keyspace.as_bytes());
    out.push(0);
    out.extend_from_slice(key);
    out
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

/// Snapshot wire/on-disk payload format version.
///
/// Bump whenever `SnapshotPayload`'s layout changes, so a snapshot written
/// by an incompatible version is rejected by `install_snapshot` with a
/// clear error instead of being silently misinterpreted (GitHub #1293).
const SNAPSHOT_FORMAT_VERSION: u32 = 2;

/// Keyspaces that are node-local and must never travel inside a snapshot:
/// `logs` is the Raft log itself (compaction/log truncation handle it
/// separately) and `local_emergency` is deliberately node-local by design
/// (ADR 0028).
const SNAPSHOT_SKIP_KEYSPACES: &[&str] = &["logs", "local_emergency"];

/// One keyspace's full contents inside a [`SnapshotPayload`]: `(key, value)`
/// pairs exactly as stored in Fjall.
type SnapshotKeyspaceEntries = Vec<(Vec<u8>, Vec<u8>)>;

/// Full contents of every replicated Fjall keyspace, plus the ephemeral
/// keyspace name registry.
///
/// This is the payload streamed between nodes during
/// `build_snapshot`/`install_snapshot` (`RaftSnapshotBuilder`/
/// `RaftStateMachine`) and the payload embedded in the on-disk/operator
/// backup `SnapshotFile`. Prior to GitHub #1293 only the `data` keyspace
/// was captured here, silently dropping `meta` (per-record `Metadata`),
/// `index`, and every other application keyspace on snapshot install.
#[derive(Serialize, Deserialize, Clone, Default)]
struct SnapshotPayload {
    version: u32,
    /// `(keyspace name, entries)` for every non-skipped Fjall keyspace --
    /// `meta`, `data`, `index`, and every dynamic application keyspace
    /// (`domain`, `project_id`, time-bucketed OAuth2 sessions, SCIM
    /// realms, ...).
    keyspaces: Vec<(String, SnapshotKeyspaceEntries)>,
    /// Names of keyspaces that are ephemeral (in-memory-only, non-Fjall) on
    /// the snapshotting node.
    ///
    /// Values are intentionally not included: ephemeral keyspaces hold
    /// inherently short-lived data (WebAuthn/OAuth2 challenge state), so
    /// losing in-flight entries across a snapshot install is acceptable.
    /// The *names* must still survive so a node installing this snapshot
    /// keeps classifying future writes to them as ephemeral rather than
    /// Fjall-backed (see [`FjallStateMachine::ephemeral`]).
    ephemeral_keyspaces: Vec<String>,
}

/// Snapshot file format: Raft metadata + versioned payload, stored together.
#[derive(Serialize, Deserialize)]
struct SnapshotFile {
    meta: SnapshotMetaOf<TypeConfig>,
    payload: SnapshotPayload,
}

/// Fjall meta key prefix for retired DEK epochs.
const DEK_RETIRED_PREFIX: &str = "_meta:dek:retired:";
/// Fjall meta key prefix for revoked DEK epochs (emergency rotation).  Only
/// the version and revocation timestamp are stored here — never the wrapped
/// key bytes — so the compromised DEK material remains genuinely discarded
/// (ADR 0016-v2 §6.2 step 5).
pub(crate) const DEK_REVOKED_PREFIX: &str = "_meta:dek:revoked:";
/// Fjall meta key prefix for the *staged* wrapped key material of an
/// emergency-revoked DEK epoch.
///
/// Unlike `DEK_REVOKED_PREFIX` (a permanent, timestamp-only marker), this
/// entry holds the actual wrapped bytes and exists only until
/// `reencrypt_pending` confirms the epoch has been fully re-encrypted under
/// the new DEK *and* no Raft log entry still references it (ADR 0016-v2
/// §6.2 step 4, "the standard CAS-on-version flow"). Only then does
/// `FjallStateMachine::finalize_if_revoked` delete this entry and drop the
/// in-memory key, which is the actual "discard" the ADR's step 5 describes —
/// deliberately sequenced *after* step 4 completes, not before it, unlike
/// the pre-fix behaviour that revoked and discarded in the same instant
/// `InstallDek`/`ConfirmPendingRotation` applied (GitHub #1299). Without
/// this staging entry, a restart mid-sweep would lose the key forever and
/// permanently strand every not-yet-migrated record under it.
pub(crate) const DEK_REVOKED_PENDING_PREFIX: &str = "_meta:dek:revoked_pending:";
/// Fjall meta key for the current wrapped DEK.
const META_DEK_CURRENT: &[u8] = b"_meta:dek:current";
/// Fjall meta key prefix for pending emergency rotations.
const PENDING_ROTATION_PREFIX: &str = "_meta:rotation:pending:";
/// Dual-control confirmation window in seconds (5 minutes).
pub const PENDING_ROTATION_TTL_SECS: u64 = 300;

/// Fjall meta key prefix marking a retired DEK epoch as fully re-encrypted.
///
/// Writes always encrypt under the *current* epoch (see
/// `encrypt_and_store`), so once a background pass over a retired epoch
/// finds nothing left to migrate, no future write can ever put a new record
/// back under it — the epoch is done for good. This marker lets later
/// rotation cycles skip re-scanning the whole dataset for epochs that are
/// already fully migrated. The retired DEK material itself is retained
/// regardless, for backup decryption (ADR 0016-v2 §7).
const DEK_REENCRYPT_DONE_PREFIX: &str = "_meta:dek:reencrypt_done:";

/// Maximum number of optimistic-CAS attempts per record during background
/// re-encryption before the record is left for the next rotation cycle
/// (ADR 0016-v2 §6 step 5).
const REENCRYPT_MAX_CAS_ATTEMPTS: usize = 3;

/// Keyspaces that never hold `state_encrypt`-encrypted records and are
/// skipped by the background re-encryption sweep: `meta` holds DEK/
/// quarantine/rotation bookkeeping and per-record `Metadata` (plaintext
/// MessagePack, not state-tier ciphertext), `logs` holds the Raft log
/// (encrypted with the Log DEK via a different scheme in `log_store.rs`,
/// naturally rotated out by snapshot compaction), and `index` holds bare
/// existence markers with empty values.
const REENCRYPT_SKIP_KEYSPACES: &[&str] = &["meta", "logs", "index"];

/// Outcome of attempting to migrate a single record to the current DEK epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReencryptOutcome {
    /// Re-encrypted under the current epoch.
    Migrated,
    /// Not eligible: already under a different epoch, or the record/its
    /// metadata vanished before it could be migrated.
    AlreadyCurrent,
    /// Exhausted the CAS retry budget; left for the next rotation cycle.
    Skipped,
}

/// Summary of one background re-encryption pass over a single retired DEK
/// epoch (ADR 0016-v2 §6 step 5 / §6.2 step 4).
#[derive(Debug, Default, Clone, Copy)]
pub struct ReencryptReport {
    /// Records successfully re-encrypted under the current epoch.
    pub migrated: u64,
    /// Records that were already under a different epoch by the time they
    /// were visited.
    pub already_current: u64,
    /// Records that exhausted the CAS retry budget this pass.
    pub skipped: u64,
}

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
            ephemeral: DashMap::new(),
            raft_prometheus_metrics: Arc::new(
                crate::prometheus_metrics::KeystoneRaftPrometheusMetrics::new(),
            ),
        })
    }

    /// This node's ADR 0031 Raft Prometheus metrics. Shared (via `Arc`)
    /// with `app::Storage`, which reads it to render `/metrics` output
    /// alongside a fresh `openraft::RaftMetrics` snapshot.
    pub fn raft_prometheus_metrics(
        &self,
    ) -> &Arc<crate::prometheus_metrics::KeystoneRaftPrometheusMetrics> {
        &self.raft_prometheus_metrics
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

    /// Returns this node's currently-installed DEK epoch in its on-disk
    /// wrapped form: `(version, wrapped_bytes)`, as stored under
    /// `_meta:dek:current`.
    ///
    /// Used by the `FetchDek` gRPC handler to hand the cluster's current DEK
    /// to a node joining for the first time (ADR 0016-v2 §2.5.3) — the
    /// wrapped bytes are already in the exact format `install_fetched_dek`
    /// expects, so no unwrap/rewrap round-trip is needed on this (leader)
    /// side. By the time this node is reachable via gRPC its own startup
    /// has already run `bootstrap_dek`, which migrates any legacy
    /// (unversioned) on-disk format in place — so only the current,
    /// versioned format is ever observed here.
    pub fn current_dek_wrapped(&self) -> Result<(u32, Vec<u8>), StoreError> {
        let stored = self.meta.get(META_DEK_CURRENT)?.ok_or_else(|| {
            crate::StoreError::Other(eyre::eyre!("no DEK installed on this node yet"))
        })?;
        let stored = stored.as_ref();
        if stored.len() < 64 {
            return Err(crate::StoreError::Other(eyre::eyre!(
                "invalid DEK stored size: {} bytes",
                stored.len()
            )));
        }
        let version =
            u32::from_be_bytes(stored[..4].try_into().map_err(|_| {
                crate::StoreError::Other(eyre::eyre!("invalid DEK version prefix"))
            })?);
        Ok((version, stored[4..].to_vec()))
    }

    /// Installs a DEK epoch fetched from the cluster leader via `FetchDek`,
    /// bypassing Raft entirely.
    ///
    /// Must only be called once, before this node registers as a learner
    /// (see `Storage::join_cluster`) — at that point `data` is still empty,
    /// so overwriting the node's own bootstrap-generated placeholder DEK
    /// loses no ciphertext. Calling this after the node holds real data
    /// would strand it under the discarded epoch, since (unlike a
    /// Raft-replicated `InstallDek`) no `old_deks` retirement entry is
    /// written here.
    ///
    /// Fails closed, without persisting anything, if `wrapped_dek` cannot be
    /// unwrapped with this node's own KEK — which signals the KEK material
    /// differs from the leader's (ADR 0016-v2 §2.5), a misconfiguration that
    /// must abort the join rather than silently fall back to a private DEK.
    pub fn install_fetched_dek(
        &self,
        dek_version: u32,
        wrapped_dek: &[u8],
    ) -> Result<(), StoreError> {
        if !self.data.is_empty()? {
            return Err(StoreError::Other(eyre::eyre!(
                "refusing to install fetched DEK version {dek_version}: this node already \
                 holds data under its own DEK epoch (join_cluster must call this before the \
                 node registers as a learner, while `data` is still empty)"
            )));
        }
        let raw = self.kek.unwrap_dek(wrapped_dek)?;
        let locked = LockedKey::from_raw(*raw);
        let epoch = Arc::new(DekEpoch::from_raw(locked, dek_version)?);

        let mut persisted = dek_version.to_be_bytes().to_vec();
        persisted.extend_from_slice(wrapped_dek);
        self.meta.insert(META_DEK_CURRENT, &persisted)?;
        self.db.persist(PersistMode::SyncAll)?;

        let mut guard = self.dek.write().unwrap_or_else(|p| p.into_inner());
        *guard = epoch;
        Ok(())
    }

    /// Returns this node's retired-but-still-readable DEK epochs in their
    /// on-disk wrapped form: `(version, wrapped_bytes)` for each entry under
    /// `_meta:dek:retired:*`.
    ///
    /// A rotation's background re-encryption sweep (`reencrypt_pending`) is
    /// best-effort and asynchronous, so records under a retired epoch can
    /// remain un-migrated for a while after `InstallDek` commits. Used by
    /// the `FetchDek` gRPC handler alongside `current_dek_wrapped` so a
    /// joining node can decrypt such records too, not just ones under the
    /// current epoch.
    pub fn retired_deks_wrapped(&self) -> Result<Vec<(u32, Vec<u8>)>, StoreError> {
        let mut out = Vec::new();
        for item in self.meta.prefix(DEK_RETIRED_PREFIX.as_bytes()) {
            let (key_bytes, wrapped) = item.into_inner()?;
            let Ok(key_str) = std::str::from_utf8(&key_bytes) else {
                continue;
            };
            let Some(version_str) = key_str.strip_prefix(DEK_RETIRED_PREFIX) else {
                continue;
            };
            let Ok(version) = version_str.parse::<u32>() else {
                tracing::warn!(
                    key = key_str,
                    "retired DEK key has non-numeric version suffix"
                );
                continue;
            };
            out.push((version, wrapped.to_vec()));
        }
        Ok(out)
    }

    /// Installs a retired DEK epoch fetched from the cluster leader via
    /// `FetchDek`, bypassing Raft entirely.
    ///
    /// Companion to `install_fetched_dek`, called once per retired epoch the
    /// leader reports, under the same ordering and safety constraints (must
    /// run before this node registers as a learner). Populates both
    /// `old_deks` (in-memory, consulted by `decrypt_state_by_version`) and
    /// the on-disk `_meta:dek:retired:<version>` record, matching what a
    /// normal `InstallDek` apply writes -- but does **not** `fsync`, since a
    /// caller adopting several retired epochs in a loop (`join_cluster`)
    /// would otherwise pay one `PersistMode::SyncAll` per epoch. The caller
    /// must call `self.db.persist(PersistMode::SyncAll)` itself once, after
    /// its last `install_fetched_retired_dek` call, or the on-disk record
    /// won't survive a crash before the next unrelated persist.
    ///
    /// Fails closed, without writing anything, if `wrapped_dek` cannot be
    /// unwrapped with this node's own KEK.
    pub fn install_fetched_retired_dek(
        &self,
        dek_version: u32,
        wrapped_dek: &[u8],
    ) -> Result<(), StoreError> {
        if !self.data.is_empty()? {
            return Err(StoreError::Other(eyre::eyre!(
                "refusing to install fetched retired DEK version {dek_version}: this node \
                 already holds data (join_cluster must call this before the node registers as \
                 a learner, while `data` is still empty)"
            )));
        }
        let raw = self.kek.unwrap_dek(wrapped_dek)?;
        let locked = LockedKey::from_raw(*raw);
        let epoch = Arc::new(DekEpoch::from_raw(locked, dek_version)?);

        let retired_key = format!("{DEK_RETIRED_PREFIX}{dek_version}");
        self.meta.insert(retired_key.as_bytes(), wrapped_dek)?;

        let mut old_deks = self.old_deks.lock().unwrap_or_else(|p| p.into_inner());
        old_deks.insert(dek_version, epoch);
        Ok(())
    }

    /// Return the path to the snapshot directory.
    pub(crate) fn snapshot_dir(&self) -> &std::path::Path {
        &self.snapshot_dir
    }

    /// Return the path of the most recently written snapshot file, if any.
    ///
    /// Snapshot filenames sort lexicographically by `<leader_id>-<index>-<rand>`, so the
    /// lexicographically greatest filename is the latest snapshot. openraft 0.10 dropped
    /// `snapshot_id` from `SnapshotMeta`, so callers that need the on-disk path (rather than
    /// going through `RaftStateMachine::get_current_snapshot`) must locate it this way.
    pub(crate) fn latest_snapshot_path(&self) -> io::Result<Option<std::path::PathBuf>> {
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

        Ok(latest_snapshot_id.map(|id| self.snapshot_dir.join(id)))
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

        let data_bytes = rmp_serde::to_vec(&snapshot_file.payload)
            .map_err(|e| crate::StoreError::Other(eyre::eyre!("snapshot re-serialize: {e}")))?;

        let snapshot = openraft::storage::Snapshot {
            meta: snapshot_file.meta,
            snapshot: data_bytes,
        };
        Ok((snapshot, utc_epoch, dek_version))
    }

    /// Collects a consistent, point-in-time snapshot payload: every
    /// replicated Fjall keyspace's full contents (everything except
    /// [`SNAPSHOT_SKIP_KEYSPACES`]) plus the ephemeral keyspace name
    /// registry.
    ///
    /// Uses a single cross-keyspace Fjall `snapshot()` so every keyspace is
    /// captured at the same point in the LSM sequence, not just internally
    /// consistent per-keyspace.
    ///
    /// Holds `keyspace_lifecycle`'s read side for the whole capture — same
    /// lock `apply()` holds — so a concurrent `drop_keyspace`/`install_snapshot`
    /// (both write-side) can't create or remove a keyspace between the
    /// `db.snapshot()` call and the `list_keyspace_names()` walk, and can't
    /// tear one down mid-iteration either.
    fn snapshot_payload(&self) -> Result<SnapshotPayload, io::Error> {
        let _lifecycle_guard = self
            .keyspace_lifecycle
            .read()
            .unwrap_or_else(|p| p.into_inner());
        let db_snapshot = self.db.snapshot();
        let mut keyspaces = Vec::new();
        for name in self.db.list_keyspace_names() {
            let name = name.to_string();
            if SNAPSHOT_SKIP_KEYSPACES.contains(&name.as_str()) {
                continue;
            }
            let ks = self
                .keyspace(&name)
                .map_err(|e| io::Error::other(e.to_string()))?;
            let mut entries = Vec::new();
            for item in db_snapshot.iter(&ks) {
                let (key, value) = item
                    .into_inner()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                entries.push((key.to_vec(), value.to_vec()));
            }
            keyspaces.push((name, entries));
        }

        let ephemeral_keyspaces = self
            .ephemeral
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        Ok(SnapshotPayload {
            version: SNAPSHOT_FORMAT_VERSION,
            keyspaces,
            ephemeral_keyspaces,
        })
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
        self.decrypt_state_by_version_raw(stored, tier, keyspace, pk, partition, hint)
            .map(|(plaintext, _next_version)| plaintext)
    }

    /// Same deterministic-epoch selection as [`Self::decrypt_state_by_version`],
    /// but also returns the record's next nonce version (`stored_version + 1`,
    /// per [`state_decrypt`]'s contract).
    ///
    /// Shared with [`Self::encrypt_and_store`], which needs that version to
    /// continue the per-record nonce counter across a DEK rotation instead
    /// of guessing at it by decrypting with the wrong (current) epoch and
    /// falling back to `0` on the resulting GCM failure (GitHub #1295) —
    /// which both broke the documented "monotonic per-record version"
    /// invariant and let a write silently overwrite a genuinely tampered
    /// record instead of counting it toward quarantine.
    fn decrypt_state_by_version_raw(
        &self,
        stored: &[u8],
        tier: u8,
        keyspace: &[u8],
        pk: &[u8],
        partition: &str,
        hint: u32,
    ) -> Result<(Vec<u8>, u32), StoreError> {
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
                // Distinguish "legitimately revoked and now fully discarded"
                // (ADR 0016-v2 §6.2) from "genuinely unknown/corrupt": by
                // the time a revoked epoch's key is actually gone from
                // `old_deks`, `finalize_if_revoked` has already confirmed
                // every record was re-encrypted away from it, so hitting
                // this for a real record should not happen — but if it
                // ever does, it is a clean security outcome, not data
                // corruption, and must not trip the quarantine threshold.
                if self
                    .revoked_deks
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .contains(&hint)
                {
                    return Err(openstack_keystone_storage_crypto::CryptoError::RevokedDek {
                        version: hint,
                    }
                    .into());
                }
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
            Ok((plaintext, next_version)) => Ok((plaintext.to_vec(), next_version)),
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
                for old in old_map.values() {
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

        // Read existing version (0 for new keys), decrypting with the exact
        // DEK epoch the existing record was written under (its recorded
        // `Metadata::dek_version`, ADR 0016-v2 §6 step 6) rather than always
        // trying the *current* epoch. A record still pending re-encryption
        // under a retired epoch would otherwise always fail GCM
        // verification against the current DEK; falling back to
        // `unwrap_or(0)` on that failure reset the documented "monotonic
        // per-record version" and, worse, made it indistinguishable from a
        // genuinely tampered record silently being overwritten instead of
        // counted toward quarantine (GitHub #1295).
        let next_version = if let Some(existing) = ks.get(key)? {
            let dek_version_hint = self
                .meta
                .get(meta_key(&partition, key))?
                .map(|m| Metadata::unpack(m.as_ref()))
                .transpose()?
                .and_then(|m| m.dek_version);

            match dek_version_hint {
                Some(hint) => {
                    self.decrypt_state_by_version_raw(
                        existing.as_ref(),
                        tier,
                        keyspace,
                        key,
                        &partition,
                        hint,
                    )?
                    .1
                }
                None => {
                    // Legacy record predating per-record DEK-version
                    // tracking: there is no recorded epoch to target
                    // deterministically, so fall back to the current DEK
                    // only, same as before this fix (backward-compatible
                    // best effort for pre-migration data only — every
                    // write now populates `dek_version`).
                    let guard = self.dek.read().unwrap_or_else(|p| p.into_inner());
                    state_decrypt(guard.state_dek(), existing.as_ref(), tier, keyspace, key)
                        .map(|(_, v)| v)
                        .unwrap_or(0)
                }
            }
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

    /// Sweep every retired-but-not-yet-fully-migrated DEK epoch and
    /// re-encrypt whatever records remain under it (ADR 0016-v2 §6 step 5 /
    /// §6.2 step 4).
    ///
    /// Called whenever a DEK rotation completes. Rather than only sweeping
    /// the epoch that was *just* retired, this revisits every epoch in
    /// `old_deks` that isn't marked fully migrated yet — this is what gives
    /// a record that exhausted its CAS retry budget on one rotation cycle
    /// another chance on the next one, per ADR 0016-v2 §6 step 5 ("skipped
    /// keys are ... automatically retried on the next scheduled rotation
    /// cycle") without needing a separate timer.
    ///
    /// Runs entirely locally on this node: `InstallDek` is Raft-committed
    /// and applied identically on every node, and `state_encrypt`/
    /// `state_decrypt` are deterministic given `(tier, keyspace, pk,
    /// version)`, so every node converges on the same ciphertext
    /// independently — the re-encryption writes themselves don't need a
    /// second consensus round.
    pub async fn reencrypt_pending(&self) {
        let epochs: Vec<Arc<DekEpoch>> = {
            let map = self.old_deks.lock().unwrap_or_else(|p| p.into_inner());
            map.values().cloned().collect()
        };

        for epoch in epochs {
            let done_key = format!("{DEK_REENCRYPT_DONE_PREFIX}{}", epoch.version);
            if matches!(self.meta.get(done_key.as_bytes()), Ok(Some(_))) {
                // Already fully migrated: for a normal retired epoch there
                // is nothing left to do. But an emergency-revoked epoch may
                // still be sitting in `old_deks` waiting on
                // `finalize_if_revoked`'s log-purge condition to become
                // true -- give it another chance every sweep rather than
                // skipping it (and thus its only remaining finalize
                // opportunity) forever.
                self.finalize_if_revoked(&epoch).await;
                continue;
            }

            let report = self.reencrypt_epoch(&epoch).await;
            tracing::info!(
                old_version = epoch.version,
                migrated = report.migrated,
                already_current = report.already_current,
                skipped = report.skipped,
                "DEK rotation: background re-encryption pass complete"
            );

            if report.skipped == 0 {
                // A clean pass with nothing left to retry: since writes
                // always target the *current* epoch, no record can ever
                // reappear under this retired one. Safe to never sweep it
                // again.
                if let Err(e) = self.meta.insert(done_key.as_bytes(), b"1") {
                    tracing::warn!(
                        old_version = epoch.version,
                        error = %e,
                        "failed to persist re-encryption completion marker; \
                         epoch will be re-swept on the next rotation cycle"
                    );
                } else {
                    tracing::info!(
                        old_version = epoch.version,
                        "DEK rotation: epoch fully re-encrypted; retired DEK retained for \
                         backup decryption only (ADR 0016-v2 §7)"
                    );
                    self.finalize_if_revoked(&epoch).await;
                }
            } else {
                tracing::warn!(
                    old_version = epoch.version,
                    skipped = report.skipped,
                    "DEK rotation: some records could not be re-encrypted this pass; \
                     will retry on the next rotation cycle (ADR 0016-v2 §6 step 5)"
                );
            }
        }
    }

    /// If `epoch` was revoked by an emergency rotation (ADR 0016-v2 §6.2)
    /// and its re-encryption sweep just completed cleanly, permanently
    /// discard the key material: this is the ADR's step 5 "discard",
    /// deliberately performed only *after* step 4's re-encryption has
    /// actually finished, rather than racing ahead of it the way the
    /// pre-fix code did (GitHub #1299). A no-op for a normal (non-revoked)
    /// retired epoch, which is kept forever for backup decryption (§7).
    ///
    /// Also requires that no Raft log entry still carries this epoch's
    /// `dek_version` tag — otherwise a lagging follower replicating an
    /// old entry, or this node replaying its own log after a restart,
    /// would hit an unreadable entry the moment the key is gone. If any
    /// remain, finalization is deferred to the next sweep; they are
    /// eventually compacted away by ordinary Raft snapshot/log-purge
    /// activity.
    async fn finalize_if_revoked(&self, epoch: &Arc<DekEpoch>) {
        let version = epoch.version;
        if !self
            .revoked_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(&version)
        {
            return;
        }

        let remaining_log_entries = self.count_log_entries_under_version(version);
        if remaining_log_entries > 0 {
            tracing::warn!(
                version,
                remaining_log_entries,
                "DEK rotation: emergency-revoked epoch fully re-encrypted in state but \
                 still referenced by un-compacted Raft log entries; deferring key discard \
                 until they are purged"
            );
            return;
        }

        // Force a fresh snapshot under the current epoch before dropping the
        // revoked key, so no on-disk snapshot is ever left depending on a
        // key that is about to become permanently unrecoverable (a
        // restart, or a new node joining via `install_snapshot`, would
        // otherwise be unable to decrypt it).
        let mut snapshot_sm = Arc::new(self.clone());
        if let Err(e) = snapshot_sm.build_snapshot().await {
            tracing::error!(
                version,
                error = %e,
                "DEK rotation: failed to build a fresh snapshot before discarding revoked \
                 epoch; deferring key discard"
            );
            return;
        }

        self.old_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&version);

        let revoked_pending_key = format!("{DEK_REVOKED_PENDING_PREFIX}{version}");
        if let Err(e) = self.meta.remove(revoked_pending_key.as_bytes()) {
            tracing::warn!(
                version,
                error = %e,
                "failed to remove staged emergency-rotation key material marker; it will \
                 be harmlessly reloaded and re-finalized on next restart"
            );
        }

        tracing::warn!(
            version,
            "SECURITY: emergency-revoked DEK version fully re-encrypted, compacted, and \
             now permanently discarded (ADR 0016-v2 §6.2 step 5)"
        );
    }

    /// Best-effort count of Raft log entries still tagged with `version` in
    /// their on-disk `dek_version` prefix (see `log_store.rs`'s entry
    /// layout). Returns `0` if the `logs` keyspace could not even be
    /// opened — finalization is simply deferred to the next sweep rather
    /// than blocked on an error here.
    fn count_log_entries_under_version(&self, version: u32) -> usize {
        let Ok(logs) = self.db.keyspace("logs", KeyspaceCreateOptions::default) else {
            return 0;
        };
        let version_prefix = version.to_be_bytes();
        logs.iter()
            .filter_map(|item| item.into_inner().ok())
            .filter(|(_, value)| value.len() >= 4 && value[..4] == version_prefix)
            .count()
    }

    /// Re-encrypt every record still under `old_epoch` to the current epoch,
    /// walking all non-system keyspaces in key-sorted order.
    async fn reencrypt_epoch(&self, old_epoch: &DekEpoch) -> ReencryptReport {
        let mut report = ReencryptReport::default();

        for name in self.db.list_keyspace_names() {
            let keyspace_name = name.to_string();
            if REENCRYPT_SKIP_KEYSPACES.contains(&keyspace_name.as_str()) {
                continue;
            }
            let Ok(ks) = self
                .db
                .keyspace(&keyspace_name, KeyspaceCreateOptions::default)
            else {
                continue;
            };

            // Snapshot keys up front (key-sorted, per ADR 0016-v2 §6 step 5):
            // re-encryption mutates the keyspace while we walk it, so a live
            // iterator could otherwise observe its own writes.
            let keys: Vec<Vec<u8>> = ks
                .iter()
                .filter_map(|item| item.into_inner().ok())
                .map(|(k, _)| k.to_vec())
                .collect();

            for key in keys {
                // Yield periodically so a large keyspace doesn't starve the
                // Raft apply loop or other tasks on this node.
                tokio::task::yield_now().await;

                match self.reencrypt_one(&ks, &keyspace_name, &key, old_epoch) {
                    ReencryptOutcome::Migrated => report.migrated += 1,
                    ReencryptOutcome::AlreadyCurrent => report.already_current += 1,
                    ReencryptOutcome::Skipped => {
                        report.skipped += 1;
                        tracing::warn!(
                            keyspace = keyspace_name,
                            key = %String::from_utf8_lossy(&key),
                            old_version = old_epoch.version,
                            "DEK rotation: record skipped after exhausting CAS retries"
                        );
                    }
                }
            }
        }

        report
    }

    /// Attempt to migrate a single record from `old_epoch` to the current
    /// DEK epoch, retrying up to `REENCRYPT_MAX_CAS_ATTEMPTS` times if it
    /// finds the record already advanced past `old_epoch` by the time it
    /// gets a chance to run (ADR 0016-v2 §6 step 5: "optimistic concurrency
    /// control (CAS on version)").
    ///
    /// The Fjall `Keyspace`/`Batch` API this crate uses has no built-in
    /// compare-and-swap, so each attempt takes `keyspace_lifecycle`'s write
    /// side for its whole read-decrypt-recompute-commit sequence.
    /// `apply()` holds that lock's read side for an entry's whole
    /// processing+commit (see its use in `apply()` below), so this
    /// guarantees no `apply()` write to this key can land between the read
    /// this function bases its computation on and the `batch.commit()`
    /// that lands it — closing the gap a prior "read -> compute -> re-read
    /// -> commit" CAS left open, where a write landing between the re-read
    /// and the commit was silently reverted (GitHub #1295: the old
    /// comment's claim that this "never corrupts data" was wrong — it
    /// could revert an already Raft-committed write on this node only,
    /// diverging it from the rest of the cluster with no Raft-visible
    /// signal). The retry loop now only exists for the ordinary case where
    /// the record was migrated (or deleted) by an earlier pass before this
    /// one got the lock.
    fn reencrypt_one(
        &self,
        ks: &Keyspace,
        keyspace_name: &str,
        key: &[u8],
        old_epoch: &DekEpoch,
    ) -> ReencryptOutcome {
        for _ in 0..REENCRYPT_MAX_CAS_ATTEMPTS {
            let _lifecycle_guard = self
                .keyspace_lifecycle
                .write()
                .unwrap_or_else(|p| p.into_inner());

            let Ok(Some(before)) = ks.get(key) else {
                return ReencryptOutcome::AlreadyCurrent; // deleted concurrently
            };
            let Ok(Some(meta_bytes)) = self.meta.get(meta_key(keyspace_name, key)) else {
                return ReencryptOutcome::AlreadyCurrent; // metadata gone
            };
            let Ok(metadata) = Metadata::unpack(meta_bytes.as_ref()) else {
                return ReencryptOutcome::Skipped;
            };
            if metadata.dek_version != Some(old_epoch.version) {
                // Already advanced by a previous re-encryption pass (or
                // never under this epoch to begin with) — an `apply()`
                // write can't be the cause while we hold the lock above,
                // and couldn't have raced this check before we took it
                // either, since `apply()` needs the same lock's read side.
                return ReencryptOutcome::AlreadyCurrent;
            }

            let tier = metadata.tier as u8;
            let Ok((plaintext, stored_version)) = state_decrypt(
                old_epoch.state_dek(),
                before.as_ref(),
                tier,
                keyspace_name.as_bytes(),
                key,
            ) else {
                return ReencryptOutcome::Skipped;
            };

            let (encrypted, new_version) = {
                let guard = self.dek.read().unwrap_or_else(|p| p.into_inner());
                if guard.version == old_epoch.version {
                    // No newer epoch installed yet — nothing to migrate to.
                    return ReencryptOutcome::AlreadyCurrent;
                }
                let Ok(encrypted) = state_encrypt(
                    guard.state_dek(),
                    plaintext.as_ref(),
                    tier,
                    keyspace_name.as_bytes(),
                    key,
                    stored_version + 1,
                ) else {
                    return ReencryptOutcome::Skipped;
                };
                (encrypted, guard.version)
            };

            let mut new_metadata = metadata.clone();
            new_metadata.dek_version = Some(new_version);
            let Ok(new_meta_bytes) = new_metadata.pack() else {
                return ReencryptOutcome::Skipped;
            };

            // No re-read-before-commit CAS needed here: `_lifecycle_guard`
            // above has excluded every `apply()` write to this key since
            // before `before`/`meta_bytes` were read, so neither can have
            // changed underneath us.
            let mut batch = self.db.batch();
            batch.insert(ks, key.to_vec(), encrypted);
            batch.insert(&self.meta, meta_key(keyspace_name, key), new_meta_bytes);
            if batch.commit().is_err() {
                continue;
            }
            return ReencryptOutcome::Migrated;
        }
        ReencryptOutcome::Skipped
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

/// Checks a decoded snapshot payload's format version against
/// [`SNAPSHOT_FORMAT_VERSION`], returning the mismatch message shared by
/// every call site so a future version-check change (e.g. a min-supported
/// range) only needs to be made once.
fn check_snapshot_format_version(version: u32) -> Result<(), String> {
    if version != SNAPSHOT_FORMAT_VERSION {
        return Err(format!(
            "unsupported snapshot format version {version} (this node expects {SNAPSHOT_FORMAT_VERSION})"
        ));
    }
    Ok(())
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

    let file: SnapshotFile = rmp_serde::from_slice(&file_bytes)
        .map_err(|e| crate::StoreError::Other(eyre::eyre!("snapshot deserialize: {e}")))?;
    check_snapshot_format_version(file.payload.version)
        .map_err(|e| crate::StoreError::Other(eyre::eyre!(e)))?;
    Ok((file, dek_version, utc_epoch))
}

impl RaftSnapshotBuilder<TypeConfig> for Arc<FjallStateMachine> {
    type SnapshotData = Vec<u8>;

    #[tracing::instrument(level = "trace", skip(self))]
    async fn build_snapshot(&mut self) -> Result<SnapshotOf<TypeConfig, Vec<u8>>, io::Error> {
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
        };

        tracing::trace!("snapshot metadata: {:?}", meta);

        let payload = self.snapshot_payload()?;

        let snapshot_file = SnapshotFile {
            meta: meta.clone(),
            payload: payload.clone(),
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

        let data_bytes = serialize(&payload).map_err(|e| {
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
    type SnapshotData = Vec<u8>;
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
    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMetaOf<TypeConfig>,
        snapshot: Vec<u8>,
    ) -> Result<(), io::Error> {
        tracing::info!(
            { snapshot_size = snapshot.len() },
            "decoding snapshot for installation"
        );

        let payload: SnapshotPayload = deserialize(snapshot.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        check_snapshot_format_version(payload.version)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let payload_clone = payload.clone();

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

        // Guards the whole clear-and-repopulate sweep below against a
        // concurrent `apply()`/`drop_keyspace` — same rationale as
        // `drop_keyspace`'s use of this lock: without it, a keyspace we're
        // mid-clearing here could be concurrently written to or deleted out
        // from under this install.
        let _lifecycle_guard = self
            .keyspace_lifecycle
            .write()
            .unwrap_or_else(|p| p.into_inner());

        // Every replicated keyspace that currently exists on this node, plus
        // every keyspace named in the incoming snapshot: the union is what
        // must be cleared, so a keyspace this node still has but the
        // snapshot no longer carries ends up empty rather than stale
        // (GitHub #1293 point 3).
        let mut touched: HashSet<String> = self
            .db
            .list_keyspace_names()
            .into_iter()
            .map(|name| name.to_string())
            .filter(|name| !SNAPSHOT_SKIP_KEYSPACES.contains(&name.as_str()))
            .collect();
        for (name, _) in &payload.keyspaces {
            if !SNAPSHOT_SKIP_KEYSPACES.contains(&name.as_str()) {
                touched.insert(name.clone());
            }
        }

        let mut batch = self.db.batch();

        for name in &touched {
            let ks = self
                .keyspace(name)
                .map_err(|e| io::Error::other(e.to_string()))?;
            for current in ks.iter() {
                if let Ok(k) = current.key() {
                    batch.remove(&ks, k);
                }
            }
        }

        for (name, entries) in payload.keyspaces {
            if SNAPSHOT_SKIP_KEYSPACES.contains(&name.as_str()) {
                continue;
            }
            let ks = self
                .keyspace(&name)
                .map_err(|e| io::Error::other(e.to_string()))?;
            for (key, value) in entries {
                batch.insert(&ks, key, value);
            }
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

        // Reset the in-memory ephemeral keyspace registry to the snapshot's
        // ground truth: stale names from before this install are dropped,
        // and every name the snapshot lists is restored so future writes to
        // it keep being classified as ephemeral rather than Fjall-backed.
        self.ephemeral.clear();
        for name in &payload_clone.ephemeral_keyspaces {
            self.ephemeral.entry(name.clone()).or_default();
        }

        drop(_lifecycle_guard);

        let snapshot_idx: u64 = rand::rng().random_range(0..1000);
        let snapshot_id = if let Some(last) = meta.last_log_id.as_ref() {
            format!(
                "{}-{}-{}",
                last.committed_leader_id(),
                last.index(),
                snapshot_idx
            )
        } else {
            format!("--{}", snapshot_idx)
        };

        let snapshot_file = SnapshotFile {
            meta: meta.clone(),
            payload: payload_clone,
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

        let snapshot_path = self.snapshot_dir.join(&snapshot_id);
        fs::write(&snapshot_path, &disk_bytes)?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<SnapshotOf<TypeConfig, Vec<u8>>>, io::Error> {
        let Some(snapshot_path) = self.latest_snapshot_path()? else {
            return Ok(None);
        };

        let disk_bytes = fs::read(&snapshot_path)?;
        let (snapshot_file, _, _) =
            decrypt_snapshot_file(&disk_bytes, &self.dek, &self.old_deks)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let data_bytes = rmp_serde::to_vec(&snapshot_file.payload)
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
            // ADR 0031 `keystone_raft_apply_duration_seconds`: measures one
            // committed log entry's full apply — write/encrypt, commit, and
            // the fsync-equivalent `persist(SyncAll)` below — a real
            // per-operation latency, unlike the read-through snapshot gauges
            // in `prometheus_metrics`.
            let apply_start = Instant::now();
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
                                    check_keyspace_allowed(&keyspace)?;

                                    if let Some(ephemeral_ks) = self.ephemeral.get(&keyspace) {
                                        if let Some(expected_revision) = expected_revision {
                                            let curr_revision = ephemeral_ks
                                                .get(&key)
                                                .map(|entry| entry.1.revision);
                                            if curr_revision.is_none_or(|r| r != expected_revision)
                                            {
                                                violations.push(Violation {
                                                    r#type: "CONFLICT".to_string(),
                                                    subject: String::from_utf8_lossy(&key)
                                                        .to_string(),
                                                    description: format!(
                                                        "Current revision is {curr_revision:?} \
                                                         while {expected_revision} was expected",
                                                    ),
                                                });
                                                continue;
                                            }
                                        }
                                        ephemeral_ks.remove(&key);
                                        continue;
                                    }

                                    if let Some(expected_revision) = expected_revision {
                                        let curr_meta = self
                                            .meta()
                                            .get(meta_key(&keyspace, &key))
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

                                    let ks = &self.keyspace(&keyspace)?;
                                    batch.remove(ks, key.clone());
                                    batch.remove(&self.meta, meta_key(&keyspace, &key));
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
                                    check_keyspace_allowed(&keyspace)?;

                                    if metadata.is_ephemeral {
                                        let ephemeral_ks =
                                            self.ephemeral.entry(keyspace.clone()).or_default();
                                        if let Some(expected_revision) = expected_revision {
                                            let curr_revision = ephemeral_ks
                                                .get(&key)
                                                .map(|entry| entry.1.revision);
                                            if curr_revision.is_none_or(|r| r != expected_revision)
                                            {
                                                violations.push(Violation {
                                                    r#type: "CONFLICT".to_string(),
                                                    subject: String::from_utf8_lossy(&key)
                                                        .to_string(),
                                                    description: format!(
                                                        "Current revision is {curr_revision:?} \
                                                         while {expected_revision} was expected",
                                                    ),
                                                });
                                                continue;
                                            }
                                        }
                                        ephemeral_ks.insert(key, (cipher, metadata));
                                        continue;
                                    }

                                    if let Some(expected_revision) = expected_revision {
                                        let curr_meta = self
                                            .meta()
                                            .get(meta_key(&keyspace, &key))
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
                                                meta_key(&keyspace, &key),
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
                                    check_keyspace_allowed(&keyspace)?;

                                    if metadata.is_ephemeral {
                                        let ephemeral_ks =
                                            self.ephemeral.entry(keyspace.clone()).or_default();
                                        if ephemeral_ks.contains_key(&key) {
                                            violations.push(Violation {
                                                r#type: "CONFLICT".to_string(),
                                                subject: String::from_utf8_lossy(&key).to_string(),
                                                description:
                                                    "key already exists (create_if_absent)"
                                                        .to_string(),
                                            });
                                            continue;
                                        }
                                        ephemeral_ks.insert(key, (cipher, metadata));
                                        continue;
                                    }

                                    let exists = self
                                        .meta()
                                        .get(meta_key(&keyspace, &key))
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
                                                meta_key(&keyspace, &key),
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
                                        // so containment survives a restart (ADR 0016-v2
                                        // §6.2 step 2). This timestamp-only marker is
                                        // permanent and is never removed.
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

                                        // Also stage the old epoch's wrapped bytes under a
                                        // *separate*, temporary prefix so the re-encryption
                                        // sweep this rotation still requires (ADR §6.2 step
                                        // 4) survives a restart before it completes.
                                        // `reencrypt_pending` deletes this entry the moment
                                        // the sweep confirms every record has migrated and
                                        // no log entry still references it — only then is
                                        // the compromised key genuinely discarded (step 5).
                                        let revoked_pending_key =
                                            format!("{DEK_REVOKED_PENDING_PREFIX}{old_version}");
                                        match self.meta.get(META_DEK_CURRENT) {
                                            Ok(Some(cur)) if cur.len() > 4 => {
                                                batch.insert(
                                                    &self.meta,
                                                    revoked_pending_key.as_bytes(),
                                                    &cur[4..],
                                                );
                                            }
                                            _ => {
                                                tracing::error!(
                                                    old_version,
                                                    "SECURITY: could not read current DEK \
                                                     bytes to stage emergency re-encryption; \
                                                     records under the revoked epoch may \
                                                     become permanently unreadable"
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

                                            // Dual-control-confirmed emergency rotation:
                                            // same containment + staged-re-encryption
                                            // bookkeeping as `InstallDek`'s emergency
                                            // branch (ADR 0016-v2 §6.2 steps 2, 4) — this
                                            // path used to skip both durable writes
                                            // entirely, silently losing revocation status
                                            // and the re-encryption key on restart
                                            // (GitHub #1299).
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
                                            let revoked_pending_key = format!(
                                                "{DEK_REVOKED_PENDING_PREFIX}{old_version}"
                                            );
                                            match self.meta.get(META_DEK_CURRENT) {
                                                Ok(Some(cur)) if cur.len() > 4 => {
                                                    batch.insert(
                                                        &self.meta,
                                                        revoked_pending_key.as_bytes(),
                                                        &cur[4..],
                                                    );
                                                }
                                                _ => {
                                                    tracing::error!(
                                                        old_version,
                                                        rotation_id,
                                                        "SECURITY: could not read current \
                                                         DEK bytes to stage emergency \
                                                         re-encryption; records under the \
                                                         revoked epoch may become \
                                                         permanently unreadable"
                                                    );
                                                }
                                            }

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
                                MutationInner::AbortPendingRotation { rotation_id } => {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    let mut pending = self
                                        .pending_rotations
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner());
                                    // Defensive re-check: only remove if still present and
                                    // actually expired. A ConfirmRotateDek may have raced
                                    // ahead of the sweeper and already resolved this entry,
                                    // or the sweeper's read may have been stale — either
                                    // way this is a silent no-op, not a violation.
                                    if let Some(entry) = pending.get(&rotation_id)
                                        && entry.expires_at <= now
                                    {
                                        let removed = pending.remove(&rotation_id);
                                        drop(pending);
                                        if let Some(entry) = removed {
                                            let meta_key =
                                                format!("{PENDING_ROTATION_PREFIX}{rotation_id}");
                                            batch.remove(&self.meta, meta_key.as_bytes());
                                            tracing::warn!(
                                                rotation_id,
                                                initiator = entry.initiator,
                                                expires_at = entry.expires_at,
                                                "SECURITY: emergency DEK rotation confirmation \
                                                 window expired with no confirmation — \
                                                 automatically aborted (ADR 0016-v2 §6.2 step 1)"
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
                        // Emergency: old DEK is revoked, not retired — but it
                        // must still go through the standard re-encryption
                        // sweep before its key material is discarded (ADR
                        // 0016-v2 §6.2 step 4 runs *before* step 5). Dropping
                        // it here immediately, as this used to do, silently
                        // and permanently loses every record, in-flight log
                        // entry, and local snapshot still under this epoch
                        // (GitHub #1299). `revoked_deks` still marks the
                        // version as compromised so it is never handed to a
                        // joining node (`FetchDek`) or reused for anything
                        // new; `finalize_if_revoked` (called from
                        // `reencrypt_pending`) removes it from `old_deks` —
                        // the actual, final discard — only once the sweep
                        // confirms nothing needs the key anymore.
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
                            "SECURITY: emergency DEK rotation — old DEK version revoked; \
                             re-encryption sweep starting before the key is discarded \
                             (ADR 0016-v2 §6.2 step 4)"
                        );
                    }
                    // Register old epoch for state/log read fallback during
                    // re-encryption -- for an emergency rotation this is
                    // temporary (see comment above); for a normal rotation
                    // it is kept forever for backup decryption (ADR §7).
                    self.old_deks
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(old_epoch.version, old_epoch.clone());
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

            self.raft_prometheus_metrics
                .apply_duration_seconds
                .record(apply_start.elapsed().as_secs_f64());

            if let Some(responder) = responder {
                responder.send(crate::ZeroizingResponse {
                    value: response.0.map(zeroize::Zeroizing::new),
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

    /// `retired_deks_wrapped`/`install_fetched_retired_dek` round-trip:
    /// records a leader retires on rotation must still be decryptable by a
    /// node that only adopted them via `FetchDek` (GitHub issue #1298) —
    /// not just records under the current epoch.
    #[test]
    fn fetch_and_install_retired_dek_round_trips() {
        let kek: Arc<dyn KekProvider> = Arc::new(EnvKek::from_bytes([0x42u8; 32]));

        // --- "Leader" side: encrypt a record under epoch 1, then rotate to
        //     epoch 2 and persist epoch 1's wrapped bytes as retired, the
        //     same way `InstallDek`'s apply() does.
        let raw_v1 = [0xAAu8; 32];
        let wrapped_v1 = kek.wrap_dek(&raw_v1).expect("wrap v1");
        let epoch_v1 = Arc::new(
            DekEpoch::from_raw(LockedKey::from_raw(raw_v1), 1).expect("construct epoch 1"),
        );
        let (leader_sm, _td1) = make_sm(epoch_v1);

        let ks = leader_sm.data().clone();
        let (ciphertext, version) = leader_sm
            .encrypt_and_store(&ks, b"k1", b"data", DataTier::Internal as u8, b"hello")
            .expect("encrypt under epoch 1");
        assert_eq!(version, 1);

        let epoch_v2 = test_epoch(0x99, 2);
        *leader_sm.dek.write().unwrap() = epoch_v2;
        leader_sm
            .meta()
            .insert(format!("{DEK_RETIRED_PREFIX}1"), &wrapped_v1)
            .expect("persist retired epoch 1");

        let retired = leader_sm.retired_deks_wrapped().expect("read retired DEKs");
        assert_eq!(retired, vec![(1, wrapped_v1.clone())]);

        // --- "Joining node" side: starts with an unrelated current epoch
        //     and no retired epochs at all, then adopts epoch 1 purely via
        //     `install_fetched_retired_dek` (as `join_cluster` would).
        let (joiner_sm, _td2) = make_sm(test_epoch(0x11, 2));
        assert!(joiner_sm.old_deks.lock().unwrap().is_empty());

        joiner_sm
            .install_fetched_retired_dek(1, &wrapped_v1)
            .expect("install fetched retired DEK");
        assert!(joiner_sm.old_deks.lock().unwrap().contains_key(&1));

        // The joining node must decrypt the leader's epoch-1 ciphertext
        // using only what `FetchDek` handed it -- the exact scenario a DEK
        // rotation's still-in-flight background re-encryption sweep leaves
        // behind.
        let plaintext = joiner_sm
            .decrypt_state(
                &ciphertext,
                DataTier::Internal as u8,
                b"data",
                b"k1",
                Some(1),
            )
            .expect("joining node decrypts leader's retired-epoch record");
        assert_eq!(plaintext, b"hello");
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

    /// Regression test for GitHub #1295 (second defect): a record still
    /// pending re-encryption under a retired epoch must have its per-record
    /// nonce version continued from where it actually was, not reset to 0
    /// by blindly decrypting the existing ciphertext with the *current*
    /// epoch (which always fails GCM verification for such a record) and
    /// falling back to `unwrap_or(0)`.
    #[test]
    fn encrypt_and_store_continues_version_across_retired_epoch_instead_of_resetting() {
        let old_epoch = test_epoch(0x30, 1);
        let (sm, _td) = make_sm(old_epoch.clone());

        let ks = sm.data().clone();
        let (ciphertext1, dek_version1) = sm
            .encrypt_and_store(&ks, b"k1", b"data", DataTier::Internal as u8, b"hello")
            .expect("first write under epoch 1");
        assert_eq!(dek_version1, 1);
        ks.insert(b"k1", ciphertext1).expect("insert ciphertext");
        let mut metadata = Metadata::new();
        metadata.dek_version = Some(dek_version1);
        sm.meta()
            .insert(
                meta_key("data", b"k1"),
                metadata.pack().expect("pack metadata"),
            )
            .expect("insert metadata");

        // Rotate: k1's record is now under a retired epoch, exactly as it
        // would be before a background re-encryption sweep reaches it.
        let new_epoch = test_epoch(0x31, 2);
        *sm.dek.write().unwrap_or_else(|p| p.into_inner()) = new_epoch.clone();
        sm.old_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(old_epoch.version, old_epoch.clone());

        // A second write to the same still-pending key must look up its
        // real epoch (1) via `Metadata::dek_version` rather than guessing
        // with the new current epoch (2).
        let (ciphertext2, dek_version2) = sm
            .encrypt_and_store(&ks, b"k1", b"data", DataTier::Internal as u8, b"world")
            .expect("second write must not error out");
        assert_eq!(dek_version2, 2);

        let (plaintext2, next_version) = state_decrypt(
            new_epoch.state_dek(),
            &ciphertext2,
            DataTier::Internal as u8,
            b"data",
            b"k1",
        )
        .expect("decrypt second write under the new current epoch");
        assert_eq!(&*plaintext2, b"world");
        assert_eq!(
            next_version, 2,
            "nonce version must continue from the record's real prior version (0 -> 1), \
             not reset to 0 by decrypting with the wrong (current) epoch"
        );
    }

    /// Regression test for GitHub #1295 (second defect): a genuinely
    /// tampered/corrupted existing record must fail the write with a
    /// `StoreError::Crypto` and count toward quarantine, not be silently
    /// overwritten as if it were merely pending re-encryption under an
    /// older epoch.
    #[test]
    fn encrypt_and_store_quarantines_instead_of_silently_overwriting_tampered_record() {
        let epoch = test_epoch(0x34, 1);
        let (sm, _td) = make_sm(epoch.clone());

        let ks = sm.data().clone();
        let (mut ciphertext, dek_version) = sm
            .encrypt_and_store(&ks, b"k1", b"data", DataTier::Internal as u8, b"hello")
            .expect("initial encrypt");
        // Flip a ciphertext byte (right after the 12-byte nonce prefix) so
        // the GCM tag no longer verifies -- simulates tampering, as
        // opposed to the record merely being under a different epoch.
        ciphertext[12] ^= 0xFF;
        ks.insert(b"k1", ciphertext.clone())
            .expect("insert tampered ciphertext");
        let mut metadata = Metadata::new();
        metadata.dek_version = Some(dek_version);
        sm.meta()
            .insert(
                meta_key("data", b"k1"),
                metadata.pack().expect("pack metadata"),
            )
            .expect("insert metadata");

        // QUARANTINE_THRESHOLD (3) identical failures within the sliding
        // window trip quarantine; each one must reject the write instead of
        // silently overwriting the tampered record.
        for attempt in 1..=QUARANTINE_THRESHOLD {
            let err = sm
                .encrypt_and_store(&ks, b"k1", b"data", DataTier::Internal as u8, b"new-value")
                .expect_err(
                    "a corrupted existing record must not be silently overwritten with version 0",
                );
            assert!(
                matches!(
                    err,
                    StoreError::Crypto {
                        source: openstack_keystone_storage_crypto::CryptoError::AesDecrypt
                    }
                ),
                "attempt {attempt}: expected a GCM tag-verification failure, got: {err:?}"
            );
        }

        // The ciphertext on disk must be untouched -- every write must have
        // been rejected before ever reaching the batch commit.
        let still_stored = ks.get(b"k1").expect("get data").expect("present");
        assert_eq!(still_stored.as_ref(), ciphertext.as_slice());

        assert!(
            sm.is_quarantined("data"),
            "repeated GCM failures against the same partition must quarantine it"
        );
    }

    /// A hint naming an epoch that is genuinely gone (not in `old_deks`)
    /// *and* known to have been emergency-revoked (ADR 0016-v2 §6.2) must
    /// fail with a clean `RevokedDek` error, not be miscategorized as
    /// corruption and trip the quarantine threshold (GitHub #1299). By the
    /// time this can happen for a real record, `finalize_if_revoked` has
    /// already confirmed nothing needs the key anymore.
    #[test]
    fn decrypt_with_revoked_and_discarded_epoch_returns_clean_error_not_quarantine() {
        let epoch = test_epoch(0x08, 2);
        let (sm, _td) = make_sm(epoch);

        sm.revoked_deks.lock().unwrap().insert(1);

        let err = sm
            .decrypt_state(
                b"irrelevant-ciphertext",
                DataTier::Internal as u8,
                b"data",
                b"k1",
                Some(1),
            )
            .expect_err("a revoked, fully-discarded epoch must not decrypt");
        assert!(
            matches!(
                err,
                StoreError::Crypto {
                    source: openstack_keystone_storage_crypto::CryptoError::RevokedDek {
                        version: 1
                    }
                }
            ),
            "expected a clean RevokedDek error, got: {err:?}"
        );
    }
}

/// Regression tests for GitHub #1294: per-record `Metadata` must be
/// namespaced by keyspace, and callers must never be able to write
/// directly into a keyspace reserved for the state machine's own storage.
#[cfg(test)]
mod keyspace_isolation_tests {
    use openstack_keystone_storage_crypto::EnvKek;

    use super::*;

    fn test_epoch(seed: u8, version: u32) -> Arc<DekEpoch> {
        Arc::new(DekEpoch::from_raw(LockedKey::from_raw([seed; 32]), version).expect("epoch"))
    }

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
            1,
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
    fn meta_key_never_collides_across_keyspaces_or_with_bare_system_keys() {
        // Two different keyspaces, same record key -> different meta keys.
        assert_ne!(meta_key("data", b"shared"), meta_key("other", b"shared"));
        // The `\0` separator can never be produced by a bare system key
        // (none of them contain a NUL byte), so a namespaced meta key can
        // never collide with one.
        assert_ne!(meta_key("data", b"shared"), META_DEK_CURRENT.to_vec());
        assert!(meta_key("data", b"shared").contains(&0u8));
        assert!(!META_DEK_CURRENT.contains(&0u8));
        assert!(!KEY_LAST_APPLIED_LOG.contains(&0u8));
        assert!(!KEY_LAST_MEMBERSHIP.contains(&0u8));
    }

    #[test]
    fn check_keyspace_allowed_rejects_only_reserved_names() {
        for reserved in RESERVED_KEYSPACES {
            assert!(
                check_keyspace_allowed(reserved).is_err(),
                "'{reserved}' must be rejected as a caller-supplied keyspace"
            );
        }
        for ok in ["data", "identity_users", "oauth2_tokens"] {
            assert!(
                check_keyspace_allowed(ok).is_ok(),
                "'{ok}' must be a valid caller-supplied keyspace"
            );
        }
    }

    /// Two records with the same key in different keyspaces must have
    /// independent `Metadata`: writing/removing one must never affect the
    /// other's revision, tier or `dek_version` (GitHub #1294 consequence
    /// 1). This mirrors what `apply()`'s `Set`/`Remove` handlers now do via
    /// `meta_key`.
    #[test]
    fn metadata_is_isolated_per_keyspace_for_the_same_record_key() {
        let epoch = test_epoch(0x50, 1);
        let (sm, _td) = make_sm(epoch);

        let ks_a = sm.keyspace("keyspace_a").expect("keyspace a");
        let ks_b = sm.keyspace("keyspace_b").expect("keyspace b");

        let (cipher_a, dek_version_a) = sm
            .encrypt_and_store(
                &ks_a,
                b"shared",
                b"keyspace_a",
                DataTier::Internal as u8,
                b"a",
            )
            .expect("encrypt in keyspace_a");
        ks_a.insert(b"shared", cipher_a).expect("insert a");
        let mut meta_a = Metadata::new();
        meta_a.revision = 7;
        meta_a.dek_version = Some(dek_version_a);
        sm.meta()
            .insert(meta_key("keyspace_a", b"shared"), meta_a.pack().unwrap())
            .expect("insert meta a");

        let (cipher_b, dek_version_b) = sm
            .encrypt_and_store(
                &ks_b,
                b"shared",
                b"keyspace_b",
                DataTier::Internal as u8,
                b"b",
            )
            .expect("encrypt in keyspace_b");
        ks_b.insert(b"shared", cipher_b).expect("insert b");
        let mut meta_b = Metadata::new();
        meta_b.revision = 3;
        meta_b.dek_version = Some(dek_version_b);
        sm.meta()
            .insert(meta_key("keyspace_b", b"shared"), meta_b.pack().unwrap())
            .expect("insert meta b");

        // Removing keyspace_a's record (as apply()'s Remove handler does)
        // must not touch keyspace_b's metadata.
        sm.meta()
            .remove(meta_key("keyspace_a", b"shared"))
            .expect("remove meta a");

        assert!(
            sm.meta()
                .get(meta_key("keyspace_a", b"shared"))
                .expect("get a")
                .is_none(),
            "keyspace_a's metadata must be gone"
        );
        let meta_b_after = sm
            .meta()
            .get(meta_key("keyspace_b", b"shared"))
            .expect("get b")
            .expect("keyspace_b's metadata must survive keyspace_a's removal");
        let unpacked_b = Metadata::unpack(meta_b_after.as_ref()).expect("unpack b");
        assert_eq!(unpacked_b.revision, 3);
        assert_eq!(unpacked_b.dek_version, Some(dek_version_b));
    }
}

#[cfg(test)]
mod reencrypt_tests {
    use openstack_keystone_storage_crypto::EnvKek;

    use super::*;

    fn test_epoch(seed: u8, version: u32) -> Arc<DekEpoch> {
        Arc::new(DekEpoch::from_raw(LockedKey::from_raw([seed; 32]), version).expect("epoch"))
    }

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
            1,
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

    /// Writes a record the way `apply()` does: ciphertext in the data
    /// keyspace plus a matching `Metadata` (with `dek_version` populated) in
    /// `meta`. Returns the DEK epoch version the record was encrypted under.
    fn write_record(sm: &FjallStateMachine, key: &[u8], plaintext: &[u8]) -> u32 {
        let ks = sm.data().clone();
        let (ciphertext, dek_version) = sm
            .encrypt_and_store(&ks, key, b"data", DataTier::Internal as u8, plaintext)
            .expect("encrypt");
        ks.insert(key, ciphertext).expect("insert ciphertext");
        let mut metadata = Metadata::new();
        metadata.dek_version = Some(dek_version);
        sm.meta()
            .insert(
                meta_key("data", key),
                metadata.pack().expect("pack metadata"),
            )
            .expect("insert metadata");
        dek_version
    }

    /// End-to-end exercise of ADR 0016-v2 §6 step 5: a record written under
    /// a since-retired DEK epoch must be re-encrypted under the current
    /// epoch, its `Metadata::dek_version` updated to match, and the epoch
    /// marked fully migrated so it isn't re-swept.
    #[test]
    fn reencrypt_pending_migrates_records_under_retired_epoch() {
        let old_epoch = test_epoch(0x10, 1);
        let (sm, _td) = make_sm(old_epoch.clone());

        let old_version = write_record(&sm, b"k1", b"hello");
        assert_eq!(old_version, old_epoch.version);

        // Simulate a completed rotation exactly as `apply()`'s
        // `MutationInner::InstallDek` handler does: swap in the new current
        // epoch and register the old one for read fallback.
        let new_epoch = test_epoch(0x11, 2);
        *sm.dek.write().unwrap_or_else(|p| p.into_inner()) = new_epoch.clone();
        sm.old_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(old_epoch.version, old_epoch.clone());

        TypeConfig::run(async {
            sm.reencrypt_pending().await;
        });

        // Metadata now names the new epoch.
        let meta_bytes = sm
            .meta()
            .get(meta_key("data", b"k1"))
            .expect("get meta")
            .expect("meta present");
        let metadata = Metadata::unpack(meta_bytes.as_ref()).expect("unpack metadata");
        assert_eq!(metadata.dek_version, Some(new_epoch.version));

        // The record now decrypts under the new epoch's exact hint.
        let stored = sm
            .data()
            .get(b"k1")
            .expect("get data")
            .expect("data present");
        let plaintext = sm
            .decrypt_state(
                stored.as_ref(),
                DataTier::Internal as u8,
                b"data",
                b"k1",
                Some(new_epoch.version),
            )
            .expect("decrypt under new epoch");
        assert_eq!(plaintext, b"hello");

        // A clean pass with nothing skipped marks the epoch done so it's
        // never re-swept (no code path ever writes a new record back under
        // a retired epoch).
        let done_key = format!("{DEK_REENCRYPT_DONE_PREFIX}{}", old_epoch.version);
        assert!(
            sm.meta()
                .get(done_key.as_bytes())
                .expect("get marker")
                .is_some(),
            "fully migrated epoch must be marked done"
        );
    }

    /// A record already under the current epoch (no rotation pending) must
    /// be left untouched by a re-encryption sweep.
    #[test]
    fn reencrypt_pending_is_noop_with_no_retired_epochs() {
        let epoch = test_epoch(0x12, 1);
        let (sm, _td) = make_sm(epoch);

        write_record(&sm, b"k2", b"hello");
        let before = sm
            .data()
            .get(b"k2")
            .expect("get data")
            .expect("present")
            .to_vec();

        TypeConfig::run(async {
            sm.reencrypt_pending().await;
        });

        let after = sm
            .data()
            .get(b"k2")
            .expect("get data")
            .expect("still present")
            .to_vec();
        assert_eq!(before, after, "no retired epoch to migrate from");
    }

    /// End-to-end exercise of the fix for GitHub #1299: an emergency-revoked
    /// epoch's key material is genuinely discarded only after its
    /// re-encryption sweep confirms completion *and* no Raft log entry
    /// still references it -- not synchronously at rotation time, the way
    /// the pre-fix code did.
    #[test]
    fn finalize_if_revoked_discards_key_once_swept_and_log_is_clear() {
        let old_epoch = test_epoch(0x20, 1);
        let (sm, _td) = make_sm(old_epoch.clone());

        let old_version = write_record(&sm, b"k1", b"hello");
        assert_eq!(old_version, old_epoch.version);

        // Simulate what the post-commit swap block now does for an
        // emergency rotation: register the old epoch in *both* `old_deks`
        // (still readable during the sweep) and `revoked_deks`
        // (containment), and stage its wrapped bytes on disk the way
        // `InstallDek`'s emergency branch does.
        let new_epoch = test_epoch(0x21, 2);
        *sm.dek.write().unwrap_or_else(|p| p.into_inner()) = new_epoch.clone();
        sm.old_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(old_epoch.version, old_epoch.clone());
        sm.revoked_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(old_epoch.version);
        let revoked_pending_key = format!("{DEK_REVOKED_PENDING_PREFIX}{}", old_epoch.version);
        sm.meta()
            .insert(revoked_pending_key.as_bytes(), b"fake-wrapped-bytes")
            .expect("stage revoked-pending key material");

        TypeConfig::run(async {
            sm.reencrypt_pending().await;
        });

        // The record has been migrated and the revoked epoch's key
        // material is genuinely gone -- both in memory and on disk.
        assert!(
            !sm.old_deks
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains_key(&old_epoch.version),
            "finalized revoked epoch must be dropped from old_deks"
        );
        assert!(
            sm.meta()
                .get(revoked_pending_key.as_bytes())
                .expect("get marker")
                .is_none(),
            "staged key material must be deleted once finalized"
        );

        let stored = sm
            .data()
            .get(b"k1")
            .expect("get data")
            .expect("data present");
        let plaintext = sm
            .decrypt_state(
                stored.as_ref(),
                DataTier::Internal as u8,
                b"data",
                b"k1",
                Some(new_epoch.version),
            )
            .expect("record remains readable after finalization");
        assert_eq!(plaintext, b"hello");
    }

    /// A revoked epoch whose re-encryption swept cleanly but which is still
    /// referenced by an un-compacted Raft log entry must not be finalized
    /// yet -- discarding the key while a log entry still needs it would
    /// make that entry permanently unreadable (GitHub #1299).
    #[test]
    fn finalize_if_revoked_defers_while_log_entries_remain() {
        let old_epoch = test_epoch(0x22, 1);
        let (sm, _td) = make_sm(old_epoch.clone());

        write_record(&sm, b"k2", b"hello");

        let new_epoch = test_epoch(0x23, 2);
        *sm.dek.write().unwrap_or_else(|p| p.into_inner()) = new_epoch;
        sm.old_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(old_epoch.version, old_epoch.clone());
        sm.revoked_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(old_epoch.version);
        let revoked_pending_key = format!("{DEK_REVOKED_PENDING_PREFIX}{}", old_epoch.version);
        sm.meta()
            .insert(revoked_pending_key.as_bytes(), b"fake-wrapped-bytes")
            .expect("stage revoked-pending key material");

        // Simulate a still-un-compacted Raft log entry tagged with the
        // revoked version (layout: [dek_version_u32_BE; 4] ++ ...).
        let logs = sm
            .db()
            .keyspace("logs", KeyspaceCreateOptions::default)
            .expect("logs keyspace");
        let mut fake_entry = old_epoch.version.to_be_bytes().to_vec();
        fake_entry.extend_from_slice(&[0u8; 40]);
        logs.insert(1u64.to_be_bytes(), fake_entry)
            .expect("insert fake log entry");

        TypeConfig::run(async {
            sm.reencrypt_pending().await;
        });

        assert!(
            sm.old_deks
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains_key(&old_epoch.version),
            "must not finalize while a log entry still references the revoked epoch"
        );
        assert!(
            sm.meta()
                .get(revoked_pending_key.as_bytes())
                .expect("get marker")
                .is_some(),
            "staged key material must survive while finalization is deferred"
        );
    }

    /// Regression test for GitHub #1295 (main defect): `reencrypt_one` must
    /// hold `keyspace_lifecycle`'s write side for its whole
    /// read-decrypt-recompute-commit sequence, so it cannot interleave with
    /// a concurrent `apply()` write that, per the fixed doc comment, holds
    /// the read side for the same key. Proven the same way as
    /// `keyspace_lifecycle_lock_excludes_concurrent_readers_and_writer`
    /// proves it for `drop_keyspace`: while a simulated in-flight `apply()`
    /// read guard is held on a background thread, a call to `reencrypt_one`
    /// on the main thread must block until that guard is released, rather
    /// than racing ahead and (as the pre-fix code could) overwriting a
    /// write that lands in the gap.
    #[test]
    fn reencrypt_one_blocks_until_concurrent_apply_guard_is_released() {
        let old_epoch = test_epoch(0x40, 1);
        let (sm, _td) = make_sm(old_epoch.clone());
        let sm = Arc::new(sm);

        write_record(&sm, b"k1", b"hello");

        let new_epoch = test_epoch(0x41, 2);
        *sm.dek.write().unwrap_or_else(|p| p.into_inner()) = new_epoch.clone();
        sm.old_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(old_epoch.version, old_epoch.clone());

        let hold_for = Duration::from_millis(200);
        let sm_bg = sm.clone();
        let apply_thread = std::thread::spawn(move || {
            // Simulates `apply()` holding the read side of
            // `keyspace_lifecycle` for an entry's whole processing+commit.
            let _guard = sm_bg
                .keyspace_lifecycle
                .read()
                .unwrap_or_else(|p| p.into_inner());
            std::thread::sleep(hold_for);
        });

        // Give the background thread a head start so it reliably acquires
        // the read guard first.
        std::thread::sleep(Duration::from_millis(30));

        let ks = sm.data().clone();
        let start = Instant::now();
        let outcome = sm.reencrypt_one(&ks, "data", b"k1", &old_epoch);
        let elapsed = start.elapsed();

        apply_thread.join().expect("apply thread must not panic");

        assert!(
            elapsed >= hold_for - Duration::from_millis(30),
            "reencrypt_one must block until the concurrent apply()'s read guard is \
             released instead of racing ahead of it, elapsed={elapsed:?}"
        );
        assert!(matches!(outcome, ReencryptOutcome::Migrated));

        let meta_bytes = sm
            .meta()
            .get(meta_key("data", b"k1"))
            .expect("get meta")
            .expect("present");
        let metadata = Metadata::unpack(meta_bytes.as_ref()).expect("unpack metadata");
        assert_eq!(metadata.dek_version, Some(new_epoch.version));
    }

    /// Stress-test counterpart to the above: many concurrent `apply()`-style
    /// writes racing a re-encryption sweep for the same key must never lose
    /// a write. This is the scenario GitHub #1295 describes directly: the
    /// old code could commit a re-encryption batch that overwrote both the
    /// ciphertext and the `Metadata` (including `revision`) of a write
    /// `apply()` had already committed, reverting it with no Raft-visible
    /// signal. With the fix, `reencrypt_one`'s write-locked critical
    /// section and `apply()`'s read-locked one can never interleave, so the
    /// final record must always reflect whichever wrote last.
    #[test]
    fn reencrypt_pending_never_loses_a_concurrent_apply_write() {
        let old_epoch = test_epoch(0x42, 1);
        let (sm, _td) = make_sm(old_epoch.clone());
        let sm = Arc::new(sm);

        write_record(&sm, b"k1", b"v0");

        let new_epoch = test_epoch(0x43, 2);
        *sm.dek.write().unwrap_or_else(|p| p.into_inner()) = new_epoch.clone();
        sm.old_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(old_epoch.version, old_epoch.clone());

        const WRITES: u64 = 50;
        let sm_writer = sm.clone();
        let writer = std::thread::spawn(move || {
            let ks = sm_writer.data().clone();
            for revision in 1..=WRITES {
                let plaintext = format!("v{revision}");
                // Mirrors apply()'s write path: hold the read side of
                // `keyspace_lifecycle` for the whole encrypt+commit.
                let _lifecycle_guard = sm_writer
                    .keyspace_lifecycle
                    .read()
                    .unwrap_or_else(|p| p.into_inner());
                let (ciphertext, dek_version) = sm_writer
                    .encrypt_and_store(
                        &ks,
                        b"k1",
                        b"data",
                        DataTier::Internal as u8,
                        plaintext.as_bytes(),
                    )
                    .expect("encrypt");
                let mut metadata = Metadata::new();
                metadata.revision = revision;
                metadata.dek_version = Some(dek_version);
                let mut batch = sm_writer.db().batch();
                batch.insert(&ks, b"k1".to_vec(), ciphertext);
                batch.insert(
                    sm_writer.meta(),
                    meta_key("data", b"k1"),
                    metadata.pack().expect("pack"),
                );
                batch.commit().expect("commit");
            }
        });

        let sm_reencrypt = sm.clone();
        let reencryptor = std::thread::spawn(move || {
            let ks = sm_reencrypt.data().clone();
            for _ in 0..WRITES {
                sm_reencrypt.reencrypt_one(&ks, "data", b"k1", &old_epoch);
                std::thread::yield_now();
            }
        });

        writer.join().expect("writer thread must not panic");
        reencryptor.join().expect("reencrypt thread must not panic");

        let meta_bytes = sm
            .meta()
            .get(meta_key("data", b"k1"))
            .expect("get meta")
            .expect("present");
        let metadata = Metadata::unpack(meta_bytes.as_ref()).expect("unpack metadata");
        assert_eq!(
            metadata.dek_version,
            Some(new_epoch.version),
            "record must end up under the current epoch"
        );
        assert_eq!(
            metadata.revision, WRITES,
            "the latest committed apply() write's revision must never be reverted \
             by a concurrent re-encryption batch"
        );

        let stored = sm.data().get(b"k1").expect("get data").expect("present");
        let plaintext = sm
            .decrypt_state(
                stored.as_ref(),
                DataTier::Internal as u8,
                b"data",
                b"k1",
                Some(new_epoch.version),
            )
            .expect("decrypt final record");
        assert_eq!(plaintext, format!("v{WRITES}").into_bytes());
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

#[cfg(test)]
mod ephemeral_tests {
    use openstack_keystone_storage_crypto::EnvKek;

    use super::*;

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

    /// Directly seeds an ephemeral keyspace the way `apply()`'s `Set`/
    /// `CreateIfAbsent` arms would, without needing to drive a full
    /// `RaftStateMachine::apply()` entry stream — the helper methods under
    /// test (`is_ephemeral_keyspace`, `ephemeral_get`, `ephemeral_prefix`,
    /// `keyspace_exists`, `drop_keyspace`) are exercised the same way
    /// regardless of what populated the map.
    fn seed(sm: &FjallStateMachine, keyspace: &str, key: &[u8], value: &[u8], metadata: Metadata) {
        sm.ephemeral
            .entry(keyspace.to_string())
            .or_default()
            .insert(key.to_vec(), (value.to_vec(), metadata));
    }

    #[test]
    fn ephemeral_write_never_touches_the_fjall_db() {
        let (sm, _td) = make_sm();
        seed(
            &sm,
            "webauthn_state_1",
            b"user-1:auth",
            b"challenge-bytes",
            Metadata::ephemeral(),
        );

        assert!(sm.keyspace_exists("webauthn_state_1"));
        assert!(sm.is_ephemeral_keyspace("webauthn_state_1"));
        // The keyspace must not exist as a real Fjall partition.
        assert!(!sm.db.keyspace_exists("webauthn_state_1"));
    }

    #[test]
    fn ephemeral_get_round_trips_value_and_metadata() {
        let (sm, _td) = make_sm();
        let metadata = Metadata::ephemeral();
        seed(
            &sm,
            "webauthn_state_1",
            b"user-1:auth",
            b"payload",
            metadata,
        );

        let (value, got_metadata) = sm
            .ephemeral_get("webauthn_state_1", b"user-1:auth")
            .expect("value present");
        assert_eq!(value, b"payload");
        assert!(got_metadata.is_ephemeral);
    }

    #[test]
    fn ephemeral_get_is_none_for_unknown_keyspace() {
        let (sm, _td) = make_sm();
        assert!(sm.ephemeral_get("never_written", b"any-key").is_none());
        assert!(!sm.is_ephemeral_keyspace("never_written"));
    }

    #[test]
    fn ephemeral_prefix_filters_by_prefix_and_is_none_for_non_ephemeral_keyspace() {
        let (sm, _td) = make_sm();
        seed(
            &sm,
            "webauthn_state_1",
            b"user-1:auth",
            b"a",
            Metadata::ephemeral(),
        );
        seed(
            &sm,
            "webauthn_state_1",
            b"user-1:registration",
            b"b",
            Metadata::ephemeral(),
        );
        seed(
            &sm,
            "webauthn_state_1",
            b"user-2:auth",
            b"c",
            Metadata::ephemeral(),
        );

        let matched = sm
            .ephemeral_prefix("webauthn_state_1", b"user-1:")
            .expect("keyspace is ephemeral");
        assert_eq!(matched.len(), 2);

        // A Fjall-backed (non-ephemeral) keyspace name must fall through to
        // `None` rather than an empty result, so callers know to read Fjall
        // instead.
        assert!(sm.ephemeral_prefix("data", b"user-1:").is_none());
    }

    #[test]
    fn drop_keyspace_reclaims_an_empty_ephemeral_partition() {
        let (sm, _td) = make_sm();
        seed(
            &sm,
            "webauthn_state_1",
            b"user-1:auth",
            b"payload",
            Metadata::ephemeral(),
        );
        // Drain it back out, mirroring what apply()'s Remove arm does.
        sm.ephemeral
            .get("webauthn_state_1")
            .expect("keyspace present")
            .remove(b"user-1:auth".as_slice());

        sm.drop_keyspace("webauthn_state_1")
            .expect("drop empty ephemeral keyspace");
        assert!(!sm.keyspace_exists("webauthn_state_1"));
    }

    #[test]
    fn drop_keyspace_refuses_non_empty_ephemeral_partition() {
        let (sm, _td) = make_sm();
        seed(
            &sm,
            "webauthn_state_1",
            b"user-1:auth",
            b"payload",
            Metadata::ephemeral(),
        );

        let err = sm
            .drop_keyspace("webauthn_state_1")
            .expect_err("must refuse to drop a non-empty ephemeral keyspace");
        assert!(matches!(err, StoreError::Other(_)));
        assert!(sm.keyspace_exists("webauthn_state_1"));
        assert!(
            sm.ephemeral_get("webauthn_state_1", b"user-1:auth")
                .is_some(),
            "the failed drop must not have discarded the entry"
        );
    }
}

/// Regression coverage for GitHub #1293: `build_snapshot`/`install_snapshot`
/// must carry every replicated Fjall keyspace (`meta`, `index`, dynamic
/// application keyspaces), not just `data`, and `install_snapshot` must
/// clear keyspaces the incoming snapshot no longer carries rather than
/// leaving them stale. These tests drive `build_snapshot`/`install_snapshot`
/// directly against `FjallStateMachine` instances, without a live Raft
/// cluster -- reproducing the full "leader snapshots, a node installs it"
/// scenario is blocked on GitHub #1329 (see issue #1293's discussion).
#[cfg(test)]
mod snapshot_tests {
    use openstack_keystone_storage_crypto::EnvKek;

    use super::*;

    fn make_sm() -> (Arc<FjallStateMachine>, tempfile::TempDir) {
        let td = tempfile::TempDir::new().expect("tempdir");
        let db = Arc::new(Database::builder(td.path()).open().expect("open db"));
        let kek: Arc<dyn KekProvider> = Arc::new(EnvKek::from_bytes([0x42u8; 32]));
        let epoch =
            Arc::new(DekEpoch::from_raw(LockedKey::from_raw([0x21; 32]), 1).expect("epoch"));
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
        (Arc::new(sm), td)
    }

    /// Seeds an ephemeral keyspace directly, mirroring `apply()`'s
    /// `Set`/`CreateIfAbsent` arms (see `ephemeral_tests::seed`).
    fn seed_ephemeral(sm: &FjallStateMachine, keyspace: &str, key: &[u8]) {
        sm.ephemeral
            .entry(keyspace.to_string())
            .or_default()
            .insert(key.to_vec(), (b"challenge".to_vec(), Metadata::ephemeral()));
    }

    /// Dumps every entry currently in Fjall keyspace `name`, sorted for
    /// deterministic comparison.
    fn dump(sm: &FjallStateMachine, name: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
        let ks = sm.keyspace(name).expect("keyspace handle");
        let mut out: Vec<_> = ks
            .iter()
            .filter_map(|item| item.into_inner().ok())
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        out.sort();
        out
    }

    #[tokio::test]
    async fn build_snapshot_captures_every_keyspace_and_ephemeral_registry() {
        let (mut sm, _td) = make_sm();

        sm.data()
            .insert(b"rec1", b"ciphertext")
            .expect("write data");
        let meta_bytes = Metadata::with_tier(DataTier::Internal)
            .pack()
            .expect("pack metadata");
        sm.meta()
            .insert(b"rec1", meta_bytes.clone())
            .expect("write meta");
        sm.index().insert(b"idx1", b"").expect("write index");
        let domain_ks = sm.keyspace("domain").expect("create domain keyspace");
        domain_ks
            .insert(b"dom1", b"domain-payload")
            .expect("write domain");
        seed_ephemeral(&sm, "webauthn_state_1", b"user-1:auth");

        let snapshot = sm.build_snapshot().await.expect("build snapshot");
        let payload: SnapshotPayload =
            rmp_serde::from_slice(&snapshot.snapshot).expect("decode payload");

        assert_eq!(payload.version, SNAPSHOT_FORMAT_VERSION);

        let by_name: HashMap<String, Vec<(Vec<u8>, Vec<u8>)>> =
            payload.keyspaces.into_iter().collect();
        assert_eq!(
            by_name.get("data"),
            Some(&vec![(b"rec1".to_vec(), b"ciphertext".to_vec())])
        );
        assert_eq!(
            by_name.get("meta"),
            Some(&vec![(b"rec1".to_vec(), meta_bytes)])
        );
        assert_eq!(
            by_name.get("index"),
            Some(&vec![(b"idx1".to_vec(), b"".to_vec())])
        );
        assert_eq!(
            by_name.get("domain"),
            Some(&vec![(b"dom1".to_vec(), b"domain-payload".to_vec())])
        );
        assert!(
            !by_name.contains_key("logs"),
            "the node-local Raft log keyspace must never travel in a snapshot"
        );
        assert!(
            !by_name.contains_key("local_emergency"),
            "the node-local emergency keyspace (ADR 0028) must never travel in a snapshot"
        );

        assert_eq!(
            payload.ephemeral_keyspaces,
            vec!["webauthn_state_1".to_string()]
        );
    }

    #[tokio::test]
    async fn install_snapshot_replaces_all_keyspaces_and_clears_stale_ones() {
        // "Leader": populate several keyspaces plus an ephemeral
        // registration, then build a snapshot from it.
        let (mut leader, _td1) = make_sm();
        leader
            .data()
            .insert(b"rec1", b"new-cipher")
            .expect("write data");
        let meta_bytes = Metadata::with_tier(DataTier::Internal)
            .pack()
            .expect("pack metadata");
        leader
            .meta()
            .insert(b"rec1", meta_bytes.clone())
            .expect("write meta");
        leader
            .keyspace("domain")
            .expect("create domain keyspace")
            .insert(b"dom1", b"fresh")
            .expect("write domain");
        seed_ephemeral(&leader, "webauthn_state_1", b"user-1:auth");

        let snapshot = leader.build_snapshot().await.expect("build snapshot");

        // "Follower": stale/different data in the same keyspaces, an extra
        // keyspace the leader's snapshot no longer carries, and a stray
        // ephemeral registration -- everything `install_snapshot` must
        // clear (GitHub #1293 point 3).
        let (mut follower, _td2) = make_sm();
        follower
            .data()
            .insert(b"rec1", b"stale-cipher")
            .expect("seed stale data");
        follower
            .data()
            .insert(b"rec-gone", b"should-be-cleared")
            .expect("seed stale-only data key");
        follower
            .meta()
            .insert(b"rec1", b"stale-meta")
            .expect("seed stale meta");
        follower
            .keyspace("project_id")
            .expect("create stale keyspace")
            .insert(b"proj1", b"stale")
            .expect("seed stale project data");
        seed_ephemeral(&follower, "stray_ephemeral", b"leftover");

        follower
            .install_snapshot(&snapshot.meta, snapshot.snapshot.clone())
            .await
            .expect("install snapshot");

        assert_eq!(
            dump(&follower, "data"),
            vec![(b"rec1".to_vec(), b"new-cipher".to_vec())],
            "the stale-only key must be gone and the stale value replaced"
        );
        assert!(
            dump(&follower, "meta").contains(&(b"rec1".to_vec(), meta_bytes)),
            "meta (per-record Metadata) must now travel in the snapshot too"
        );
        assert_eq!(
            dump(&follower, "domain"),
            vec![(b"dom1".to_vec(), b"fresh".to_vec())]
        );
        assert!(
            dump(&follower, "project_id").is_empty(),
            "a keyspace no longer present in the snapshot must end up empty, not stale"
        );

        assert!(follower.is_ephemeral_keyspace("webauthn_state_1"));
        assert!(
            !follower.is_ephemeral_keyspace("stray_ephemeral"),
            "the follower's stale ephemeral registration must not survive install"
        );
    }

    #[tokio::test]
    async fn install_snapshot_rejects_unsupported_format_version() {
        let (mut sm, _td) = make_sm();
        sm.data().insert(b"rec1", b"original").expect("seed data");

        let bogus = SnapshotPayload {
            version: SNAPSHOT_FORMAT_VERSION + 1,
            keyspaces: vec![(
                "data".to_string(),
                vec![(b"rec1".to_vec(), b"attacker-controlled".to_vec())],
            )],
            ephemeral_keyspaces: vec![],
        };
        let bytes = rmp_serde::to_vec(&bogus).expect("encode bogus payload");

        let meta = SnapshotMeta {
            last_log_id: None,
            last_membership: Default::default(),
        };
        let err = sm
            .install_snapshot(&meta, bytes)
            .await
            .expect_err("must reject a snapshot format version it doesn't understand");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("version"));

        // The rejected install must not have touched existing state.
        assert_eq!(
            dump(&sm, "data"),
            vec![(b"rec1".to_vec(), b"original".to_vec())]
        );
    }
}
