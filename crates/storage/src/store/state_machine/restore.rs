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

//! Restore of operator backups and snapshot installation.

use super::*;

/// `meta` key prefix under which the chunks of an in-flight live restore are
/// staged (`<prefix><restore_id>:<seq u32 BE>`). Staged chunks travel in
/// snapshots (a follower that catches up by snapshot between the chunks and
/// the apply must still find them) but are never part of a restore.
pub(super) const RESTORE_STAGE_PREFIX: &str = "_meta:restore:stage:";

/// Largest backup accepted into a running cluster. Every node reassembles
/// and decrypts it at apply time, so this is far below what the disaster
/// recovery path takes. Enforced where the upload is received and again at
/// apply, so a faulty proposer cannot make every node allocate more.
pub(crate) const MAX_LIVE_RESTORE_SIZE: u64 = 1024 * 1024 * 1024;

/// Staging key of chunk `seq` of restore `restore_id`.
pub(super) fn restore_stage_key(restore_id: &str, seq: u32) -> Vec<u8> {
    let mut key = restore_stage_prefix(restore_id);
    key.extend_from_slice(&seq.to_be_bytes());
    key
}

/// Common prefix of every staged chunk of `restore_id`.
pub(super) fn restore_stage_prefix(restore_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(RESTORE_STAGE_PREFIX.len() + restore_id.len() + 5);
    key.extend_from_slice(RESTORE_STAGE_PREFIX.as_bytes());
    key.extend_from_slice(restore_id.as_bytes());
    key.push(b':');
    key
}

/// `meta` key prefix for the wrapped DEK epochs a live restore displaced
/// (`<prefix><version>:<n>`).
///
/// The restore replaces the cluster's DEKs with the backup's, but this node's
/// Raft log and older snapshot files are still encrypted under the previous
/// ones, and the backup may reuse the same version numbers for different
/// keys. The displaced epochs are therefore kept in a side list, tried by
/// version as a fallback after the regular epoch maps. Every node displaces
/// the same epochs at the same log index, so the entries replicate
/// consistently through snapshots.
pub(super) const DEK_SHADOW_PREFIX: &str = "_meta:dek:shadow:";

/// Why [`FjallStateMachine::apply_restore`] failed.
#[derive(Debug)]
pub(super) enum RestoreError {
    /// The backup was refused before any state changed. Reported to the
    /// caller as a violation; the node keeps running.
    Rejected(String),
    /// Applying the backup failed half-way (I/O error). The node's state no
    /// longer matches its peers, so it must stop like for any other apply
    /// I/O error.
    Fatal(io::Error),
}

/// Parses the DEK version out of a [`DEK_SHADOW_PREFIX`] key.
pub(super) fn shadow_key_version(key: &[u8]) -> Option<u32> {
    std::str::from_utf8(key)
        .ok()?
        .strip_prefix(DEK_SHADOW_PREFIX)?
        .split(':')
        .next()?
        .parse()
        .ok()
}

/// Unwraps the shadow DEK entries among `entries` (`meta` key/value pairs).
/// Entries that cannot be unwrapped are skipped with a warning: they only
/// affect the readability of pre-restore history.
pub(super) fn shadow_epochs<'a>(
    entries: impl Iterator<Item = (&'a [u8], &'a [u8])>,
    kek: &dyn KekProvider,
) -> Vec<Arc<DekEpoch>> {
    let mut epochs = Vec::new();
    for (key, wrapped) in entries {
        let Some(version) = shadow_key_version(key) else {
            continue;
        };
        match kek
            .unwrap_dek(wrapped)
            .map_err(|e| e.to_string())
            .and_then(|raw| {
                DekEpoch::from_raw(LockedKey::from_raw(*raw), version).map_err(|e| e.to_string())
            }) {
            Ok(epoch) => epochs.push(Arc::new(epoch)),
            Err(error) => {
                tracing::warn!(version, %error, "cannot unwrap shadow DEK; skipping");
            }
        }
    }
    epochs
}

/// What [`FjallStateMachine::install_payload`] does with this node's Raft
/// bookkeeping (`last_applied_log`, `last_membership`, snapshot history).
pub(super) enum RaftBookkeeping {
    /// Snapshot install: record the snapshot's `(last_applied_log,
    /// last_membership)`.
    Install(Option<Vec<u8>>, Vec<u8>),
    /// Restore into a live cluster: keep this node's own bookkeeping so the
    /// membership and apply position are unchanged.
    Keep,
}

impl FjallStateMachine {
    /// Replaces every replicated keyspace, the ephemeral registry and the
    /// in-memory DEK epochs with the contents of `payload`.
    ///
    /// `bookkeeping` selects what happens to this node's Raft
    /// `(last_applied_log, last_membership)` and snapshot history, see
    /// [`RaftBookkeeping`].
    ///
    /// Failures before any state is touched carry
    /// [`io::ErrorKind::InvalidData`]; anything else happened while writing.
    ///
    /// Returns the payload's [`DekManifest`].
    pub(super) fn install_payload(
        &self,
        payload: SnapshotPayload,
        bookkeeping: RaftBookkeeping,
    ) -> io::Result<DekManifest> {
        let keep_local = matches!(bookkeeping, RaftBookkeeping::Keep);
        let ephemeral_keyspaces = payload.ephemeral_keyspaces.clone();
        // Validate that the DEKs this snapshot's data is encrypted under can
        // be unwrapped *before* touching any state: a failure after the
        // commit below would leave the keyspaces replaced but the in-memory
        // DEKs unable to read them.
        let manifest = dek_manifest_from_payload(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let (new_current_dek, new_old_deks) =
            dek_epochs_from_manifest(&manifest, self.kek.as_ref())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let new_revoked: HashSet<u32> = payload
            .keyspaces
            .iter()
            .filter(|(name, _)| name == "meta")
            .flat_map(|(_, entries)| entries.iter())
            .filter_map(|(key, _)| {
                std::str::from_utf8(key)
                    .ok()?
                    .strip_prefix(DEK_REVOKED_PREFIX)?
                    .parse::<u32>()
                    .ok()
            })
            .collect();

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

        // Read before the clear sweep below wipes `meta`. `meta` also holds
        // state that belongs to this node rather than to the replicated
        // state -- vote, purge marker, nonce counters, snapshot history --
        // and the sending node's must never overwrite it. A restore into a
        // live cluster additionally keeps the Raft bookkeeping and the DEK
        // epochs it displaces.
        let mut kept: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut shadow: Vec<Arc<DekEpoch>> = Vec::new();
        for key in self.node_local_meta_keys(keep_local) {
            if let Some(value) = self
                .meta
                .get(&key)
                .map_err(|e| io::Error::other(e.to_string()))?
            {
                kept.push((key, value.to_vec()));
            }
        }
        for prefix in self.node_local_meta_prefixes() {
            for item in self.meta.prefix(&prefix) {
                let (key, value) = item
                    .into_inner()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                kept.push((key.to_vec(), value.to_vec()));
            }
        }
        if keep_local {
            let displaced = self.displaced_dek_entries()?;
            shadow = shadow_epochs(
                displaced.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
                self.kek.as_ref(),
            );
            kept.extend(displaced);
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

        let mut installed_shadow: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for (name, entries) in payload.keyspaces {
            if SNAPSHOT_SKIP_KEYSPACES.contains(&name.as_str()) {
                continue;
            }
            let ks = self
                .keyspace(&name)
                .map_err(|e| io::Error::other(e.to_string()))?;
            for (key, value) in entries {
                if name == "meta" {
                    // Never take the sending node's vote, nonce counters,
                    // snapshot history (or, for a restore, its applied and
                    // membership pointers and in-flight staging): this
                    // node's own are kept.
                    if self.is_node_local_meta_key(&key, keep_local) {
                        continue;
                    }
                    if !keep_local && key.starts_with(DEK_SHADOW_PREFIX.as_bytes()) {
                        installed_shadow.push((key.clone(), value.clone()));
                    }
                }
                batch.insert(&ks, key, value);
            }
        }

        match bookkeeping {
            RaftBookkeeping::Install(last_applied_bytes, last_membership_bytes) => {
                if let Some(bytes) = last_applied_bytes {
                    batch.insert(&self.meta, KEY_LAST_APPLIED_LOG, bytes);
                }
                batch.insert(&self.meta, KEY_LAST_MEMBERSHIP, last_membership_bytes);
                shadow = shadow_epochs(
                    installed_shadow
                        .iter()
                        .map(|(k, v)| (k.as_slice(), v.as_slice())),
                    self.kek.as_ref(),
                );
            }
            RaftBookkeeping::Keep => {}
        }
        for (key, value) in kept {
            batch.insert(&self.meta, key, value);
        }

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
        for name in &ephemeral_keyspaces {
            self.ephemeral.entry(name.clone()).or_default();
        }

        // The installed `meta` keyspace replaced this node's persisted DEKs;
        // make the in-memory epochs match it. For a follower that already
        // adopted the leader's DEK this is a no-op, but for a restore into a
        // fresh cluster (or a snapshot spanning a DEK rotation) the node's
        // previous epoch could not read the installed records.
        *self.dek.write().unwrap_or_else(|p| p.into_inner()) = new_current_dek;
        *self.old_deks.lock().unwrap_or_else(|p| p.into_inner()) = new_old_deks;
        *self.revoked_deks.lock().unwrap_or_else(|p| p.into_inner()) = new_revoked;
        *self.shadow_deks.lock().unwrap_or_else(|p| p.into_inner()) = shadow;

        // A snapshot built before install times were recorded — e.g. by a
        // still-running old node during a rolling upgrade — carries no
        // `META_DEK_INSTALLED_AT`. Without this, the age-based rotation
        // trigger would stay inert on this node until a later rotation
        // happened to write the key. The value is replicated (not
        // node-local), so a current snapshot already carries it and the
        // call is a no-op there.
        self.ensure_dek_installed_at()
            .map_err(|e| io::Error::other(e.to_string()))?;

        drop(_lifecycle_guard);

        Ok(manifest)
    }

    /// `meta` keys that belong to this node and survive a snapshot install
    /// or restore. A live restore also keeps the applied/membership pointers
    /// (`keep_raft_state`); a snapshot install sets those explicitly.
    pub(super) fn node_local_meta_keys(&self, keep_raft_state: bool) -> Vec<Vec<u8>> {
        let mut keys = vec![
            SNAPSHOT_HISTORY_META_KEY.to_vec(),
            KEY_VOTE.to_vec(),
            KEY_PURGED.to_vec(),
            format!("_meta:nonce_ctr:{}", self.node_id).into_bytes(),
            format!("_meta:nonce_hwm:{}", self.node_id).into_bytes(),
        ];
        if keep_raft_state {
            keys.push(KEY_LAST_APPLIED_LOG.to_vec());
            keys.push(KEY_LAST_MEMBERSHIP.to_vec());
        }
        keys
    }

    /// `meta` key prefixes whose entries belong to this node and survive a
    /// snapshot install or restore: the per-epoch log nonce counters.
    pub(super) fn node_local_meta_prefixes(&self) -> Vec<Vec<u8>> {
        vec![nonce_meta_prefix(self.node_id).into_bytes()]
    }

    /// Whether an incoming `meta` entry must be dropped: one this node keeps
    /// its own of ([`Self::node_local_meta_keys`],
    /// [`Self::node_local_meta_prefixes`] and, for a restore, in-flight
    /// restore chunks and displaced-DEK entries), or a re-encryption
    /// checkpoint, which describes the sending node's sweep and not the
    /// installed data.
    pub(super) fn is_node_local_meta_key(&self, key: &[u8], keep_raft_state: bool) -> bool {
        key.starts_with(REENCRYPT_PROGRESS_PREFIX.as_bytes())
            || self
                .node_local_meta_prefixes()
                .iter()
                .any(|p| key.starts_with(p))
            || (keep_raft_state
                && (key.starts_with(RESTORE_STAGE_PREFIX.as_bytes())
                    || key.starts_with(DEK_SHADOW_PREFIX.as_bytes())))
            || self
                .node_local_meta_keys(keep_raft_state)
                .iter()
                .any(|k| k == key)
    }

    /// The `meta` entries that preserve every DEK epoch this node can
    /// currently read, as [`DEK_SHADOW_PREFIX`] entries: the ones already
    /// shadowed plus the current, retired and revoked-pending epochs.
    pub(super) fn displaced_dek_entries(&self) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let other = |e: &dyn std::fmt::Display| io::Error::other(e.to_string());
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut wrapped_seen: HashSet<Vec<u8>> = HashSet::new();
        for item in self.meta.prefix(DEK_SHADOW_PREFIX.as_bytes()) {
            let (key, value) = item.into_inner().map_err(|e| other(&e))?;
            wrapped_seen.insert(value.to_vec());
            entries.push((key.to_vec(), value.to_vec()));
        }

        let mut candidates: Vec<(u32, Vec<u8>)> = Vec::new();
        if let Some(cur) = self.meta.get(META_DEK_CURRENT).map_err(|e| other(&e))?
            && cur.len() > 4
        {
            let version = u32::from_be_bytes([cur[0], cur[1], cur[2], cur[3]]);
            candidates.push((version, cur[4..].to_vec()));
        }
        for prefix in [DEK_RETIRED_PREFIX, DEK_REVOKED_PENDING_PREFIX] {
            for item in self.meta.prefix(prefix.as_bytes()) {
                let (key, value) = item.into_inner().map_err(|e| other(&e))?;
                let version = std::str::from_utf8(&key)
                    .ok()
                    .and_then(|k| k.strip_prefix(prefix))
                    .and_then(|v| v.parse::<u32>().ok());
                if let Some(version) = version {
                    candidates.push((version, value.to_vec()));
                }
            }
        }

        for (version, wrapped) in candidates {
            if !wrapped_seen.insert(wrapped.clone()) {
                continue;
            }
            let mut n = 0u32;
            let key = loop {
                let key = format!("{DEK_SHADOW_PREFIX}{version}:{n}").into_bytes();
                if !entries.iter().any(|(k, _)| *k == key) {
                    break key;
                }
                n += 1;
            };
            entries.push((key, wrapped));
        }
        Ok(entries)
    }

    /// Checks that a decoded backup payload can be installed on this node --
    /// right format version, and its DEK manifest unwraps under this node's
    /// KEK -- without touching any state.
    ///
    /// The leader runs this before proposing a live restore so a bad backup
    /// is rejected up front rather than committed and rejected on every node.
    pub fn validate_backup_payload(&self, payload_bytes: &[u8]) -> io::Result<()> {
        let payload: SnapshotPayload = deserialize(payload_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        check_snapshot_format_version(payload.version)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let manifest = dek_manifest_from_payload(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        dek_epochs_from_manifest(&manifest, self.kek.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(())
    }

    /// Applies a committed [`StoreCommand::RestoreApply`]: reassembles the
    /// staged chunks of `restore_id` into the encrypted backup blob and
    /// replaces the replicated state with it, keeping this node's Raft
    /// bookkeeping.
    ///
    /// Deterministic across nodes. A rejected backup is reported as
    /// [`RestoreError::Rejected`] (surfaced to the caller as a violation,
    /// never as an I/O error that would take the node down) and its staged
    /// chunks are discarded; that outcome leaves the replicated state
    /// untouched. An I/O error while writing is [`RestoreError::Fatal`].
    ///
    /// Must be called without `keyspace_lifecycle` held.
    pub(super) fn apply_restore(
        &self,
        restore_id: &str,
        chunks: u32,
        total_len: u64,
    ) -> Result<(), RestoreError> {
        let outcome = self.restore_from_staged(restore_id, chunks, total_len);
        // On success the install already wiped `meta` (staging included);
        // on rejection the chunks must still go.
        if matches!(outcome, Err(RestoreError::Rejected(_))) {
            self.discard_staged_restore(restore_id);
        }
        outcome
    }

    /// Removes every staged chunk of `restore_id`.
    pub(super) fn discard_staged_restore(&self, restore_id: &str) {
        let prefix = restore_stage_prefix(restore_id);
        let mut batch = self.db.batch();
        for item in self.meta.prefix(&prefix) {
            if let Ok(key) = item.key() {
                batch.remove(&self.meta, key);
            }
        }
        if let Err(e) = batch.commit() {
            tracing::warn!(restore_id, error = %e, "failed to discard staged restore chunks");
        }
    }

    pub(super) fn restore_from_staged(
        &self,
        restore_id: &str,
        chunks: u32,
        total_len: u64,
    ) -> Result<(), RestoreError> {
        let rejected = |msg: String| RestoreError::Rejected(msg);
        let prefix = restore_stage_prefix(restore_id);
        // First pass reads keys only, so the chunks are never held twice.
        let mut seqs: Vec<u32> = Vec::new();
        for item in self.meta.prefix(&prefix) {
            let key = item.key().map_err(|e| {
                RestoreError::Fatal(io::Error::other(format!(
                    "reading staged restore chunk: {e}"
                )))
            })?;
            let seq = key
                .get(prefix.len()..)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_be_bytes)
                .ok_or_else(|| rejected("malformed staged restore chunk key".to_string()))?;
            seqs.push(seq);
        }
        seqs.sort_unstable();
        if seqs.len() != chunks as usize || seqs.iter().enumerate().any(|(i, s)| *s as usize != i) {
            return Err(rejected(format!(
                "restore {restore_id}: expected {chunks} contiguous chunks, found {}",
                seqs.len()
            )));
        }
        if total_len > MAX_LIVE_RESTORE_SIZE {
            return Err(rejected(format!(
                "restore {restore_id}: {total_len} bytes exceeds the {MAX_LIVE_RESTORE_SIZE} byte limit"
            )));
        }
        let mut blob = Vec::with_capacity(usize::try_from(total_len).unwrap_or(0));
        for seq in seqs {
            let data = self
                .meta
                .get(restore_stage_key(restore_id, seq))
                .map_err(|e| {
                    RestoreError::Fatal(io::Error::other(format!(
                        "reading staged restore chunk: {e}"
                    )))
                })?
                .ok_or_else(|| rejected(format!("restore {restore_id}: chunk {seq} vanished")))?;
            blob.extend_from_slice(&data);
        }
        if blob.len() as u64 != total_len {
            return Err(rejected(format!(
                "restore {restore_id}: expected {total_len} bytes, staged {}",
                blob.len()
            )));
        }

        let (file, _, _) = self
            .decrypt_backup_file(&blob)
            .map_err(|e| rejected(format!("invalid backup blob: {e}")))?;
        drop(blob);
        match self.install_payload(file.payload, RaftBookkeeping::Keep) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                Err(rejected(format!("installing backup: {e}")))
            }
            Err(e) => Err(RestoreError::Fatal(e)),
        }
    }

    /// Decrypts an operator backup blob into its [`SnapshotFile`], also
    /// trying the DEK epochs the backup's own manifest carries (unwrapped
    /// with this node's KEK): this node usually holds a different DEK than
    /// the cluster that produced the backup.
    pub(super) fn decrypt_backup_file(
        &self,
        bytes: &[u8],
    ) -> Result<(SnapshotFile, u32, u64), crate::StoreError> {
        let extra: Vec<Arc<DekEpoch>> = match read_dek_manifest(bytes) {
            Ok(manifest) => {
                let (current, retired) = dek_epochs_from_manifest(&manifest, self.kek.as_ref())?;
                std::iter::once(current)
                    .chain(retired.into_values())
                    .collect()
            }
            // Backups taken before snapshot files carried a manifest.
            Err(_) => Vec::new(),
        };
        decrypt_snapshot_file(bytes, &self.dek, &self.old_deks, &self.shadow_deks, &extra)
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
        let (snapshot_file, dek_version, utc_epoch) = self.decrypt_backup_file(bytes)?;

        let data_bytes = rmp_serde::to_vec(&snapshot_file.payload)
            .map_err(|e| crate::StoreError::Other(eyre::eyre!("snapshot re-serialize: {e}")))?;

        let snapshot = openraft::storage::Snapshot {
            meta: snapshot_file.meta,
            snapshot: data_bytes,
        };
        Ok((snapshot, utc_epoch, dek_version))
    }
}
