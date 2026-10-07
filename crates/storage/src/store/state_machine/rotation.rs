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

//! DEK rotation: pending rotations and background re-encryption.

use super::*;

/// Fjall meta key prefix for retired DEK epochs.
pub(super) const DEK_RETIRED_PREFIX: &str = "_meta:dek:retired:";
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
pub(super) const META_DEK_CURRENT: &[u8] = b"_meta:dek:current";
/// Fjall meta key prefix for pending emergency rotations.
pub(super) const PENDING_ROTATION_PREFIX: &str = "_meta:rotation:pending:";
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
pub(super) const DEK_REENCRYPT_DONE_PREFIX: &str = "_meta:dek:reencrypt_done:";

/// Fjall meta key holding when the current DEK epoch was installed:
/// `[version_u32_BE; 4] ++ [unix_secs_u64_BE; 8]`. Drives the time-based
/// automatic rotation (`[distributed_storage] dek_rotation_days`).
pub(super) const META_DEK_INSTALLED_AT: &[u8] = b"_meta:dek:installed_at";

/// Fjall meta key prefix of a re-encryption sweep checkpoint
/// (`<prefix><node_id>:<version>`). Each node sweeps its own state, so the
/// checkpoint is node-scoped and never taken from a snapshot.
pub(super) const REENCRYPT_PROGRESS_PREFIX: &str = "_meta:dek:rotation_progress:";

/// Records visited between two persisted re-encryption checkpoints.
pub(super) const REENCRYPT_CHECKPOINT_INTERVAL: u64 = 1000;

/// Maximum number of optimistic-CAS attempts per record during background
/// re-encryption before the record is left for the next rotation cycle
/// (ADR 0016-v2 §6 step 5).
pub(super) const REENCRYPT_MAX_CAS_ATTEMPTS: usize = 3;

/// Keyspaces that never hold `state_encrypt`-encrypted records and are
/// skipped by the background re-encryption sweep: `meta` holds DEK/
/// quarantine/rotation bookkeeping and per-record `Metadata` (plaintext
/// MessagePack, not state-tier ciphertext), `logs` holds the Raft log
/// (encrypted with the Log DEK via a different scheme in `log_store.rs`,
/// naturally rotated out by snapshot compaction), and `index` holds bare
/// existence markers with empty values.
pub(super) const REENCRYPT_SKIP_KEYSPACES: &[&str] = &["meta", "logs", "index"];

/// Outcome of attempting to migrate a single record to the current DEK epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReencryptOutcome {
    /// Re-encrypted under the current epoch.
    Migrated,
    /// Not eligible: already under a different epoch, or the record/its
    /// metadata vanished before it could be migrated.
    AlreadyCurrent,
    /// Exhausted the CAS retry budget; left for the next rotation cycle.
    Skipped,
}

/// A deferred in-memory mutation to `pending_rotations`, applied only once
/// the transaction's `batch` has actually committed (GitHub #1297 item 4).
///
/// `CreatePendingRotation`/`ConfirmPendingRotation` used to mutate
/// `pending_rotations` directly while processing their own mutation, even
/// though a *different* mutation later in the same `Transaction` could
/// still produce a violation and leave the whole `batch` uncommitted —
/// leaving the in-memory map and the Fjall `meta` entry disagreeing until
/// restart.
pub(super) enum PendingRotationMutation {
    Insert(String, PendingRotation),
    Remove(String),
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

/// Persisted position of an interrupted re-encryption pass over one retired
/// epoch, with the counts of the part already done.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ReencryptProgress {
    /// Keyspace of the last visited record.
    pub keyspace: String,
    /// Key of the last visited record.
    pub key: Vec<u8>,
    pub migrated: u64,
    pub already_current: u64,
    pub skipped: u64,
}

/// Checkpoint key of `node_id`'s sweep over epoch `version`.
pub(super) fn reencrypt_progress_key(node_id: u64, version: u32) -> String {
    format!("{REENCRYPT_PROGRESS_PREFIX}{node_id}:{version}")
}

/// Seconds since the Unix epoch.
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Value of [`META_DEK_INSTALLED_AT`].
pub(super) fn dek_installed_at_value(version: u32, installed_at: u64) -> Vec<u8> {
    let mut value = version.to_be_bytes().to_vec();
    value.extend_from_slice(&installed_at.to_be_bytes());
    value
}

/// Violation for a DEK install whose version is not above the current one.
pub(super) fn stale_dek_version_violation(version: u32, current: u32) -> Option<Violation> {
    (version <= current).then(|| Violation {
        r#type: "STALE_DEK_VERSION".to_string(),
        subject: version.to_string(),
        description: format!(
            "DEK version {version} is not newer than the current version {current}; \
             another rotation committed first"
        ),
    })
}

/// Maximum number of revoked DEK versions tracked in memory.
///
/// Revoked versions accumulate only on emergency rotations.  Exceeding this
/// cap is operationally impossible under normal conditions (it would require
/// more than 1024 security incidents), but the cap prevents unbounded growth
/// and triggers an ERROR log so operators can investigate.
pub(super) const MAX_REVOKED_DEKS: usize = 1024;

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

impl FjallStateMachine {
    /// Version of the current DEK epoch.
    pub(crate) fn current_dek_version(&self) -> u32 {
        self.dek.read().unwrap_or_else(|p| p.into_inner()).version
    }

    /// When the current DEK epoch was installed (Unix seconds), if recorded
    /// for that epoch.
    pub fn dek_installed_at(&self) -> Option<u64> {
        let value = self.meta.get(META_DEK_INSTALLED_AT).ok().flatten()?;
        let version = u32::from_be_bytes(value.get(..4)?.try_into().ok()?);
        let installed_at = u64::from_be_bytes(value.get(4..12)?.try_into().ok()?);
        (version == self.current_dek_version()).then_some(installed_at)
    }

    /// Record the current DEK epoch as installed now unless an install time
    /// is already known for it: the epoch bootstrapped on first start, and
    /// nodes that ran before install times were recorded, start their
    /// rotation interval here.
    pub fn ensure_dek_installed_at(&self) -> Result<(), StoreError> {
        if self.dek_installed_at().is_none() {
            self.meta.insert(
                META_DEK_INSTALLED_AT,
                dek_installed_at_value(self.current_dek_version(), unix_now()),
            )?;
        }
        Ok(())
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
            self.raft_prometheus_metrics
                .record_reencrypt_report(&report);
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
    pub(super) async fn finalize_if_revoked(&self, epoch: &Arc<DekEpoch>) {
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
    pub(super) fn count_log_entries_under_version(&self, version: u32) -> usize {
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
    /// walking all non-system keyspaces in name and key order.
    ///
    /// The position is checkpointed every [`REENCRYPT_CHECKPOINT_INTERVAL`]
    /// records, so a pass interrupted by a restart resumes where it stopped
    /// (ADR 0016-v2 §6 "Progress") with the counts of the part already done;
    /// records skipped before the interruption therefore still keep the
    /// epoch from being marked fully migrated. The checkpoint is removed
    /// once the pass completes.
    pub(super) async fn reencrypt_epoch(&self, old_epoch: &DekEpoch) -> ReencryptReport {
        let progress_key = reencrypt_progress_key(self.node_id, old_epoch.version);
        let resume = self.load_reencrypt_progress(&progress_key);
        let mut report = resume
            .as_ref()
            .map(|p| ReencryptReport {
                migrated: p.migrated,
                already_current: p.already_current,
                skipped: p.skipped,
            })
            .unwrap_or_default();
        if let Some(p) = &resume {
            tracing::info!(
                old_version = old_epoch.version,
                keyspace = p.keyspace,
                "DEK rotation: resuming re-encryption pass from checkpoint"
            );
        }

        let mut names: Vec<String> = self
            .db
            .list_keyspace_names()
            .into_iter()
            .map(|name| name.to_string())
            .filter(|name| !REENCRYPT_SKIP_KEYSPACES.contains(&name.as_str()))
            .collect();
        names.sort();

        let mut since_checkpoint = 0u64;
        for keyspace_name in names {
            if resume.as_ref().is_some_and(|p| keyspace_name < p.keyspace) {
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
                .filter(|k| {
                    !resume.as_ref().is_some_and(|p| {
                        p.keyspace == keyspace_name && k.as_slice() <= p.key.as_slice()
                    })
                })
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

                since_checkpoint += 1;
                if since_checkpoint >= REENCRYPT_CHECKPOINT_INTERVAL {
                    since_checkpoint = 0;
                    self.save_reencrypt_progress(
                        &progress_key,
                        &ReencryptProgress {
                            keyspace: keyspace_name.clone(),
                            key: key.clone(),
                            migrated: report.migrated,
                            already_current: report.already_current,
                            skipped: report.skipped,
                        },
                    );
                }
            }
        }

        if let Err(e) = self.meta.remove(progress_key.as_bytes()) {
            tracing::warn!(
                old_version = old_epoch.version,
                error = %e,
                "failed to remove re-encryption checkpoint; the next pass resumes from it"
            );
        }
        report
    }

    /// Load a re-encryption checkpoint. An unreadable one is ignored, which
    /// only costs a pass from the start.
    pub(super) fn load_reencrypt_progress(&self, key: &str) -> Option<ReencryptProgress> {
        let value = self.meta.get(key.as_bytes()).ok().flatten()?;
        match rmp_serde::from_slice(&value) {
            Ok(progress) => Some(progress),
            Err(e) => {
                tracing::warn!(error = %e, "ignoring unreadable re-encryption checkpoint");
                None
            }
        }
    }

    /// Persist a re-encryption checkpoint. Best effort: a lost checkpoint
    /// only costs revisiting records on resume.
    pub(super) fn save_reencrypt_progress(&self, key: &str, progress: &ReencryptProgress) {
        let saved = rmp_serde::to_vec(progress)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                self.meta
                    .insert(key.as_bytes(), bytes)
                    .map_err(|e| e.to_string())
            });
        if let Err(e) = saved {
            tracing::warn!(error = %e, "failed to persist re-encryption checkpoint");
        }
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
    pub(super) fn reencrypt_one(
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
}
