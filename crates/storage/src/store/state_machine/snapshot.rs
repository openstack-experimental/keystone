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

//! Snapshot files on disk and the snapshot builder.

use super::*;

impl FjallStateMachine {
    /// Return the path of the most recently written snapshot file that
    /// still exists on disk, if any.
    ///
    /// Uses the persisted history recorded by [`Self::record_snapshot_and_gc`]
    /// rather than lexicographic filename order (GitHub #1296 item 1 — see
    /// [`SNAPSHOT_HISTORY_META_KEY`]). openraft 0.10 dropped `snapshot_id`
    /// from `SnapshotMeta`, so callers that need the on-disk path (rather
    /// than going through `RaftStateMachine::get_current_snapshot`) must
    /// locate it this way.
    pub fn latest_snapshot_path(&self) -> io::Result<Option<std::path::PathBuf>> {
        for snapshot_id in self.snapshot_history()? {
            let path = self.snapshot_dir.join(&snapshot_id);
            if path.is_file() {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }

    /// Encrypts `file_bytes` (a serialized [`SnapshotFile`]) with the
    /// current `BackupDek` and writes it to
    /// `<snapshot_dir>/<snapshot_id>`, then records `snapshot_id` as the
    /// newest local snapshot and garbage-collects every on-disk file that
    /// has fallen out of the retained history (GitHub #1296 items 1-2).
    ///
    /// On-disk format: `[dek_version_u32_BE; 4] ++ [utc_epoch_u64_BE; 8] ++
    /// [nonce_salt_u64_BE; 8] ++ [manifest_len_u32_BE; 4] ++ DekManifest ++
    /// AES-256-GCM(file_bytes)`. The KEK-wrapped [`DekManifest`] lets a node
    /// that does not know the DEK yet decrypt a restored backup. `nonce_salt`
    /// is a fresh random value per snapshot rather than a per-process
    /// counter (GitHub #1296 item 4): a counter reset to 0 on every process
    /// restart could reuse a nonce if a snapshot were written again within
    /// the same wall-clock second, and a missing durable counter forced
    /// `decrypt_snapshot_file` to brute-force it (capping snapshots at
    /// 1024 per process lifetime). A random 64-bit salt makes reuse
    /// astronomically unlikely without any durable counter state, and is
    /// stored directly in the header so decryption never has to guess it.
    pub(super) fn persist_snapshot_file(
        &self,
        snapshot_id: &str,
        file_bytes: &[u8],
        manifest: &DekManifest,
    ) -> io::Result<()> {
        // Encrypt under the epoch the manifest names as current, which is
        // the one matching the captured payload even if a rotation landed
        // between payload capture and now.
        let dek_version = manifest.current.0;
        let backup_dek_ref = {
            let guard = self.dek.read().unwrap_or_else(|p| p.into_inner());
            if guard.version == dek_version {
                guard.backup_dek().as_bytes().to_owned()
            } else {
                drop(guard);
                let old = self.old_deks.lock().unwrap_or_else(|p| p.into_inner());
                old.get(&dek_version)
                    .ok_or_else(|| {
                        io::Error::other(format!(
                            "no DEK epoch {dek_version} available to encrypt the snapshot"
                        ))
                    })?
                    .backup_dek()
                    .as_bytes()
                    .to_owned()
            }
        };
        use openstack_keystone_storage_crypto::dek::BackupDek;
        let bdek = BackupDek::from_raw(backup_dek_ref);
        let utc_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let nonce_salt: u64 = rand::rng().random();
        let encrypted = backup_encrypt(&bdek, file_bytes, dek_version, utc_epoch, nonce_salt)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let manifest_bytes =
            rmp_serde::to_vec(manifest).map_err(|e| io::Error::other(e.to_string()))?;
        let manifest_len = u32::try_from(manifest_bytes.len())
            .map_err(|_| io::Error::other("DEK manifest too large"))?;

        let mut disk_bytes = Vec::with_capacity(24 + manifest_bytes.len() + encrypted.len());
        disk_bytes.extend_from_slice(&dek_version.to_be_bytes());
        disk_bytes.extend_from_slice(&utc_epoch.to_be_bytes());
        disk_bytes.extend_from_slice(&nonce_salt.to_be_bytes());
        disk_bytes.extend_from_slice(&manifest_len.to_be_bytes());
        disk_bytes.extend_from_slice(&manifest_bytes);
        disk_bytes.extend_from_slice(&encrypted);

        let snapshot_path = self.snapshot_dir.join(snapshot_id);
        fs::write(&snapshot_path, &disk_bytes)?;

        self.record_snapshot_and_gc(snapshot_id)
    }

    /// Prepends `snapshot_id` to the persisted snapshot history, keeps
    /// only the newest [`SNAPSHOT_KEEP`] entries, and deletes every
    /// on-disk snapshot file that isn't one of them (GitHub #1296 item 2:
    /// snapshot files were previously never garbage-collected, so every
    /// `build_snapshot`/`install_snapshot` left behind a full copy of the
    /// dataset forever).
    pub(super) fn record_snapshot_and_gc(&self, snapshot_id: &str) -> io::Result<()> {
        let mut history = self.snapshot_history()?;
        history.retain(|id| id != snapshot_id);
        history.insert(0, snapshot_id.to_string());
        history.truncate(SNAPSHOT_KEEP);

        let packed = serialize(&history).map_err(|e| io::Error::other(e.to_string()))?;
        self.meta
            .insert(SNAPSHOT_HISTORY_META_KEY, packed)
            .map_err(|e| io::Error::other(e.to_string()))?;

        let keep: HashSet<&str> = history.iter().map(String::as_str).collect();
        for entry in fs::read_dir(&self.snapshot_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !keep.contains(name)
                && let Err(e) = fs::remove_file(&path)
            {
                tracing::warn!(
                    file = name,
                    error = %e,
                    "failed to garbage-collect stale snapshot file"
                );
            }
        }
        Ok(())
    }

    /// Return the path to the snapshot directory.
    #[cfg(test)]
    pub(crate) fn snapshot_dir(&self) -> &std::path::Path {
        &self.snapshot_dir
    }

    /// Returns the persisted snapshot history, newest first (see
    /// [`Self::record_snapshot_and_gc`]).
    pub(super) fn snapshot_history(&self) -> io::Result<Vec<String>> {
        let history: Option<Vec<String>> = self
            .meta
            .get(SNAPSHOT_HISTORY_META_KEY)
            .map_err(|e| io::Error::other(e.to_string()))?
            .map(|bytes| deserialize(&bytes))
            .transpose()
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(history.unwrap_or_default())
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
    /// lock `apply()` holds — so a concurrent
    /// `drop_keyspace`/`install_snapshot` (both write-side) can't create or
    /// remove a keyspace between the `db.snapshot()` call and the
    /// `list_keyspace_names()` walk, and can't tear one down mid-iteration
    /// either.
    pub(super) fn snapshot_payload(&self) -> Result<SnapshotPayload, io::Error> {
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

        // Encrypt snapshot file at rest with BackupDek (ADR §7), persist it,
        // record it as the newest snapshot and GC stale files.
        let manifest = dek_manifest_from_payload(&payload)?;
        self.persist_snapshot_file(&snapshot_id, &file_bytes, &manifest)
            .map_err(|e| {
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
        tracing::trace!(snapshot_id, "snapshot written");

        Ok(Snapshot {
            meta,
            snapshot: data_bytes,
        })
    }
}
