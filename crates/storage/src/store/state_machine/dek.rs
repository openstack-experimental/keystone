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

//! Data encryption key handling: wrapping, installation and state
//! encryption.

use super::*;

impl FjallStateMachine {
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
    pub(super) fn decrypt_state_by_version(
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

    /// Same deterministic-epoch selection as
    /// [`Self::decrypt_state_by_version`], but also returns the record's
    /// next nonce version (`stored_version + 1`, per [`state_decrypt`]'s
    /// contract).
    ///
    /// Shared with [`Self::encrypt_and_store`], which needs that version to
    /// continue the per-record nonce counter across a DEK rotation instead
    /// of guessing at it by decrypting with the wrong (current) epoch and
    /// falling back to `0` on the resulting GCM failure (GitHub #1295) —
    /// which both broke the documented "monotonic per-record version"
    /// invariant and let a write silently overwrite a genuinely tampered
    /// record instead of counting it toward quarantine.
    pub(super) fn decrypt_state_by_version_raw(
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
    pub(super) fn decrypt_state_legacy_probe(
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
                // ALWAYS record failure first, even if retired DEK succeeds (M6
                // fix). The retired DEK fallback is only for
                // reading pre-rotation data, but the GCM
                // failure with the current DEK still counts toward
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
    pub(super) fn encrypt_and_store(
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
        let threshold = self.write_rate_threshold();
        if next_version >= threshold {
            let key_str = String::from_utf8_lossy(key).into_owned();
            tracing::error!(
                key = %key_str,
                version = next_version,
                threshold,
                "CRITICAL: per-record write rate threshold reached; further writes to the \
                 record are rejected",
            );
            return Err(StoreError::WriteRateExceeded(key_str, next_version));
        } else if next_version >= threshold / 10 * 9 {
            tracing::warn!(
                key = %String::from_utf8_lossy(key),
                version = next_version,
                threshold,
                "per-record write count at 90% of threshold",
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
}
