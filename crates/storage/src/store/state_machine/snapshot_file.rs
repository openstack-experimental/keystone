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

//! On-disk snapshot and backup file format.

use super::*;

/// Snapshot wire/on-disk payload format version.
///
/// Bump whenever `SnapshotPayload`'s layout changes, so a snapshot written
/// by an incompatible version is rejected by `install_snapshot` with a
/// clear error instead of being silently misinterpreted (GitHub #1293).
pub(super) const SNAPSHOT_FORMAT_VERSION: u32 = 2;

/// Keyspaces that are node-local and must never travel inside a snapshot:
/// `logs` is the Raft log itself (compaction/log truncation handle it
/// separately) and `local_emergency` is deliberately node-local by design
/// (ADR 0028).
pub(super) const SNAPSHOT_SKIP_KEYSPACES: &[&str] = &["logs", "local_emergency"];

/// Fjall meta key recording the filenames of the most recently written
/// local snapshot files, newest first, as a msgpack-encoded `Vec<String>`
/// (GitHub #1296 item 1).
///
/// `latest_snapshot_path`/`get_current_snapshot` used to pick the
/// "latest" snapshot as the lexicographically greatest filename among
/// `<leader_id>-<index>-<rand>`, which picks a *stale* snapshot once the
/// applied index crosses a digit boundary (`"1-9-123" > "1-10-456"` as
/// strings) — openraft then ships a snapshot below the purged log to a
/// lagging follower, which can never catch up, and the `Backup` RPC
/// silently backs up stale state. Recording the actual write order here
/// sidesteps filename parsing entirely.
pub(super) const SNAPSHOT_HISTORY_META_KEY: &[u8] = b"_meta:snapshot:history";

/// Number of local snapshot files retained on disk.
///
/// Kept greater than 1 so `get_current_snapshot` has an older,
/// previously-valid file to fall back to if the newest one turns out
/// corrupt or undecryptable at startup (GitHub #1296 item 3), instead of
/// refusing to start with no operator recourse.
pub(super) const SNAPSHOT_KEEP: usize = 2;

/// One keyspace's full contents inside a [`SnapshotPayload`]: `(key, value)`
/// pairs exactly as stored in Fjall.
pub(super) type SnapshotKeyspaceEntries = Vec<(Vec<u8>, Vec<u8>)>;

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
pub(super) struct SnapshotPayload {
    pub(super) version: u32,
    /// `(keyspace name, entries)` for every non-skipped Fjall keyspace --
    /// `meta`, `data`, `index`, and every dynamic application keyspace
    /// (`domain`, `project_id`, time-bucketed OAuth2 sessions, SCIM
    /// realms, ...).
    pub(super) keyspaces: Vec<(String, SnapshotKeyspaceEntries)>,
    /// Names of keyspaces that are ephemeral (in-memory-only, non-Fjall) on
    /// the snapshotting node.
    ///
    /// Values are intentionally not included: ephemeral keyspaces hold
    /// inherently short-lived data (WebAuthn/OAuth2 challenge state), so
    /// losing in-flight entries across a snapshot install is acceptable.
    /// The *names* must still survive so a node installing this snapshot
    /// keeps classifying future writes to them as ephemeral rather than
    /// Fjall-backed (see [`FjallStateMachine::ephemeral`]).
    pub(super) ephemeral_keyspaces: Vec<String>,
}

/// Snapshot file format: Raft metadata + versioned payload, stored together.
#[derive(Serialize, Deserialize)]
pub(super) struct SnapshotFile {
    pub(super) meta: SnapshotMetaOf<TypeConfig>,
    pub(super) payload: SnapshotPayload,
}

/// Wrapped DEK material every snapshot file carries in its (unencrypted)
/// header, so a snapshot can be decrypted by a node that does not hold the
/// snapshotting cluster's DEK yet -- the restore-into-a-fresh-cluster case
/// (ADR 0016-v2 §7 step 3, GitHub #1298).
///
/// Every entry is still wrapped under the cluster KEK exactly as in the
/// `meta` keyspace, so the header leaks nothing a holder of the KEK could
/// not already read from the (KEK-wrapped) `meta` entries inside the
/// payload; a restore therefore requires the target cluster to use the
/// same KEK material as the source.
#[derive(Serialize, Deserialize)]
pub(super) struct DekManifest {
    /// Current epoch `(version, wrapped)`.
    pub(super) current: (u32, Vec<u8>),
    /// Retired and revoked-but-not-yet-migrated epochs, still needed to
    /// decrypt records that were not re-encrypted at backup time.
    pub(super) retired: Vec<(u32, Vec<u8>)>,
}

/// Upper bound for the manifest length read from a snapshot header.
pub(super) const MAX_DEK_MANIFEST_LEN: usize = 1024 * 1024;

/// Extracts the [`DekManifest`] from the `meta` keyspace entries captured in
/// `payload`, so the manifest always matches the payload it travels with.
pub(super) fn dek_manifest_from_payload(payload: &SnapshotPayload) -> io::Result<DekManifest> {
    let invalid = |msg: String| io::Error::new(io::ErrorKind::InvalidData, msg);
    let entries = payload
        .keyspaces
        .iter()
        .find(|(name, _)| name == "meta")
        .map(|(_, entries)| entries.as_slice())
        .unwrap_or_default();

    let mut current = None;
    let mut retired = BTreeMap::new();
    for (key, value) in entries {
        if key.as_slice() == META_DEK_CURRENT {
            if value.len() < 64 {
                return Err(invalid(format!(
                    "invalid DEK stored size in snapshot: {} bytes",
                    value.len()
                )));
            }
            let version = u32::from_be_bytes(
                value[..4]
                    .try_into()
                    .map_err(|_| invalid("invalid DEK version prefix in snapshot".into()))?,
            );
            current = Some((version, value[4..].to_vec()));
            continue;
        }
        let Ok(key) = std::str::from_utf8(key) else {
            continue;
        };
        let version = key
            .strip_prefix(DEK_RETIRED_PREFIX)
            .or_else(|| key.strip_prefix(DEK_REVOKED_PENDING_PREFIX))
            .and_then(|v| v.parse::<u32>().ok());
        if let Some(version) = version {
            retired.entry(version).or_insert_with(|| value.clone());
        }
    }
    let current = current
        .ok_or_else(|| invalid("snapshot carries no current DEK (`_meta:dek:current`)".into()))?;
    Ok(DekManifest {
        current,
        retired: retired.into_iter().collect(),
    })
}

/// Unwraps every DEK in `manifest` with `kek`, returning the current epoch
/// and the retired ones. Fails closed: a DEK that cannot be unwrapped means
/// the KEK differs from the snapshotting cluster's (or the manifest is
/// corrupt), and silently skipping it would strand records under it.
pub(super) fn dek_epochs_from_manifest(
    manifest: &DekManifest,
    kek: &dyn KekProvider,
) -> Result<(Arc<DekEpoch>, BTreeMap<u32, Arc<DekEpoch>>), StoreError> {
    let unwrap = |version: u32, wrapped: &[u8]| -> Result<Arc<DekEpoch>, StoreError> {
        let raw = kek.unwrap_dek(wrapped).map_err(|e| {
            StoreError::Other(eyre::eyre!(
                "cannot unwrap DEK version {version} from the snapshot: {e}; the target \
                 cluster must use the same KEK material as the cluster that produced it"
            ))
        })?;
        Ok(Arc::new(DekEpoch::from_raw(
            LockedKey::from_raw(*raw),
            version,
        )?))
    };
    let current = unwrap(manifest.current.0, &manifest.current.1)?;
    let mut retired = BTreeMap::new();
    for (version, wrapped) in &manifest.retired {
        retired.insert(*version, unwrap(*version, wrapped)?);
    }
    Ok((current, retired))
}

/// Checks a decoded snapshot payload's format version against
/// [`SNAPSHOT_FORMAT_VERSION`], returning the mismatch message shared by
/// every call site so a future version-check change (e.g. a min-supported
/// range) only needs to be made once.
pub(super) fn check_snapshot_format_version(version: u32) -> Result<(), String> {
    if version != SNAPSHOT_FORMAT_VERSION {
        return Err(format!(
            "unsupported snapshot format version {version} (this node expects {SNAPSHOT_FORMAT_VERSION})"
        ));
    }
    Ok(())
}

/// Length of the fixed part of a snapshot file header:
/// `dek_version (4) + utc_epoch (8) + nonce_salt (8) + manifest_len (4)`.
pub(super) const SNAPSHOT_HEADER_LEN: usize = 4 + 8 + 8 + 4;

/// Splits a snapshot file into its [`DekManifest`] and the encrypted body.
pub(super) fn split_snapshot_manifest(
    disk_bytes: &[u8],
) -> Result<(DekManifest, &[u8]), crate::StoreError> {
    let err = |msg: String| crate::StoreError::Other(eyre::eyre!(msg));
    if disk_bytes.len() < SNAPSHOT_HEADER_LEN {
        return Err(err(format!(
            "snapshot file too short: {} bytes",
            disk_bytes.len()
        )));
    }
    let manifest_len = u32::from_be_bytes(
        disk_bytes[20..24]
            .try_into()
            .map_err(|_| err("invalid snapshot manifest length".into()))?,
    ) as usize;
    let body_start = SNAPSHOT_HEADER_LEN
        .checked_add(manifest_len)
        .filter(|end| manifest_len <= MAX_DEK_MANIFEST_LEN && *end <= disk_bytes.len())
        .ok_or_else(|| err(format!("invalid snapshot manifest length {manifest_len}")))?;
    let manifest: DekManifest = rmp_serde::from_slice(&disk_bytes[SNAPSHOT_HEADER_LEN..body_start])
        .map_err(|e| err(format!("snapshot DEK manifest deserialize: {e}")))?;
    Ok((manifest, &disk_bytes[body_start..]))
}

/// Reads just the [`DekManifest`] from a snapshot file / backup blob.
pub(super) fn read_dek_manifest(disk_bytes: &[u8]) -> Result<DekManifest, crate::StoreError> {
    split_snapshot_manifest(disk_bytes).map(|(manifest, _)| manifest)
}

/// Length of the header of snapshot files written before they carried a
/// [`DekManifest`]: `dek_version (4) + utc_epoch (8) + nonce_salt (8)`, then
/// the ciphertext directly.
pub(super) const LEGACY_SNAPSHOT_HEADER_LEN: usize = 4 + 8 + 8;

/// Decrypt and deserialize a snapshot file from disk.
///
/// On-disk format:
/// `[dek_version_u32_BE; 4] ++ [utc_epoch_u64_BE; 8] ++ [nonce_salt_u64_BE; 8] ++
/// [manifest_len_u32_BE; 4] ++ DekManifest ++
/// backup_encrypt(rmp_serde(SnapshotFile))`. Files without the manifest (the
/// header is followed by the ciphertext directly) are still read: the
/// authenticated decryption tells the two layouts apart. `extra_epochs` are
/// candidate epochs tried after this node's own (e.g. those unwrapped from
/// the snapshot's own manifest during a restore). `nonce_salt` is generated
/// fresh per snapshot and stored directly in the header (GitHub #1296 item
/// 4), so decryption needs exactly one attempt per candidate DEK epoch
/// instead of brute-forcing a missing counter over `0..1024`.
pub(super) fn decrypt_snapshot_file(
    disk_bytes: &[u8],
    current_dek: &std::sync::Arc<std::sync::RwLock<std::sync::Arc<DekEpoch>>>,
    old_deks: &std::sync::Arc<std::sync::Mutex<BTreeMap<u32, std::sync::Arc<DekEpoch>>>>,
    shadow_deks: &std::sync::Arc<std::sync::Mutex<Vec<std::sync::Arc<DekEpoch>>>>,
    extra_epochs: &[std::sync::Arc<DekEpoch>],
) -> Result<(SnapshotFile, u32, u64), crate::StoreError> {
    use openstack_keystone_storage_crypto::dek::BackupDek;

    if disk_bytes.len() < LEGACY_SNAPSHOT_HEADER_LEN {
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
    let nonce_salt = u64::from_be_bytes(
        disk_bytes[12..20]
            .try_into()
            .map_err(|_| crate::StoreError::Other(eyre::eyre!("invalid snapshot nonce salt")))?,
    );
    let mut bodies: Vec<&[u8]> = Vec::with_capacity(2);
    if let Ok((_, encrypted)) = split_snapshot_manifest(disk_bytes) {
        bodies.push(encrypted);
    }
    bodies.push(&disk_bytes[LEGACY_SNAPSHOT_HEADER_LEN..]);

    let try_decrypt = |epoch: &DekEpoch| -> Option<zeroize::Zeroizing<Vec<u8>>> {
        if epoch.version != dek_version {
            return None;
        }
        let bdek = BackupDek::from_raw(*epoch.backup_dek().as_bytes());
        bodies.iter().find_map(|encrypted| {
            backup_decrypt(&bdek, encrypted, dek_version, utc_epoch, nonce_salt).ok()
        })
    };

    let file_bytes = {
        let guard = current_dek.read().unwrap_or_else(|p| p.into_inner());
        try_decrypt(&guard)
    }
    .or_else(|| {
        let old = old_deks.lock().unwrap_or_else(|p| p.into_inner());
        old.values().find_map(|epoch| try_decrypt(epoch))
    })
    .or_else(|| {
        let shadow = shadow_deks.lock().unwrap_or_else(|p| p.into_inner());
        shadow.iter().find_map(|epoch| try_decrypt(epoch))
    })
    .or_else(|| extra_epochs.iter().find_map(|epoch| try_decrypt(epoch)))
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
