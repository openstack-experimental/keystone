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
//! # Data Encryption Key (DEK) hierarchy
//!
//! A [`DekEpoch`] holds the current DEK version and the sub-keys derived from
//! it via HKDF.  Sub-keys are domain-separated so log, state, and
//! backup ciphertexts are never encrypted under the same key context.
//!
//! ## Sub-key derivation
//!
//! ```text
//! DEK (256-bit uniform random)
//!  ├── LogDek   = HKDF(salt, DEK, info="keystone-raft-log-v1",    L=32)
//!  └── StateDek = HKDF(salt, DEK, info="keystone-fjall-state-v1", L=32)
//! ```
//!
//! with `salt = "keystone-dek-hierarchy-v1"`. The DEK is already
//! cryptographically uniform random (generated with a CSPRNG), so Extract adds
//! no entropy; it is run anyway, with a fixed public salt and a non-empty
//! info, because full Extract-then-Expand is the flow the FIPS module
//! documents as an approved service (ADR §2.1).

use crate::audit::AuditHmacKey;
use crate::backend::{fill_random, hkdf_extract_expand};
use crate::error::CryptoError;
use crate::mlock::LockedKey;

/// HKDF salt of the key hierarchy. Full Extract-then-Expand with a non-empty
/// salt and info is the flow the FIPS module documents as an approved
/// service; the salt is a fixed public domain separator, as the DEK itself is
/// already uniformly random.
const DEK_HIERARCHY_SALT: &[u8] = b"keystone-dek-hierarchy-v1";
const LOG_DEK_INFO: &[u8] = b"keystone-raft-log-v1";
const STATE_DEK_INFO: &[u8] = b"keystone-fjall-state-v1";
const BACKUP_DEK_INFO_PREFIX: &[u8] = b"keystone-backup-v1";
const AUDIT_DEK_INFO_PREFIX: &[u8] = b"keystone-audit-dek-v1";

// ---------------------------------------------------------------------------
// Sub-key types  (no Debug/Display — never format key material)
// ---------------------------------------------------------------------------

/// Sub-key for encrypting Raft log entries.
///
/// Backed by `LockedKey` (mlock'd, guard-paged memory) per ADR §9 ("all keys
/// — `Dek`, `LogDek`, `StateDek` — ... must be allocated in memory-locked
/// pages").
pub struct LogDek(pub(crate) LockedKey);

/// Sub-key for encrypting Fjall state machine entries.
///
/// Backed by `LockedKey` (mlock'd, guard-paged memory) per ADR §9.
pub struct StateDek(pub(crate) LockedKey);

/// Sub-key for encrypting Raft snapshot (backup) data.
///
/// Derived per-DEK-version so backup ciphertexts are never re-usable across
/// rotation epochs.  Stored independently of `StateDek` so a compromised
/// backup does not expose live data keys.  Backed by `LockedKey` (mlock'd,
/// guard-paged memory) per ADR §9, Invariant 8.
pub struct BackupDek(pub(crate) LockedKey);

impl BackupDek {
    /// Access the raw key bytes (e.g. for AES-256-GCM snapshot encryption).
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Wrap raw key bytes into a `BackupDek` (used externally when copying
    /// bytes out of a lock guard before calling backup_encrypt/decrypt).
    pub fn from_raw(raw: [u8; 32]) -> Self {
        Self(LockedKey::from_raw(raw))
    }
}

/// Derive the backup sub-key info string for a given epoch version.
fn backup_info(version: u32) -> Vec<u8> {
    let mut buf = BACKUP_DEK_INFO_PREFIX.to_vec();
    buf.extend_from_slice(&version.to_be_bytes());
    buf
}

// ---------------------------------------------------------------------------
// DekEpoch
// ---------------------------------------------------------------------------

/// A single DEK rotation epoch: version number, root DEK in mlock'd memory,
/// and derived sub-keys.
///
/// All encryption in a given epoch uses the sub-keys held here.  On DEK
/// rotation (Phase 5) a new `DekEpoch` with an incremented version replaces
/// this one.
///
/// The root DEK is stored in a `LockedKey` (mlock'd page) per ADR §9.
/// Sub-keys are derived via HKDF and stored independently.
pub struct DekEpoch {
    backup_dek: BackupDek,
    log_dek: LogDek,
    /// Root 256-bit DEK in mlock'd memory (ADR §9, Invariant 8).
    root_dek: LockedKey,
    state_dek: StateDek,
    /// Monotonically increasing epoch counter (`dek_version_u32`).
    pub version: u32,
}

impl DekEpoch {
    /// Returns the backup (snapshot) sub-key for this epoch.
    pub fn backup_dek(&self) -> &BackupDek {
        &self.backup_dek
    }

    /// Derive the per-epoch audit HMAC key from the root DEK (ADR §3.1).
    ///
    /// `AuditHmacKey = HKDF(salt, DEK, info = b"keystone-audit-dek-v1" ++
    /// version_u32_be ++ node_id_u64_be, L=32)`. Binding to both DEK
    /// version and node ID ensures the audit key rotates with every DEK
    /// rotation and cannot be forged across nodes.
    pub fn derive_audit_key(&self, node_id: u64) -> Result<AuditHmacKey, CryptoError> {
        let mut info = AUDIT_DEK_INFO_PREFIX.to_vec();
        info.extend_from_slice(&self.version.to_be_bytes());
        info.extend_from_slice(&node_id.to_be_bytes());
        let mut out = [0u8; 32];
        hkdf_extract_expand(
            DEK_HIERARCHY_SALT,
            self.root_dek.as_bytes().as_ref(),
            &info,
            &mut out,
        )?;
        Ok(AuditHmacKey::from_raw(out))
    }

    /// Derive a `DekEpoch` from a `LockedKey` containing the root DEK bytes.
    ///
    /// Uses HKDF (Extract-then-Expand) to produce domain-separated sub-keys.
    /// The backup sub-key is version-bound so different rotation epochs produce
    /// different backup encryption keys.
    pub fn from_raw(dek: LockedKey, version: u32) -> Result<Self, CryptoError> {
        let ikm = dek.as_bytes();

        // Derive sub-keys directly into mlock'd allocations (ADR §9): never
        // materialise the key in an unlocked buffer first.
        let mut log_locked = LockedKey::alloc().map_err(|_| CryptoError::InvalidKeyLength)?;
        hkdf_extract_expand(
            DEK_HIERARCHY_SALT,
            ikm.as_ref(),
            LOG_DEK_INFO,
            log_locked.as_mut(),
        )?;

        let mut state_locked = LockedKey::alloc().map_err(|_| CryptoError::InvalidKeyLength)?;
        hkdf_extract_expand(
            DEK_HIERARCHY_SALT,
            ikm.as_ref(),
            STATE_DEK_INFO,
            state_locked.as_mut(),
        )?;

        // BackupDek info is version-bound: prefix ++ version_u32_BE.
        // Derive into a LockedKey so backup key material is mlock'd (ADR §9).
        let mut backup_locked = LockedKey::alloc().map_err(|_| CryptoError::InvalidKeyLength)?;
        hkdf_extract_expand(
            DEK_HIERARCHY_SALT,
            ikm.as_ref(),
            &backup_info(version),
            backup_locked.as_mut(),
        )?;

        Ok(Self {
            version,
            root_dek: dek,
            log_dek: LogDek(log_locked),
            state_dek: StateDek(state_locked),
            backup_dek: BackupDek(backup_locked),
        })
    }

    /// Returns the log sub-key.
    pub fn log_dek(&self) -> &LogDek {
        &self.log_dek
    }

    /// Returns the state sub-key.
    pub fn state_dek(&self) -> &StateDek {
        &self.state_dek
    }
}

/// Generate a fresh 256-bit DEK in guard-paged, mlock'd memory using a CSPRNG.
///
/// Returns the key in a `LockedKey` per ADR §9, Invariant 8.
/// Panics on OOM; allocation failure for key material is fatal.
#[allow(clippy::expect_used)]
pub fn generate_dek() -> LockedKey {
    let mut dek = LockedKey::alloc().expect("OOM allocating DEK");
    // CSPRNG-backed: OS RNG by default, the validated module's DRBG with the
    // `fips` feature.
    fill_random(dek.as_mut()).expect("RNG failure generating DEK");
    dek
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_locked_dek() -> LockedKey {
        LockedKey::alloc().expect("alloc failed")
    }

    #[test]
    fn test_dek_epoch_from_raw() {
        let mut raw = test_locked_dek();
        raw.as_mut().copy_from_slice(&[0x55u8; 32]);
        let epoch = DekEpoch::from_raw(raw, 0).expect("derive");
        // Sub-keys must differ from each other and from raw input.
        assert_ne!(epoch.log_dek.0.as_bytes(), &[0x55u8; 32]);
        assert_ne!(epoch.state_dek.0.as_bytes(), &[0x55u8; 32]);
        assert_ne!(epoch.log_dek.0.as_bytes(), epoch.state_dek.0.as_bytes());
    }

    #[test]
    fn test_dek_epoch_deterministic() {
        let mut raw1 = test_locked_dek();
        raw1.as_mut().copy_from_slice(&[0xAAu8; 32]);
        let e1 = DekEpoch::from_raw(raw1, 1).expect("first");
        let mut raw2 = test_locked_dek();
        raw2.as_mut().copy_from_slice(&[0xAAu8; 32]);
        let e2 = DekEpoch::from_raw(raw2, 1).expect("second");
        assert_eq!(e1.log_dek.0.as_bytes(), e2.log_dek.0.as_bytes());
        assert_eq!(e1.state_dek.0.as_bytes(), e2.state_dek.0.as_bytes());
    }

    #[test]
    fn test_generate_dek_non_zero() {
        let dek = generate_dek();
        assert_ne!(dek.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_derive_audit_key_per_epoch() {
        let mut raw = test_locked_dek();
        raw.as_mut().copy_from_slice(&[0xBBu8; 32]);
        let epoch = DekEpoch::from_raw(raw, 42).expect("epoch");
        let audit = epoch.derive_audit_key(1).expect("audit key");
        let mac = audit.sign(b"test").expect("sign");
        assert_eq!(mac.len(), 32);
    }
}
