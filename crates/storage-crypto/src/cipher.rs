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
//! # AES-256-GCM encrypt / decrypt helpers
//!
//! Two domains, each with distinct nonce schemes and Associated Data (AD):
//!
//! ## Raft Log (`LogDek`)
//!
//! ```text
//! Nonce  = [8-byte NodeId BE] ++ [4-byte monotonic counter BE]  (ADR §2.2, F1)
//! AD     = [term u64 BE] ++ [index u64 BE]                      (ADR §2.3)
//! Layout = [nonce 12B] ++ [ciphertext] ++ [tag 16B]
//! ```
//!
//! ## Fjall State Machine (`StateDek`)
//!
//! ```text
//! Nonce  = HKDF-Expand(StateDek, info = pk ++ version_u32_be, L=12)  (ADR §2.2)
//! AD     = [tier u8] ++ domain_id ++ pk                               (ADR §2.3)
//! Layout = [nonce 12B] ++ [ciphertext] ++ [tag 16B] ++ [version u32 BE]
//! ```
//!
//! All GCM tags are 16 bytes (full-length).  Truncated tags are prohibited
//! (ADR §2.2).

use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use hybrid_array::Array;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::dek::{BackupDek, LogDek, StateDek};
use crate::error::CryptoError;
use crate::gcm::{GcmKey, GcmNonce, GcmTag};

// Label for snapshot backup AD (ADR §7).
const BACKUP_AD_LABEL: &[u8] = b"keystone-backup-v1";

// Minimum bytes in a stored state value: nonce(12) + tag(16) + version(4) = 32
const STATE_MIN_LEN: usize = 32;
// Minimum bytes in a stored log value: nonce(12) + tag(16) = 28
const LOG_MIN_LEN: usize = 28;

/// Convert a slice reference to a typed GCM nonce array reference.
fn nonce_ref(s: &[u8]) -> Result<&GcmNonce, CryptoError> {
    Array::slice_as_array(s).ok_or(CryptoError::InvalidArrayLength)
}

/// Convert a slice reference to a typed GCM tag array reference.
fn tag_ref(s: &[u8]) -> Result<&GcmTag, CryptoError> {
    Array::slice_as_array(s).ok_or(CryptoError::InvalidArrayLength)
}

/// Convert a 32-byte slice to a typed GCM key array reference.
fn key_ref(s: &[u8]) -> Result<&GcmKey, CryptoError> {
    Array::slice_as_array(s).ok_or(CryptoError::InvalidArrayLength)
}

// ---------------------------------------------------------------------------
// Log encryption
// ---------------------------------------------------------------------------

/// Encrypt a Raft log `app_data` payload.
///
/// # Parameters
/// - `dek`        — the log sub-key for this DEK epoch.
/// - `plaintext`  — serialised `StoreCommand` bytes to encrypt.
/// - `term`       — Raft term (part of Associated Data).
/// - `index`      — Raft log index (part of Associated Data).
/// - `nonce`      — 12-byte nonce: `[8-byte NodeId BE] ++ [4-byte counter BE]`.
///
/// # Returns
/// `[nonce 12B] ++ [ciphertext] ++ [tag 16B]`.
pub fn log_encrypt(
    dek: &LogDek,
    plaintext: &[u8],
    term: u64,
    index: u64,
    nonce: &[u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key_ref(dek.0.as_bytes())?);
    let aad = log_aad(term, index);
    let gcm_nonce = nonce_ref(nonce)?;

    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(gcm_nonce, &aad, buf.as_mut_slice().into())
        .map_err(|_| CryptoError::AesEncrypt)?;

    let mut out = Vec::with_capacity(12 + plaintext.len() + 16);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt a Raft log `app_data` payload previously encrypted with
/// [`log_encrypt`].
///
/// Returns the plaintext in a zeroing wrapper.  Returns
/// [`CryptoError::AesDecrypt`] if the GCM tag does not verify.
pub fn log_decrypt(
    dek: &LogDek,
    stored: &[u8],
    term: u64,
    index: u64,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if stored.len() < LOG_MIN_LEN {
        return Err(CryptoError::CiphertextTooShort);
    }
    let (nonce_bytes, rest) = stored.split_at(12);
    let (ciphertext, tag_bytes) = rest.split_at(rest.len() - 16);
    let gcm_nonce = nonce_ref(nonce_bytes)?;
    let tag = tag_ref(tag_bytes)?;
    let aad = log_aad(term, index);
    let cipher = Aes256Gcm::new(key_ref(dek.0.as_bytes())?);

    let mut buf = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_inout_detached(gcm_nonce, &aad, buf.as_mut_slice().into(), tag)
        .map_err(|_| CryptoError::AesDecrypt)?;
    Ok(buf)
}

/// Encrypt a Fjall state machine record.
///
/// # Parameters
/// - `dek`        — the state sub-key for this DEK epoch.
/// - `plaintext`  — serialised record bytes to encrypt.
/// - `tier`       — data sensitivity tier byte (0–3), bound into GCM AD.
/// - `domain_id`  — domain identifier bytes, bound into GCM AD.
/// - `pk`         — primary key bytes, used in AD and nonce derivation.
/// - `version`    — record version counter; must be incremented on each write.
///
/// # Returns
/// `[nonce 12B] ++ [ciphertext] ++ [tag 16B] ++ [version u32 BE]`.
pub fn state_encrypt(
    dek: &StateDek,
    plaintext: &[u8],
    tier: u8,
    domain_id: &[u8],
    pk: &[u8],
    version: u32,
) -> Result<Vec<u8>, CryptoError> {
    let nonce_array = state_nonce(dek, pk, version)?;
    let aad = state_aad(tier, domain_id, pk);
    let cipher = Aes256Gcm::new(key_ref(dek.0.as_bytes())?);
    let gcm_nonce = nonce_ref(&nonce_array)?;

    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(gcm_nonce, &aad, buf.as_mut_slice().into())
        .map_err(|_| CryptoError::AesEncrypt)?;

    let mut out = Vec::with_capacity(12 + plaintext.len() + 16 + 4);
    out.extend_from_slice(&nonce_array);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&version.to_be_bytes());
    Ok(out)
}

/// Decrypt a Fjall state entry previously encrypted with [`state_encrypt`].
///
/// # Returns
/// `(plaintext, next_version)` where `next_version = stored_version + 1`.
/// Returns [`CryptoError::AesDecrypt`] if the GCM tag does not verify —
/// callers MUST treat this as a quarantine-triggering event.
pub fn state_decrypt(
    dek: &StateDek,
    stored: &[u8],
    tier: u8,
    domain_id: &[u8],
    pk: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, u32), CryptoError> {
    if stored.len() < STATE_MIN_LEN {
        return Err(CryptoError::CiphertextTooShort);
    }
    // Layout: [nonce 12B][ciphertext][tag 16B][version 4B]
    let (nonce_bytes, rest) = stored.split_at(12);
    let version_bytes: [u8; 4] = rest[rest.len() - 4..]
        .try_into()
        .map_err(|_| CryptoError::CiphertextTooShort)?;
    let stored_version = u32::from_be_bytes(version_bytes);
    let middle = &rest[..rest.len() - 4]; // ciphertext ++ tag
    if middle.len() < 16 {
        return Err(CryptoError::CiphertextTooShort);
    }
    let (ciphertext, tag_bytes) = middle.split_at(middle.len() - 16);

    // Re-derive the nonce from the stored version to validate.
    let expected_nonce = state_nonce(dek, pk, stored_version)?;
    if nonce_bytes != expected_nonce.as_ref() {
        // Nonce mismatch indicates tampering or key/version confusion.
        return Err(CryptoError::AesDecrypt);
    }

    let gcm_nonce = nonce_ref(nonce_bytes)?;
    let tag = tag_ref(tag_bytes)?;
    let aad = state_aad(tier, domain_id, pk);
    let cipher = Aes256Gcm::new(key_ref(dek.0.as_bytes())?);

    let mut buf = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_inout_detached(gcm_nonce, &aad, buf.as_mut_slice().into(), tag)
        .map_err(|_| CryptoError::AesDecrypt)?;

    let next_version = stored_version.saturating_add(1);
    Ok((buf, next_version))
}

// ---------------------------------------------------------------------------
// Snapshot backup encryption
// ---------------------------------------------------------------------------

/// Encrypt a Raft snapshot with the epoch's `BackupDek`.
///
/// Nonce is derived deterministically via
/// HKDF-Expand(BackupDek, BACKUP_AD_LABEL ++ utc_epoch_u64_BE ++
/// counter_u64_BE, L=12) so that no random material is required (ADR Invariant
/// 10 — deterministic nonces only). The `counter` ensures uniqueness when
/// multiple snapshots are taken under the same DEK epoch in the same second.
/// AD = `b"keystone-backup-v1" ++ utc_epoch_u64_BE ++ dek_version_u32_BE ++
/// counter_u64_BE`.
///
/// # Returns
/// `[nonce 12B] ++ [ciphertext] ++ [tag 16B]`.
#[allow(clippy::disallowed_methods)]
pub fn backup_encrypt(
    dek: &BackupDek,
    plaintext: &[u8],
    dek_version: u32,
    utc_epoch: u64,
    counter: u64,
) -> Result<Vec<u8>, CryptoError> {
    let nonce_bytes = backup_nonce(dek, utc_epoch, counter)?;
    let aad = backup_aad(dek_version, utc_epoch, counter);
    let cipher = Aes256Gcm::new(key_ref(dek.as_bytes())?);
    let gcm_nonce = nonce_ref(&nonce_bytes)?;

    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(gcm_nonce, &aad, buf.as_mut_slice().into())
        .map_err(|_| CryptoError::AesEncrypt)?;

    let mut out = Vec::with_capacity(12 + plaintext.len() + 16);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt a snapshot previously encrypted with [`backup_encrypt`].
///
/// `dek_version`, `utc_epoch`, and `counter` must match the values used at
/// encrypt time; any mismatch causes GCM tag verification to fail.
/// The stored nonce is re-derived from (`dek`, `utc_epoch`, `counter`) and
/// verified against the stored bytes to detect accidental epoch/timestamp
/// confusion.
pub fn backup_decrypt(
    dek: &BackupDek,
    stored: &[u8],
    dek_version: u32,
    utc_epoch: u64,
    counter: u64,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    const BACKUP_MIN_LEN: usize = 12 + 16;
    if stored.len() < BACKUP_MIN_LEN {
        return Err(CryptoError::CiphertextTooShort);
    }
    let (nonce_bytes, rest) = stored.split_at(12);

    // Verify nonce matches the deterministic derivation.
    let expected_nonce = backup_nonce(dek, utc_epoch, counter)?;
    if nonce_bytes != expected_nonce {
        return Err(CryptoError::AesDecrypt);
    }

    let (ciphertext, tag_bytes) = rest.split_at(rest.len() - 16);
    let aad = backup_aad(dek_version, utc_epoch, counter);
    let cipher = Aes256Gcm::new(key_ref(dek.as_bytes())?);
    let gcm_nonce = nonce_ref(nonce_bytes)?;
    let tag = tag_ref(tag_bytes)?;

    let mut buf = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_inout_detached(gcm_nonce, &aad, buf.as_mut_slice().into(), tag)
        .map_err(|_| CryptoError::AesDecrypt)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn log_aad(term: u64, index: u64) -> [u8; 16] {
    let mut aad = [0u8; 16];
    aad[..8].copy_from_slice(&term.to_be_bytes());
    aad[8..].copy_from_slice(&index.to_be_bytes());
    aad
}

/// Derive a 12-byte state nonce via HKDF-Expand.
///
/// `info = pk ++ version_u32_be` as per ADR §2.2.
fn state_nonce(dek: &StateDek, pk: &[u8], version: u32) -> Result<[u8; 12], CryptoError> {
    let hkdf =
        Hkdf::<Sha256>::from_prk(dek.0.as_bytes()).map_err(|_| CryptoError::InvalidKeyLength)?;

    let mut info = Vec::with_capacity(pk.len() + 4);
    info.extend_from_slice(pk);
    info.extend_from_slice(&version.to_be_bytes());

    let mut nonce = [0u8; 12];
    hkdf.expand(&info, &mut nonce)
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    Ok(nonce)
}

fn state_aad(tier: u8, domain_id: &[u8], pk: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + domain_id.len() + pk.len());
    aad.push(tier);
    aad.extend_from_slice(domain_id);
    aad.extend_from_slice(pk);
    aad
}

fn backup_aad(dek_version: u32, utc_epoch: u64, counter: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(BACKUP_AD_LABEL.len() + 8 + 4 + 8);
    aad.extend_from_slice(BACKUP_AD_LABEL);
    aad.extend_from_slice(&utc_epoch.to_be_bytes());
    aad.extend_from_slice(&dek_version.to_be_bytes());
    aad.extend_from_slice(&counter.to_be_bytes());
    aad
}

/// Derive a deterministic 12-byte nonce for snapshot encryption (ADR Invariant
/// 10).
///
/// `info = BACKUP_AD_LABEL ++ utc_epoch_u64_be ++ counter_u64_be`.
/// The `counter` parameter ensures uniqueness even when multiple snapshots are
/// taken within the same second under the same DEK epoch (H4 fix).
fn backup_nonce(dek: &BackupDek, utc_epoch: u64, counter: u64) -> Result<[u8; 12], CryptoError> {
    let hkdf =
        Hkdf::<Sha256>::from_prk(dek.as_bytes()).map_err(|_| CryptoError::InvalidKeyLength)?;
    let mut info = Vec::with_capacity(BACKUP_AD_LABEL.len() + 8 + 8);
    info.extend_from_slice(BACKUP_AD_LABEL);
    info.extend_from_slice(&utc_epoch.to_be_bytes());
    info.extend_from_slice(&counter.to_be_bytes());
    let mut nonce = [0u8; 12];
    hkdf.expand(&info, &mut nonce)
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dek::{LogDek, StateDek};
    use crate::mlock::LockedKey;

    fn test_log_dek() -> LogDek {
        LogDek(LockedKey::from_raw([0x11u8; 32]))
    }

    fn test_state_dek() -> StateDek {
        StateDek(LockedKey::from_raw([0x22u8; 32]))
    }

    fn test_nonce() -> [u8; 12] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // node_id
            0x00, 0x00, 0x00, 0x01,
        ] // counter
    }

    #[test]
    fn test_log_roundtrip() {
        let dek = test_log_dek();
        let plaintext = b"hello log world";
        let term = 3u64;
        let index = 42u64;
        let nonce = test_nonce();

        let enc = log_encrypt(&dek, plaintext, term, index, &nonce).expect("encrypt");
        assert_eq!(enc.len(), 12 + plaintext.len() + 16);

        let dec = log_decrypt(&dek, &enc, term, index).expect("decrypt");
        assert_eq!(dec.as_slice(), plaintext);
    }

    #[test]
    fn test_log_wrong_term_rejected() {
        let dek = test_log_dek();
        let plaintext = b"test";
        let enc = log_encrypt(&dek, plaintext, 1, 1, &test_nonce()).expect("encrypt");
        assert!(matches!(
            log_decrypt(&dek, &enc, 2, 1),
            Err(CryptoError::AesDecrypt)
        ));
    }

    #[test]
    fn test_log_wrong_index_rejected() {
        let dek = test_log_dek();
        let plaintext = b"test";
        let enc = log_encrypt(&dek, plaintext, 1, 1, &test_nonce()).expect("encrypt");
        assert!(matches!(
            log_decrypt(&dek, &enc, 1, 2),
            Err(CryptoError::AesDecrypt)
        ));
    }

    #[test]
    fn test_state_roundtrip() {
        let dek = test_state_dek();
        let plaintext = b"user data";
        let tier = 2u8;
        let domain = b"domain-uuid";
        let pk = b"user-uuid";
        let version = 0u32;

        let enc = state_encrypt(&dek, plaintext, tier, domain, pk, version).expect("encrypt");
        // 12 (nonce) + len(plaintext) + 16 (tag) + 4 (version)
        assert_eq!(enc.len(), 12 + plaintext.len() + 16 + 4);

        let (dec, next_v) = state_decrypt(&dek, &enc, tier, domain, pk).expect("decrypt");
        assert_eq!(dec.as_slice(), plaintext);
        assert_eq!(next_v, 1);
    }

    #[test]
    fn test_state_wrong_tier_rejected() {
        let dek = test_state_dek();
        let plaintext = b"sensitive";
        let domain = b"dom";
        let pk = b"key";
        let enc = state_encrypt(&dek, plaintext, 2, domain, pk, 0).expect("encrypt");
        assert!(matches!(
            state_decrypt(&dek, &enc, 1, domain, pk),
            Err(CryptoError::AesDecrypt)
        ));
    }

    #[test]
    fn test_state_different_versions_different_nonces() {
        let dek = test_state_dek();
        let pk = b"pk";
        let n0 = state_nonce(&dek, pk, 0).expect("nonce 0");
        let n1 = state_nonce(&dek, pk, 1).expect("nonce 1");
        assert_ne!(n0, n1);
    }

    #[test]
    fn test_log_too_short() {
        let dek = test_log_dek();
        assert!(matches!(
            log_decrypt(&dek, &[0u8; 10], 0, 0),
            Err(CryptoError::CiphertextTooShort)
        ));
    }

    #[test]
    fn test_state_too_short() {
        let dek = test_state_dek();
        assert!(matches!(
            state_decrypt(&dek, &[0u8; 10], 0, b"", b""),
            Err(CryptoError::CiphertextTooShort)
        ));
    }

    fn test_backup_dek() -> crate::dek::BackupDek {
        crate::dek::BackupDek::from_raw([0x33u8; 32])
    }

    #[test]
    fn test_backup_roundtrip() {
        let dek = test_backup_dek();
        let plaintext = b"snapshot data";
        let dek_version = 1u32;
        let utc_epoch = 1_700_000_000u64;

        let enc = backup_encrypt(&dek, plaintext, dek_version, utc_epoch, 0).expect("encrypt");
        assert_eq!(enc.len(), 12 + plaintext.len() + 16);

        let dec = backup_decrypt(&dek, &enc, dek_version, utc_epoch, 0).expect("decrypt");
        assert_eq!(dec.as_slice(), plaintext);
    }

    #[test]
    fn test_backup_nonce_is_deterministic() {
        let dek = test_backup_dek();
        let utc_epoch = 1_700_000_000u64;
        let n1 = backup_nonce(&dek, utc_epoch, 0).expect("nonce 1");
        let n2 = backup_nonce(&dek, utc_epoch, 0).expect("nonce 2");
        assert_eq!(n1, n2, "nonce must be deterministic for same inputs");
    }

    #[test]
    fn test_backup_different_epoch_different_nonce() {
        let dek = test_backup_dek();
        let n1 = backup_nonce(&dek, 1_000u64, 0).expect("nonce 1");
        let n2 = backup_nonce(&dek, 1_001u64, 0).expect("nonce 2");
        assert_ne!(n1, n2, "different utc_epoch must produce different nonces");
    }

    #[test]
    fn test_backup_wrong_epoch_rejected() {
        let dek = test_backup_dek();
        let enc = backup_encrypt(&dek, b"data", 1, 1_000u64, 0).expect("encrypt");
        assert!(
            matches!(
                backup_decrypt(&dek, &enc, 1, 1_001u64, 0),
                Err(CryptoError::AesDecrypt)
            ),
            "mismatched utc_epoch must fail decryption"
        );
    }

    #[test]
    fn test_backup_wrong_dek_version_rejected() {
        let dek = test_backup_dek();
        let enc = backup_encrypt(&dek, b"data", 1, 1_000u64, 0).expect("encrypt");
        assert!(
            matches!(
                backup_decrypt(&dek, &enc, 2, 1_000u64, 0),
                Err(CryptoError::AesDecrypt)
            ),
            "mismatched dek_version must fail decryption"
        );
    }
}
