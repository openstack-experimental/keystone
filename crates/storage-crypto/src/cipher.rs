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

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::dek::{LogDek, StateDek};
use crate::error::CryptoError;

// Minimum bytes in a stored state value: nonce(12) + tag(16) + version(4) = 32
const STATE_MIN_LEN: usize = 32;
// Minimum bytes in a stored log value: nonce(12) + tag(16) = 28
const LOG_MIN_LEN: usize = 28;

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
/// `[nonce 12B] ++ [ciphertext] ++ [tag 16B]`
pub fn log_encrypt(
    dek: &LogDek,
    plaintext: &[u8],
    term: u64,
    index: u64,
    nonce: &[u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(dek.0.as_ref()));
    let aad = log_aad(term, index);
    let gcm_nonce = GenericArray::from_slice(nonce.as_ref());

    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(gcm_nonce, &aad, &mut buf)
        .map_err(|_| CryptoError::AesEncrypt)?;

    let mut out = Vec::with_capacity(12 + plaintext.len() + 16);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&buf);
    out.extend_from_slice(tag.as_slice());
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
    let gcm_nonce = GenericArray::from_slice(nonce_bytes);
    let tag = GenericArray::from_slice(tag_bytes);
    let aad = log_aad(term, index);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(dek.0.as_ref()));

    let mut buf = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_in_place_detached(gcm_nonce, &aad, buf.as_mut(), tag)
        .map_err(|_| CryptoError::AesDecrypt)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// State encryption
// ---------------------------------------------------------------------------

/// Encrypt a Fjall state entry for a given record version.
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
/// `[nonce 12B] ++ [ciphertext] ++ [tag 16B] ++ [version u32 BE]`
pub fn state_encrypt(
    dek: &StateDek,
    plaintext: &[u8],
    tier: u8,
    domain_id: &[u8],
    pk: &[u8],
    version: u32,
) -> Result<Vec<u8>, CryptoError> {
    let nonce_bytes = state_nonce(dek, pk, version)?;
    let aad = state_aad(tier, domain_id, pk);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(dek.0.as_ref()));
    let gcm_nonce = GenericArray::from_slice(nonce_bytes.as_ref());

    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(gcm_nonce, &aad, &mut buf)
        .map_err(|_| CryptoError::AesEncrypt)?;

    let mut out = Vec::with_capacity(12 + plaintext.len() + 16 + 4);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    out.extend_from_slice(tag.as_slice());
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

    let gcm_nonce = GenericArray::from_slice(nonce_bytes);
    let tag = GenericArray::from_slice(tag_bytes);
    let aad = state_aad(tier, domain_id, pk);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(dek.0.as_ref()));

    let mut buf = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_in_place_detached(gcm_nonce, &aad, buf.as_mut(), tag)
        .map_err(|_| CryptoError::AesDecrypt)?;

    let next_version = stored_version.checked_add(1).unwrap_or(u32::MAX);
    Ok((buf, next_version))
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
        Hkdf::<Sha256>::from_prk(dek.0.as_ref()).map_err(|_| CryptoError::InvalidKeyLength)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dek::{LogDek, StateDek};
    use zeroize::Zeroizing;

    fn test_log_dek() -> LogDek {
        LogDek(Zeroizing::new([0x11u8; 32]))
    }

    fn test_state_dek() -> StateDek {
        StateDek(Zeroizing::new([0x22u8; 32]))
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
}
