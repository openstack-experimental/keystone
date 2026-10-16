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
// Crypto inventory: STO-1, STO-3; see doc/src/contributor/crypto-inventory.md
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

use zeroize::Zeroizing;

use crate::backend::{FIPS_BUILD, gcm_open, gcm_seal_iv, hkdf_expand, hkdf_extract_expand};
use crate::dek::{BackupDek, LogDek, StateDek};
use crate::error::CryptoError;

// Label for snapshot backup AD (ADR §7).
const BACKUP_AD_LABEL: &[u8] = b"keystone-backup-v1";

// Minimum bytes in a stored state value: nonce(12) + tag(16) + version(4) = 32
const STATE_MIN_LEN: usize = 32;
// Minimum bytes in a stored log value: nonce(12) + tag(16) = 28
const LOG_MIN_LEN: usize = 28;

/// Convert a slice to a fixed-size array, mapping a length mismatch to
/// [`CryptoError::InvalidArrayLength`].
fn array_ref<const N: usize>(s: &[u8]) -> Result<[u8; N], CryptoError> {
    s.try_into().map_err(|_| CryptoError::InvalidArrayLength)
}

// ---------------------------------------------------------------------------
// Per-message keys (fips builds)
// ---------------------------------------------------------------------------

/// HKDF salt of the per-message keys used in `fips` builds. The derivation is
/// full HKDF (Extract-then-Expand) with a non-empty salt and info, the flow
/// the validated module documents as an approved service, unlike the
/// Expand-only derivation of the sub-keys themselves.
const MESSAGE_KEY_SALT: &[u8] = b"keystone-gcm-message-key-v1";

/// Key a single log entry or state record is encrypted under in a `fips`
/// build: `HKDF(salt = MESSAGE_KEY_SALT, ikm = base, info = context)`.
///
/// The validated module picks random IVs, which are only safe for fewer than
/// 2^32 encryptions under one key (SP 800-38D §8.3). Log entries and state
/// records are encrypted at a rate that would exhaust that limit within days
/// once many nodes (for example a fleet of learners) encrypt under the same
/// DEK. Deriving the key from the message identity (`term`/`index`, or
/// keyspace/key/`version`) means a key only ever encrypts the same
/// message, which every node applies once, so the limit is never approached
/// and no usage counter or cluster-size accounting is needed.
fn message_key(base: &[u8; 32], context: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf_extract_expand(MESSAGE_KEY_SALT, base, context, key.as_mut())?;
    Ok(key)
}

/// Encrypt `buf` in place for the message identified by `context`.
///
/// With the `fips` feature the module-chosen IV is used under the per-message
/// key; otherwise `nonce` is used under `base` itself.
fn seal_message(
    base: &[u8; 32],
    context: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<([u8; 12], [u8; 16]), CryptoError> {
    if FIPS_BUILD {
        gcm_seal_iv(message_key(base, context)?.as_ref(), nonce, aad, buf)
    } else {
        gcm_seal_iv(base, nonce, aad, buf)
    }
}

/// Decrypt the message identified by `context`.
///
/// A `fips` build tries the per-message key first and then `base` itself, so
/// records written by a default build keep decrypting. The flag is `true`
/// when `base` was used, i.e. the record has the default-build layout and the
/// caller must still apply that layout's own checks (derived-nonce
/// validation).
fn open_message(
    base: &[u8; 32],
    context: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<(Zeroizing<Vec<u8>>, bool), CryptoError> {
    if FIPS_BUILD {
        let key = message_key(base, context)?;
        let mut buf = Zeroizing::new(ciphertext.to_vec());
        if gcm_open(key.as_ref(), nonce, aad, &mut buf, tag).is_ok() {
            return Ok((buf, false));
        }
    }
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    gcm_open(base, nonce, aad, &mut buf, tag)?;
    Ok((buf, true))
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
    let aad = log_aad(term, index);

    let mut buf = plaintext.to_vec();
    let (iv, tag) = seal_message(
        dek.0.as_bytes(),
        &log_context(term, index),
        nonce,
        &aad,
        &mut buf,
    )?;

    let mut out = Vec::with_capacity(12 + plaintext.len() + 16);
    out.extend_from_slice(&iv);
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
    let gcm_nonce = array_ref::<12>(nonce_bytes)?;
    let tag = array_ref::<16>(tag_bytes)?;
    let aad = log_aad(term, index);

    let (buf, _) = open_message(
        dek.0.as_bytes(),
        &log_context(term, index),
        &gcm_nonce,
        &aad,
        ciphertext,
        &tag,
    )?;
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
    // With the `fips` feature the module picks the IV; the derived value is
    // then only a placeholder.
    let nonce_array = if FIPS_BUILD {
        [0u8; 12]
    } else {
        state_nonce(dek, pk, version)?
    };
    let aad = state_aad(tier, domain_id, pk);

    let mut buf = plaintext.to_vec();
    let (iv, tag) = seal_message(
        dek.0.as_bytes(),
        &state_context(domain_id, pk, version),
        &nonce_array,
        &aad,
        &mut buf,
    )?;

    let mut out = Vec::with_capacity(12 + plaintext.len() + 16 + 4);
    out.extend_from_slice(&iv);
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

    // The AAD does not contain the version; it is bound through the nonce.
    // Default-layout records (all records in a default build, legacy records
    // in a `fips` build) re-derive the nonce from the stored version to
    // validate it, see below. `fips` records are bound to the version by the
    // per-message key instead.
    let gcm_nonce = array_ref::<12>(nonce_bytes)?;
    let tag = array_ref::<16>(tag_bytes)?;
    let aad = state_aad(tier, domain_id, pk);

    let (buf, default_layout) = open_message(
        dek.0.as_bytes(),
        &state_context(domain_id, pk, stored_version),
        &gcm_nonce,
        &aad,
        ciphertext,
        &tag,
    )?;
    if default_layout {
        let expected_nonce = state_nonce(dek, pk, stored_version)?;
        if nonce_bytes != expected_nonce.as_ref() {
            // Nonce mismatch indicates tampering or key/version confusion.
            return Err(CryptoError::AesDecrypt);
        }
    }

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
    let nonce_bytes = if FIPS_BUILD {
        [0u8; 12]
    } else {
        backup_nonce(dek, utc_epoch, counter)?
    };
    let aad = backup_aad(dek_version, utc_epoch, counter);

    let mut buf = plaintext.to_vec();
    let (iv, tag) = gcm_seal_iv(dek.as_bytes(), &nonce_bytes, &aad, &mut buf)?;

    let mut out = Vec::with_capacity(12 + plaintext.len() + 16);
    out.extend_from_slice(&iv);
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

    // Verify nonce matches the deterministic derivation (not possible for
    // module-generated IVs in a `fips` build; the tag still authenticates).
    if !FIPS_BUILD {
        let expected_nonce = backup_nonce(dek, utc_epoch, counter)?;
        if nonce_bytes != expected_nonce {
            return Err(CryptoError::AesDecrypt);
        }
    }

    let (ciphertext, tag_bytes) = rest.split_at(rest.len() - 16);
    let aad = backup_aad(dek_version, utc_epoch, counter);
    let gcm_nonce = array_ref::<12>(nonce_bytes)?;
    let tag = array_ref::<16>(tag_bytes)?;

    let mut buf = Zeroizing::new(ciphertext.to_vec());
    gcm_open(dek.as_bytes(), &gcm_nonce, &aad, &mut buf, &tag)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Identity of a log entry for per-message key derivation.
fn log_context(term: u64, index: u64) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(3 + 16);
    ctx.extend_from_slice(b"log");
    ctx.extend_from_slice(&term.to_be_bytes());
    ctx.extend_from_slice(&index.to_be_bytes());
    ctx
}

/// Identity of a state record version for per-message key derivation. The
/// lengths keep `domain_id ++ pk` unambiguous.
fn state_context(domain_id: &[u8], pk: &[u8], version: u32) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(5 + 8 + domain_id.len() + pk.len() + 4);
    ctx.extend_from_slice(b"state");
    ctx.extend_from_slice(&(domain_id.len() as u64).to_be_bytes());
    ctx.extend_from_slice(domain_id);
    ctx.extend_from_slice(&(pk.len() as u64).to_be_bytes());
    ctx.extend_from_slice(pk);
    ctx.extend_from_slice(&version.to_be_bytes());
    ctx
}

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
    let mut info = Vec::with_capacity(pk.len() + 4);
    info.extend_from_slice(pk);
    info.extend_from_slice(&version.to_be_bytes());

    let mut nonce = [0u8; 12];
    hkdf_expand(dek.0.as_bytes(), &info, &mut nonce)?;
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
    let mut info = Vec::with_capacity(BACKUP_AD_LABEL.len() + 8 + 8);
    info.extend_from_slice(BACKUP_AD_LABEL);
    info.extend_from_slice(&utc_epoch.to_be_bytes());
    info.extend_from_slice(&counter.to_be_bytes());
    let mut nonce = [0u8; 12];
    hkdf_expand(dek.as_bytes(), &info, &mut nonce)?;
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

    /// `fips` builds ignore the supplied nonce and let the module pick a
    /// fresh IV for every encryption; the IV is stored so decryption works.
    #[cfg(feature = "fips")]
    #[test]
    fn test_fips_encrypt_uses_module_generated_iv() {
        let dek = test_log_dek();
        let hint = [0x42u8; 12];
        let a = log_encrypt(&dek, b"payload", 1, 2, &hint).expect("a");
        let b = log_encrypt(&dek, b"payload", 1, 2, &hint).expect("b");
        assert_ne!(a[..12], hint);
        assert_ne!(a[..12], b[..12]);
        assert_eq!(
            log_decrypt(&dek, &a, 1, 2).expect("dec a").as_slice(),
            b"payload"
        );
        assert_eq!(
            log_decrypt(&dek, &b, 1, 2).expect("dec b").as_slice(),
            b"payload"
        );

        let sdek = test_state_dek();
        let s1 = state_encrypt(&sdek, b"v", 0, b"dom", b"pk", 0).expect("s1");
        let s2 = state_encrypt(&sdek, b"v", 0, b"dom", b"pk", 0).expect("s2");
        assert_ne!(s1[..12], s2[..12]);
        let (pt, next) = state_decrypt(&sdek, &s1, 0, b"dom", b"pk").expect("dec s1");
        assert_eq!((pt.as_slice(), next), (b"v".as_slice(), 1));
    }

    /// Every message gets its own key in a `fips` build, so a record cannot
    /// be opened under the neighbouring (term, index) or version even by
    /// someone replaying the stored IV and tag.
    #[cfg(feature = "fips")]
    #[test]
    fn test_fips_messages_use_distinct_keys() {
        let dek = test_log_dek();
        let k1 = message_key(dek.0.as_bytes(), &log_context(1, 2)).expect("k1");
        let k2 = message_key(dek.0.as_bytes(), &log_context(1, 3)).expect("k2");
        assert_ne!(*k1, *k2);
        assert_ne!(*k1, *dek.0.as_bytes());
        let ctx_a = state_context(b"ab", b"c", 0);
        let ctx_b = state_context(b"a", b"bc", 0);
        assert_ne!(ctx_a, ctx_b);

        // A stored record does not open under a neighbouring identity.
        let entry = log_encrypt(&dek, b"payload", 1, 2, &[0u8; 12]).expect("enc");
        assert!(log_decrypt(&dek, &entry, 1, 3).is_err());
        assert!(log_decrypt(&dek, &entry, 2, 2).is_err());
        let sdek = test_state_dek();
        let rec = state_encrypt(&sdek, b"v", 0, b"dom", b"pk", 4).expect("enc");
        let mut moved = rec.clone();
        let n = moved.len();
        moved[n - 4..].copy_from_slice(&5u32.to_be_bytes());
        assert!(state_decrypt(&sdek, &moved, 0, b"dom", b"pk").is_err());
    }

    /// A legacy record read by a `fips` node keeps its version binding: the
    /// unauthenticated trailing version cannot be rewritten.
    #[cfg(feature = "fips")]
    #[test]
    fn test_fips_legacy_state_record_version_is_bound() {
        let sdek = test_state_dek();
        let nonce = state_nonce(&sdek, b"pk", 3).expect("nonce");
        let aad = state_aad(0, b"dom", b"pk");
        let mut buf = b"legacy".to_vec();
        let tag =
            crate::backend::gcm_seal(sdek.0.as_bytes(), &nonce, &aad, &mut buf).expect("seal");
        let mut stored = nonce.to_vec();
        stored.extend_from_slice(&buf);
        stored.extend_from_slice(&tag);
        stored.extend_from_slice(&9u32.to_be_bytes());
        assert!(state_decrypt(&sdek, &stored, 0, b"dom", b"pk").is_err());
    }

    /// Log entries written by a default build (nonce counter, shared key)
    /// keep decrypting under `fips`.
    #[cfg(feature = "fips")]
    #[test]
    fn test_fips_reads_default_build_log_entries() {
        let dek = test_log_dek();
        let aad = log_aad(5, 9);
        let nonce = [7u8; 12];
        let mut buf = b"old entry".to_vec();
        let tag = crate::backend::gcm_seal(dek.0.as_bytes(), &nonce, &aad, &mut buf).expect("seal");
        let mut stored = nonce.to_vec();
        stored.extend_from_slice(&buf);
        stored.extend_from_slice(&tag);
        let out = log_decrypt(&dek, &stored, 5, 9).expect("decrypt");
        assert_eq!(out.as_slice(), b"old entry");
    }

    /// Records written with HKDF-derived nonces by a default build keep
    /// decrypting under `fips`: the nonce is read from the record.
    #[cfg(feature = "fips")]
    #[test]
    fn test_fips_reads_derived_nonce_records() {
        let sdek = test_state_dek();
        let nonce = state_nonce(&sdek, b"pk", 3).expect("nonce");
        let aad = state_aad(0, b"dom", b"pk");
        let mut buf = b"legacy".to_vec();
        let tag =
            crate::backend::gcm_seal(sdek.0.as_bytes(), &nonce, &aad, &mut buf).expect("seal");
        let mut stored = nonce.to_vec();
        stored.extend_from_slice(&buf);
        stored.extend_from_slice(&tag);
        stored.extend_from_slice(&3u32.to_be_bytes());
        let (pt, next) = state_decrypt(&sdek, &stored, 0, b"dom", b"pk").expect("decrypt");
        assert_eq!((pt.as_slice(), next), (b"legacy".as_slice(), 4));
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
