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
//! # Key Encryption Key (KEK) providers
//!
//! A `KekProvider` wraps and unwraps the Data Encryption Key (DEK) using an
//! external key source. This crate provides [`EnvKek`], a dev-mode-only
//! implementation that reads a hex-encoded 256-bit key from the
//! `KEYSTONE_DEV_KEK` environment variable — requires `--dev-mode` and
//! `KEYSTONE_ALLOW_ENV_KEK=1`. After reading, the variable is removed from
//! the Rust environment map (via `unsafe env::remove_var`). Zeroing the
//! underlying bytes in `/proc/<pid>/environ` was attempted but is currently a
//! no-op (see [`zero_environ_entry`]) — the raw `environ` bytes are not
//! scrubbed, so this is a best-effort dev-mode control, not a guarantee.
//!
//! Production KEK sources — PKCS#11 and TPM 2.0 — live in the separate
//! `storage-crypto-pkcs11` and `storage-crypto-tpm` crates (ADR 0016-v2
//! §2.5), each implementing the same [`KekProvider`] trait defined here.

use std::env;

use zeroize::{Zeroize, Zeroizing};

use crate::backend::{gcm_open, gcm_seal, hkdf_expand, hmac_sha256};
use crate::error::CryptoError;

/// Associated data used for DEK wrapping to bind context.
const DEK_WRAP_AD: &[u8] = b"keystone-dek-wrap-v1";

/// HKDF info for the sub-key used to derive wrap nonces.
const DEK_WRAP_NONCE_INFO: &[u8] = b"keystone-dek-wrap-nonce-v1";

/// Object-safe trait for Key Encryption Key operations.
pub trait KekProvider: Send + Sync {
    /// Unwrap (decrypt) a wrapped DEK blob produced by [`wrap_dek`].
    fn unwrap_dek(&self, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError>;

    /// Wrap (encrypt) a 256-bit DEK.
    ///
    /// Returns an opaque blob: `[12-byte nonce][ciphertext][16-byte GCM tag]`.
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<Vec<u8>, CryptoError>;
}

// ---------------------------------------------------------------------------
// EnvKek
// ---------------------------------------------------------------------------

/// Development-mode KEK that reads its key bytes from `KEYSTONE_DEV_KEK`.
///
/// The process must have been started with `--dev-mode` and
/// `KEYSTONE_ALLOW_ENV_KEK=1` set; the caller is responsible for checking
/// those flags before constructing this type.
///
/// `KEYSTONE_DEV_KEK` is removed from the Rust environment immediately after
/// reading (ADR 0016-v2 §2.1).  The raw bytes backing that entry in
/// `/proc/<pid>/environ` are NOT currently scrubbed — see
/// [`zero_environ_entry`] — so a process with `/proc` read access could still
/// recover the key from the original environment block until process exit.
pub struct EnvKek {
    key: Zeroizing<[u8; 32]>,
}

impl EnvKek {
    /// Construct from the `KEYSTONE_DEV_KEK` environment variable.
    ///
    /// Reads the hex-encoded 256-bit key, removes the variable, and zeroes
    /// the intermediate hex string.
    /// Construct directly from raw key bytes (for tests and bootstrapping).
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }

    // # Why `#[allow(unsafe_code)]`
    //
    // `std::env::remove_var` is `unsafe` in Rust 2024 (TOCTOU: concurrent
    // threads reading the environment while we mutate it can cause UB in some
    // C library implementations).  Here the call is safe because:
    //
    // 1. `from_env` is called exactly once during storage initialisation,
    //    before any async tasks that might inspect the environment are spawned.
    // 2. No other thread is spawned before `init_storage` reaches this point,
    //    so there is no concurrent reader of `KEYSTONE_DEV_KEK`.
    // 3. Removing the variable immediately after reading minimises (but, per
    //    `zero_environ_entry`, does not eliminate) the window in which
    //    `/proc/<pid>/environ` exposes the key (ADR 0016-v2 §2.1).
    //
    // The workspace sets `unsafe_code = "forbid"` but `storage-crypto` relaxes
    // this to `unsafe_code = "deny"` specifically to permit the mlock
    // primitives in `mlock.rs`.  This function is the only other site that
    // requires `unsafe` in this crate.
    #[allow(unsafe_code)]
    pub fn from_env() -> Result<Self, CryptoError> {
        let mut hex_val = env::var("KEYSTONE_DEV_KEK").map_err(|_| CryptoError::KekMissing)?;
        let mut raw = Zeroizing::new(decode_hex(&hex_val).map_err(|_| CryptoError::InvalidHex)?);
        hex_val.zeroize();

        // SAFETY: see comment above. No concurrent env readers exist at this
        // call site.
        unsafe {
            env::remove_var("KEYSTONE_DEV_KEK");
            #[cfg(target_os = "linux")]
            zero_environ_entry();
        }

        if raw.len() != 32 {
            raw.zeroize();
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&raw);
        Ok(Self { key })
    }
}

impl KekProvider for EnvKek {
    fn unwrap_dek(&self, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        // Layout: [12-byte nonce][32-byte ciphertext][16-byte tag]
        if wrapped.len() != 12 + 32 + 16 {
            return Err(CryptoError::WrappedDekSize);
        }
        // Both slices below are exactly 12/16 bytes given the length check
        // above (60 = 12 + 32 + 16), so the conversions cannot fail, but
        // errors are propagated rather than unwrapped in case that
        // invariant is ever violated by a future edit.
        let nonce_arr: [u8; 12] = wrapped[..12]
            .try_into()
            .map_err(|_| CryptoError::WrappedDekSize)?;
        let tag_arr: [u8; 16] = wrapped[44..]
            .try_into()
            .map_err(|_| CryptoError::WrappedDekSize)?;
        let mut buf = wrapped[12..44].to_vec();
        gcm_open(
            &*self.key,
            &nonce_arr,
            DEK_WRAP_AD,
            buf.as_mut_slice(),
            &tag_arr,
        )?;

        if buf.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&buf);
        Ok(out)
    }

    /// The nonce is deterministic: no random material is involved (ADR
    /// invariant 10, and no RNG dependency on the FIPS path). It is the
    /// truncated HMAC-SHA256 of the DEK under a nonce sub-key derived from the
    /// KEK, so it is unique per distinct DEK short of a 96-bit collision.
    /// Wrapping the same DEK twice yields identical output, which reveals
    /// nothing beyond equality.
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        let mut nonce_key = Zeroizing::new([0u8; 32]);
        hkdf_expand(&*self.key, DEK_WRAP_NONCE_INFO, nonce_key.as_mut())?;
        let mac = hmac_sha256(nonce_key.as_ref(), dek)?;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&mac[..12]);

        let mut buf = dek.to_vec();
        let tag = gcm_seal(&*self.key, &nonce_bytes, DEK_WRAP_AD, buf.as_mut_slice())?;

        let mut out = Vec::with_capacity(12 + 32 + 16);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&buf);
        out.extend_from_slice(&tag);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn decode_hex(s: &str) -> Result<Vec<u8>, CryptoError> {
    if !s.len().is_multiple_of(2) {
        return Err(CryptoError::InvalidHex);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| CryptoError::InvalidHex))
        .collect()
}

/// No-op placeholder for zeroing the value portion of the `KEYSTONE_DEV_KEK`
/// entry in the raw `environ` block on Linux.
///
/// On Linux the initial environment is a contiguous array of null-terminated
/// strings placed on the stack by the kernel.  `libc::unsetenv` (called by
/// [`std::env::remove_var`]) removes the entry from the internal lookup but
/// does not zero the bytes of the original string in this block, so
/// `/proc/<pid>/environ` still exposes the raw key bytes to any process with
/// `/proc` read access for the remainder of this process's lifetime.
///
/// This function does **not** currently mitigate that: an earlier
/// implementation iterated the libc `environ` array via raw pointers and
/// wrote zeros over the value in place, but that approach was unreliable
/// (misaligned pointers, corrupted `environ` arrays after
/// `std::env::remove_var`, and segfaults in test harnesses) and was reverted.
/// The primary protections — `env::remove_var` and copying the key into a
/// `Zeroizing` buffer rather than holding onto the hex string — still prevent
/// the key from leaking through normal Rust-level paths; only the raw
/// `/proc/<pid>/environ` exposure is unaddressed. Reinstating a safe
/// zeroing implementation is tracked as follow-up work.
#[cfg(target_os = "linux")]
fn zero_environ_entry() {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kek() -> EnvKek {
        EnvKek {
            key: Zeroizing::new([0x42u8; 32]),
        }
    }

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let kek = test_kek();
        let dek = [0xABu8; 32];
        let wrapped = kek.wrap_dek(&dek).expect("wrap");
        assert_eq!(wrapped.len(), 60); // 12 + 32 + 16
        let unwrapped = kek.unwrap_dek(&wrapped).expect("unwrap");
        assert_eq!(unwrapped.as_ref(), &dek);
    }

    #[test]
    fn test_wrap_nonce_is_deterministic_and_dek_specific() {
        let kek = test_kek();
        let w1 = kek.wrap_dek(&[0xCDu8; 32]).expect("wrap 1");
        let w2 = kek.wrap_dek(&[0xCDu8; 32]).expect("wrap 2");
        let w3 = kek.wrap_dek(&[0xCEu8; 32]).expect("wrap 3");
        // Same DEK: identical blob (no RNG involved).
        assert_eq!(w1, w2);
        // Different DEK: different nonce.
        assert_ne!(w1[..12], w3[..12]);
    }

    #[test]
    fn test_unwrap_blob_with_foreign_nonce() {
        // Blobs wrapped before the nonce became deterministic (random 96-bit
        // nonce) must still unwrap: the nonce is read from the blob.
        let kek = test_kek();
        let dek = [0x5Au8; 32];
        let nonce = [0x11u8; 12];
        let mut buf = dek.to_vec();
        let tag = gcm_seal(&*kek.key, &nonce, DEK_WRAP_AD, &mut buf).expect("seal");
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&buf);
        blob.extend_from_slice(&tag);
        let out = kek.unwrap_dek(&blob).expect("unwrap legacy blob");
        assert_eq!(*out, dek);
    }

    #[test]
    fn test_unwrap_wrong_tag_fails() {
        let kek = test_kek();
        let dek = [0x11u8; 32];
        let mut wrapped = kek.wrap_dek(&dek).expect("wrap");
        // Corrupt the tag
        *wrapped.last_mut().expect("non-empty") ^= 0xFF;
        assert!(matches!(
            kek.unwrap_dek(&wrapped),
            Err(CryptoError::AesDecrypt)
        ));
    }

    #[test]
    fn test_decode_hex_valid() {
        let bytes = decode_hex("deadbeef").expect("decode");
        assert_eq!(bytes, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_decode_hex_odd_length() {
        assert!(decode_hex("abc").is_err());
    }

    // `EnvKek::from_env` reads and removes a process-global environment
    // variable, so tests that touch it must be serialized against each other
    // to avoid racing on shared state.
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[allow(unsafe_code)]
    fn with_env_kek<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        match value {
            Some(v) => unsafe { env::set_var("KEYSTONE_DEV_KEK", v) },
            None => unsafe { env::remove_var("KEYSTONE_DEV_KEK") },
        }
        let result = f();
        unsafe { env::remove_var("KEYSTONE_DEV_KEK") };
        result
    }

    #[test]
    fn test_from_env_success() {
        with_env_kek(Some(&"ab".repeat(32)), || {
            let kek = EnvKek::from_env().expect("from_env");
            assert_eq!(kek.key.as_ref(), &[0xabu8; 32]);
            // The variable must be removed after reading.
            assert!(env::var("KEYSTONE_DEV_KEK").is_err());
        });
    }

    #[test]
    fn test_from_env_missing_var() {
        with_env_kek(None, || {
            assert!(matches!(EnvKek::from_env(), Err(CryptoError::KekMissing)));
        });
    }

    #[test]
    fn test_from_env_invalid_hex() {
        with_env_kek(Some("not-hex!!"), || {
            assert!(matches!(EnvKek::from_env(), Err(CryptoError::InvalidHex)));
        });
    }

    #[test]
    fn test_from_env_wrong_length() {
        with_env_kek(Some(&"ab".repeat(16)), || {
            assert!(matches!(
                EnvKek::from_env(),
                Err(CryptoError::InvalidKeyLength)
            ));
        });
    }
}
