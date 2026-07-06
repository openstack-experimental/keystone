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

use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes256Gcm, KeyInit};
use hybrid_array::Array;

use crate::gcm::{GcmKey, GcmNonce, GcmTag};

/// Convert a 12-byte slice reference to a typed GCM nonce array reference.
///
/// `Err(CryptoError::WrappedDekSize)` if `s` is not exactly 12 bytes — never
/// hit by the call sites in this file (the nonce is always a freshly
/// generated or length-checked `[u8; 12]`), but propagated rather than
/// panicked on so a future caller passing an unchecked slice fails cleanly.
fn nonce_ref(s: &[u8]) -> Result<&GcmNonce, CryptoError> {
    Array::slice_as_array(s).ok_or(CryptoError::WrappedDekSize)
}

/// Convert a 16-byte slice reference to a typed GCM tag array reference.
/// See [`nonce_ref`] for the error-propagation rationale.
fn tag_ref(s: &[u8]) -> Result<&GcmTag, CryptoError> {
    Array::slice_as_array(s).ok_or(CryptoError::WrappedDekSize)
}

/// Convert a 32-byte slice reference to a typed GCM key array reference.
/// See [`nonce_ref`] for the error-propagation rationale.
fn key_ref(s: &[u8]) -> Result<&GcmKey, CryptoError> {
    Array::slice_as_array(s).ok_or(CryptoError::InvalidKeyLength)
}
use rand::RngExt;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;

/// Associated data used for DEK wrapping to bind context.
const DEK_WRAP_AD: &[u8] = b"keystone-dek-wrap-v1";

/// Object-safe trait for Key Encryption Key operations.
pub trait KekProvider: Send + Sync {
    /// Wrap (encrypt) a 256-bit DEK.
    ///
    /// Returns an opaque blob: `[12-byte nonce][ciphertext][16-byte GCM tag]`.
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<Vec<u8>, CryptoError>;

    /// Unwrap (decrypt) a wrapped DEK blob produced by [`wrap_dek`].
    fn unwrap_dek(&self, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError>;
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
    // 1. `from_env` is called exactly once during storage initialisation, before
    //    any async tasks that might inspect the environment are spawned.
    // 2. No other thread is spawned before `init_storage` reaches this point, so
    //    there is no concurrent reader of `KEYSTONE_DEV_KEK`.
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
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        let nonce_bytes: [u8; 12] = rand::rng().random();
        let cipher = Aes256Gcm::new(key_ref(&*self.key)?);
        let gcm_nonce = nonce_ref(&nonce_bytes)?;

        let mut buf = dek.to_vec();
        let tag = cipher
            .encrypt_inout_detached(gcm_nonce, DEK_WRAP_AD, buf.as_mut_slice().into())
            .map_err(|_| CryptoError::AesEncrypt)?;

        let mut out = Vec::with_capacity(12 + 32 + 16);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&buf);
        out.extend_from_slice(&tag);
        Ok(out)
    }

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
        let cipher = Aes256Gcm::new(key_ref(&*self.key)?);

        let mut buf = wrapped[12..44].to_vec();
        cipher
            .decrypt_inout_detached(
                nonce_ref(&nonce_arr)?,
                DEK_WRAP_AD,
                buf.as_mut_slice().into(),
                tag_ref(&tag_arr)?,
            )
            .map_err(|_| CryptoError::AesDecrypt)?;

        if buf.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&buf);
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
    fn test_wrap_produces_different_nonces() {
        let kek = test_kek();
        let dek = [0xCDu8; 32];
        let w1 = kek.wrap_dek(&dek).expect("wrap 1");
        let w2 = kek.wrap_dek(&dek).expect("wrap 2");
        // Different nonces → different ciphertexts
        assert_ne!(w1, w2);
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
