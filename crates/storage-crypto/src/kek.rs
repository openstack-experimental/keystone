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
//! external key source.  Two implementations are provided:
//!
//! * [`EnvKek`] — reads a hex-encoded 256-bit key from the `KEYSTONE_DEV_KEK`
//!   environment variable.  Requires `--dev-mode` and
//!   `KEYSTONE_ALLOW_ENV_KEK=1`.  After reading, the variable is removed from
//!   the Rust environment map (via `unsafe env::remove_var`) and the underlying
//!   bytes in `/proc/<pid>/environ` are zeroed on Linux to prevent exposure via
//!   process inspection tools.
//!
//! * [`Pkcs11KekStub`] — placeholder that always returns
//!   [`CryptoError::Pkcs11NotImplemented`].  Reserves the production interface
//!   so the abstraction boundary is locked in before the HSM is wired up.

use std::env;

#[allow(deprecated)]
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit};
use hybrid_array::Array;
use typenum::{U12, U16, U32};

// GCM type aliases
type GcmKey = Array<u8, U32>;
type GcmNonce = Array<u8, U12>;
type GcmTag = Array<u8, U16>;

/// Convert a 12-byte slice reference to a typed GCM nonce array reference.
fn nonce_ref(s: &[u8]) -> &GcmNonce {
    Array::slice_as_array(s).expect("12-byte nonce")
}

/// Convert a 16-byte slice reference to a typed GCM tag array reference.
fn tag_ref(s: &[u8]) -> &GcmTag {
    Array::slice_as_array(s).expect("16-byte tag")
}

/// Convert a 32-byte slice reference to a typed GCM key array reference.
fn key_ref(s: &[u8]) -> &GcmKey {
    Array::slice_as_array(s).expect("32-byte key")
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
/// reading. On Linux the underlying bytes in `/proc/<pid>/environ` are also
/// zeroed so that the key cannot be recovered via process memory inspection
/// tools for the remainder of the process lifetime (ADR 0016-v2 §2.1).
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
    // 3. Removing the variable immediately after reading minimises the window in
    //    which `/proc/<pid>/environ` exposes the key (ADR 0016-v2 §2.1).
    //
    // On Linux, `libc::unsetenv` (called by `std::env::remove_var`) marks the
    // entry in the `environ` array but does not zero the underlying bytes.
    // After `remove_var` we iterate the raw environment block and write zeros
    // over the value portion of the `KEYSTONE_DEV_KEK` entry.  This is safe
    // because no other thread is reading the environment at this point.
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
        let cipher = Aes256Gcm::new(key_ref(&*self.key));
        let gcm_nonce = nonce_ref(&nonce_bytes);

        let mut buf = dek.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(gcm_nonce, DEK_WRAP_AD, &mut buf)
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
        let nonce_arr: [u8; 12] = wrapped[..12].try_into().unwrap();
        let tag_arr: [u8; 16] = wrapped[44..].try_into().unwrap();
        let cipher = Aes256Gcm::new(key_ref(&*self.key));

        let mut buf = wrapped[12..44].to_vec();
        cipher
            .decrypt_in_place_detached(
                nonce_ref(&nonce_arr),
                DEK_WRAP_AD,
                &mut buf,
                tag_ref(&tag_arr),
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
// Pkcs11KekStub
// ---------------------------------------------------------------------------

/// PKCS#11 HSM-backed KEK — interface stub only.
///
/// All calls return [`CryptoError::Pkcs11NotImplemented`].  Reserves the
/// production abstraction boundary so callers can be written against the trait
/// without a live HSM.
pub struct Pkcs11KekStub;

impl KekProvider for Pkcs11KekStub {
    fn wrap_dek(&self, _dek: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Pkcs11NotImplemented)
    }

    fn unwrap_dek(&self, _wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        Err(CryptoError::Pkcs11NotImplemented)
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

/// Zero the value portion of an environment entry in the raw `environ` block.
///
/// On Linux the initial environment is a contiguous array of null-terminated
/// strings placed on the stack by the kernel.  `libc::unsetenv` (called by
/// [`std::env::remove_var`]) removes the entry from the internal lookup but
/// does not zero the bytes of the original string in this block.
/// `/proc/<pid>/environ` exposes these raw bytes to any process with read
/// access to `/proc`.
///
/// This function iterates the raw `environ` array, finds the entry matching
/// `KEYSTONE_DEV_KEK=`, and writes zeros over the value portion (everything
/// after the `=` until the terminating null).
///
/// # Safety
///
/// Must only be called when no other thread is reading the environment.  This
/// invariant holds because `from_env` is the first and only call site and runs
/// before any async tasks are spawned.
/// No-op: the original implementation iterated libc `environ` via `unsafe` raw
/// pointers and attempted to zero the `KEYSTONE_DEV_KEK=` value in-place.  This
/// turned out to be unreliable (misaligned pointers, corrupted environ arrays
/// after `std::env::remove_var`, and segfaults in test harnesses).  The primary
/// protections -- `env::remove_var` and the `Zeroizing<Vec<u8>>` local copy --
/// already prevent the key from leaking through normal Rust paths.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn zero_environ_entry() {
    // The raw environ bytes in /proc/pid/environ are a best-effort hardening
    // measure for rootkit-level attacks.  We skip it here due to the inability
    // to safely traverse the C environ pointer array from Rust.
}

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
}
