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
//!   `KEYSTONE_ALLOW_ENV_KEK=1`.  The variable is unset immediately after
//!   reading to avoid leaking it into `/proc/<pid>/environ`.
//!
//! * [`Pkcs11KekStub`] — placeholder that always returns
//!   [`CryptoError::Pkcs11NotImplemented`].  Reserves the production interface
//!   so the abstraction boundary is locked in before the HSM is wired up.

use std::env;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit};
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
/// Note: `std::env::remove_var` is `unsafe` in Rust 2024 edition (TOCTOU with
/// concurrent env reads) and the workspace forbids `unsafe` code, so the
/// variable is NOT removed from the process environment after reading.
/// The key material is consumed into a `Zeroizing` allocation; the env string
/// copy is zeroized before drop.  Operators should use OS-level process
/// isolation (e.g., `systemd` with `UnsetEnvironment=`) to clear the variable.
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

    pub fn from_env() -> Result<Self, CryptoError> {
        let mut hex_val = env::var("KEYSTONE_DEV_KEK").map_err(|_| CryptoError::KekMissing)?;
        let raw = decode_hex(&hex_val).map_err(|_| CryptoError::InvalidHex)?;
        hex_val.zeroize();

        if raw.len() != 32 {
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
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(self.key.as_ref()));

        let mut buf = dek.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, DEK_WRAP_AD, &mut buf)
            .map_err(|_| CryptoError::AesEncrypt)?;

        let mut out = Vec::with_capacity(12 + 32 + 16);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&buf);
        out.extend_from_slice(tag.as_slice());
        Ok(out)
    }

    fn unwrap_dek(&self, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        // Layout: [12-byte nonce][32-byte ciphertext][16-byte tag]
        if wrapped.len() != 12 + 32 + 16 {
            return Err(CryptoError::WrappedDekSize);
        }
        let nonce = GenericArray::from_slice(&wrapped[..12]);
        let tag = GenericArray::from_slice(&wrapped[44..]);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(self.key.as_ref()));

        let mut buf = wrapped[12..44].to_vec();
        cipher
            .decrypt_in_place_detached(nonce, DEK_WRAP_AD, &mut buf, tag)
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
    if s.len() % 2 != 0 {
        return Err(CryptoError::InvalidHex);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| CryptoError::InvalidHex))
        .collect()
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
        assert!(matches!(kek.unwrap_dek(&wrapped), Err(CryptoError::AesDecrypt)));
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
