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

use thiserror::Error;

/// Errors produced by the storage cryptographic layer.
#[derive(Error, Debug)]
pub enum CryptoError {
    /// AES encryption (wrap) failed, whether the AEAD construction is
    /// AES-256-GCM ([`EnvKek`], PKCS#11) or AES-256-CFB + HMAC
    /// Encrypt-then-MAC (TPM).
    ///
    /// [`EnvKek`]: crate::kek::EnvKek
    #[error("AES encryption error")]
    AesEncrypt,

    /// AES decryption (unwrap) failed — tag mismatch indicates data
    /// corruption or tampering. Covers both AES-256-GCM ([`EnvKek`],
    /// PKCS#11) and AES-256-CFB + HMAC Encrypt-then-MAC (TPM); the shared
    /// variant intentionally makes the two constructions' failures
    /// indistinguishable to callers.
    ///
    /// [`EnvKek`]: crate::kek::EnvKek
    #[error("AES decryption error: authentication tag verification failed")]
    AesDecrypt,

    /// DEK epoch has not been loaded; `bootstrap_dek` must be called first.
    #[error("DEK not loaded — bootstrap must be called before encryption")]
    DekMissing,

    /// The nonce read-back after a persistence write did not match the written
    /// value, indicating a storage error.
    #[error("nonce read-back mismatch after write — storage error")]
    NonceReadbackMismatch,

    /// The recovered nonce counter is less than the high-water mark, indicating
    /// rollback or corruption.  Node must not start to prevent nonce reuse.
    #[error("nonce counter rollback detected: recovered={current} is not ahead of hwm={hwm}")]
    NonceCounterRollback { current: u64, hwm: u64 },

    /// The nonce counter has reached the rotation threshold.
    #[error("nonce counter exhausted — DEK rotation required")]
    NonceExhausted,

    /// An error occurred while persisting nonce state.
    #[error("nonce persistence error: {0}")]
    NoncePersistence(String),

    /// KEK is not configured.
    #[error("KEK not configured or unavailable")]
    KekMissing,

    /// The supplied hex string is not valid hexadecimal.
    #[error("invalid hex encoding for key material")]
    InvalidHex,

    /// The decoded key material has an unexpected length.
    #[error("invalid key length: expected 32 bytes")]
    InvalidKeyLength,

    /// The wrapped DEK blob has an unexpected size.
    #[error("wrapped DEK has wrong format or size")]
    WrappedDekSize,

    /// The stored bytes are too short to contain a valid encrypted record.
    #[error("stored ciphertext is too short to be a valid encrypted record")]
    CiphertextTooShort,

    /// A byte slice that should have a fixed AEAD parameter length
    /// (nonce/tag/key) did not. Should be unreachable in practice — every
    /// call site passes a statically-sized array — but propagated as an
    /// error instead of panicking in case that invariant is ever violated.
    #[error("internal error: fixed-length cryptographic parameter had the wrong size")]
    InvalidArrayLength,

    /// Ciphertext was encrypted under a revoked DEK epoch (ADR 0016-v2 §6.2).
    /// Emergency rotation revokes the compromised DEK; any attempt to decrypt
    /// data with the revoked key is a fatal error.
    #[error("DEK epoch {version} was revoked; decryption refused")]
    RevokedDek { version: u32 },

    /// A PKCS#11 setup or session operation failed (module load, slot lookup,
    /// login, key generation/lookup). Wrap/unwrap operation failures use
    /// [`CryptoError::AesEncrypt`] / [`CryptoError::AesDecrypt`] instead, so
    /// this variant is confined to provider construction.
    #[error("PKCS#11 operation failed: {0}")]
    Pkcs11(String),

    /// A TPM 2.0 setup or session operation failed (context open, primary
    /// creation, key generation/lookup, persistence). Wrap/unwrap operation
    /// failures use [`CryptoError::AesEncrypt`] / [`CryptoError::AesDecrypt`]
    /// instead, so this variant is confined to provider construction.
    #[error("TPM operation failed: {0}")]
    Tpm(String),
}
