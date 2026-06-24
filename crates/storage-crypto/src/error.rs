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
    /// AES-256-GCM encryption failed (internal AES error).
    #[error("AES-256-GCM encryption error")]
    AesEncrypt,

    /// AES-256-GCM decryption failed — GCM tag mismatch indicates data
    /// corruption or tampering.
    #[error("AES-256-GCM decryption error: GCM tag verification failed")]
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

    /// PKCS#11 backend is not yet implemented.
    #[error("PKCS#11 HSM backend is not implemented in this build")]
    Pkcs11NotImplemented,
}
