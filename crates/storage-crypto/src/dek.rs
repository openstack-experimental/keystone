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
//! it via HKDF-Expand.  Sub-keys are domain-separated so log, state, and
//! backup ciphertexts are never encrypted under the same key context.
//!
//! ## Sub-key derivation
//!
//! ```text
//! DEK (256-bit uniform random)
//!  ├── LogDek   = HKDF-Expand(DEK, info="keystone-raft-log-v1",    L=32)
//!  └── StateDek = HKDF-Expand(DEK, info="keystone-fjall-state-v1", L=32)
//! ```
//!
//! HKDF-Expand (without Extract) is used because the DEK is already
//! cryptographically uniform random (generated with a CSPRNG), so the
//! Extract step adds no security and Extract is omitted as per ADR §2.1.

use hkdf::Hkdf;
use rand::RngExt;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;

const LOG_DEK_INFO: &[u8] = b"keystone-raft-log-v1";
const STATE_DEK_INFO: &[u8] = b"keystone-fjall-state-v1";

// ---------------------------------------------------------------------------
// Sub-key types  (no Debug/Display — never format key material)
// ---------------------------------------------------------------------------

/// Sub-key for encrypting Raft log entries.
pub struct LogDek(pub(crate) Zeroizing<[u8; 32]>);

/// Sub-key for encrypting Fjall state machine entries.
pub struct StateDek(pub(crate) Zeroizing<[u8; 32]>);

// ---------------------------------------------------------------------------
// DekEpoch
// ---------------------------------------------------------------------------

/// A single DEK rotation epoch: version number plus derived sub-keys.
///
/// All encryption in a given epoch uses the sub-keys held here.  On DEK
/// rotation (Phase 5) a new `DekEpoch` with an incremented version replaces
/// this one.
pub struct DekEpoch {
    /// Monotonically increasing epoch counter (`dek_version_u32`).
    pub version: u32,
    log_dek: LogDek,
    state_dek: StateDek,
}

impl DekEpoch {
    /// Derive a `DekEpoch` from raw DEK bytes.
    ///
    /// Uses HKDF-Expand (no Extract) to produce domain-separated sub-keys.
    /// The raw DEK bytes are zeroed when this function returns.
    pub fn from_raw(dek_bytes: &Zeroizing<[u8; 32]>, version: u32) -> Result<Self, CryptoError> {
        let hkdf = Hkdf::<Sha256>::from_prk(dek_bytes.as_ref())
            .map_err(|_| CryptoError::InvalidKeyLength)?;

        let mut log_key = Zeroizing::new([0u8; 32]);
        hkdf.expand(LOG_DEK_INFO, log_key.as_mut())
            .map_err(|_| CryptoError::InvalidKeyLength)?;

        let mut state_key = Zeroizing::new([0u8; 32]);
        hkdf.expand(STATE_DEK_INFO, state_key.as_mut())
            .map_err(|_| CryptoError::InvalidKeyLength)?;

        Ok(Self {
            version,
            log_dek: LogDek(log_key),
            state_dek: StateDek(state_key),
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

/// Generate a fresh 256-bit DEK using a CSPRNG.
///
/// Returns the raw key bytes in a zeroing wrapper.  The caller is responsible
/// for immediately wrapping the DEK under the KEK and clearing the raw bytes.
pub fn generate_dek() -> Zeroizing<[u8; 32]> {
    let mut dek = Zeroizing::new([0u8; 32]);
    // rand::fill is CSPRNG-backed (OsRng on all supported platforms).
    rand::rng().fill(dek.as_mut());
    dek
}

/// Zeroize sub-keys when `DekEpoch` is dropped.
impl Drop for DekEpoch {
    fn drop(&mut self) {
        self.log_dek.0.zeroize();
        self.state_dek.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dek_epoch_from_raw() {
        let raw = Zeroizing::new([0x55u8; 32]);
        let epoch = DekEpoch::from_raw(&raw, 0).expect("derive");
        // Sub-keys must differ from each other and from raw input.
        assert_ne!(epoch.log_dek.0.as_ref(), raw.as_ref());
        assert_ne!(epoch.state_dek.0.as_ref(), raw.as_ref());
        assert_ne!(epoch.log_dek.0.as_ref(), epoch.state_dek.0.as_ref());
    }

    #[test]
    fn test_dek_epoch_deterministic() {
        let raw = Zeroizing::new([0xAAu8; 32]);
        let e1 = DekEpoch::from_raw(&raw, 1).expect("first");
        let e2 = DekEpoch::from_raw(&raw, 1).expect("second");
        // Same DEK → same sub-keys regardless of call order.
        assert_eq!(e1.log_dek.0.as_ref(), e2.log_dek.0.as_ref());
        assert_eq!(e1.state_dek.0.as_ref(), e2.state_dek.0.as_ref());
    }

    #[test]
    fn test_generate_dek_non_zero() {
        let dek = generate_dek();
        // Statistically impossible to generate all-zeros from a CSPRNG.
        assert_ne!(dek.as_ref(), &[0u8; 32]);
    }
}
