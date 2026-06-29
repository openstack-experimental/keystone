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
//! Per-node audit HMAC key (ADR 0016-v2 §3.1 / Phase 8).
//!
//! `AuditHmacKey` is derived from the DEK per epoch via
//! `DekEpoch::derive_audit_key(node_id)`, so the HMAC key rotates with each
//! DEK rotation, binding audit key lifetime to DEK epoch (F2: preventing
//! indefinite forgery after a single compromise).
//!
//! Derivation:
//! `AuditHmacKey = HKDF-Expand(DEK, info = b"keystone-audit-dek-v1" ++
//! version_u32_be ++ node_id_u64_be, L=32)`.
//!
//! Signing:
//! `HMAC-SHA256(AuditHmacKey, canonical_message_bytes)`.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::CryptoError;

type HmacSha256 = Hmac<Sha256>;

/// Per-node HMAC key for signing audit records.
///
/// Does not derive `Debug` or `Display` to prevent accidental key leakage.
pub struct AuditHmacKey(Zeroizing<[u8; 32]>);

impl AuditHmacKey {
    /// Wrap raw key bytes into an `AuditHmacKey`.
    pub fn from_raw(raw: [u8; 32]) -> Self {
        Self(Zeroizing::new(raw))
    }

    /// Compute `HMAC-SHA256(self, message)` and return the 32-byte MAC.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 32], CryptoError> {
        let mut mac = HmacSha256::new_from_slice(self.0.as_ref())
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        mac.update(message);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_deterministic() {
        let key = AuditHmacKey::from_raw([0x01u8; 32]);
        let msg = b"test audit record";
        let mac1 = key.sign(msg).unwrap();
        let mac2 = key.sign(msg).unwrap();
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_sign_different_keys() {
        let key1 = AuditHmacKey::from_raw([0x01u8; 32]);
        let key2 = AuditHmacKey::from_raw([0x02u8; 32]);
        let msg = b"same message";
        assert_ne!(key1.sign(msg).unwrap(), key2.sign(msg).unwrap());
    }

    #[test]
    fn test_sign_different_messages() {
        let key = AuditHmacKey::from_raw([0x03u8; 32]);
        let mac1 = key.sign(b"message one").unwrap();
        let mac2 = key.sign(b"message two").unwrap();
        assert_ne!(mac1, mac2);
    }
}
