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
// Crypto inventory: TOK-12; see doc/src/contributor/crypto-inventory.md
//! # DPoP server nonces (RFC 9449 §8, ADR 0043 §2)
//!
//! A nonce is `HMAC-SHA256(K, slot)` where `slot = now / lifetime` and `K` is
//! derived from the cluster salt. The value is stateless and identical on
//! every node that shares the salt, so any node accepts a nonce issued by
//! another. The current and the previous slot are accepted, so a nonce stays
//! valid for between one and two slot lengths.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use thiserror::Error;

/// Domain separation label for the nonce key derivation.
const KEY_LABEL: &[u8] = b"keystone-oauth2-dpop-nonce-v1";

type HmacSha256 = Hmac<Sha256>;

/// Nonce generator construction failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DpopNonceError {
    /// The cluster salt is empty.
    #[error("cluster salt is empty")]
    EmptySalt,

    /// The MAC rejected the key material.
    #[error("DPoP nonce key is unusable")]
    InvalidKey,

    /// The slot length is zero.
    #[error("DPoP nonce lifetime must be greater than zero")]
    ZeroLifetime,
}

/// Stateless issuer and checker of DPoP nonces.
pub struct DpopNonceGenerator {
    lifetime_secs: u64,
    /// HMAC keyed with the derived nonce key; cloned for every computation.
    mac: HmacSha256,
}

impl DpopNonceGenerator {
    /// Derive the nonce key from the cluster salt.
    ///
    /// `lifetime_secs` is `[oauth2] dpop_nonce_lifetime_seconds`.
    ///
    /// # Errors
    /// Fails on an empty salt or a zero lifetime.
    pub fn new(cluster_salt: &[u8], lifetime_secs: u64) -> Result<Self, DpopNonceError> {
        if cluster_salt.is_empty() {
            return Err(DpopNonceError::EmptySalt);
        }
        if lifetime_secs == 0 {
            return Err(DpopNonceError::ZeroLifetime);
        }
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(cluster_salt)
            .map_err(|_| DpopNonceError::InvalidKey)?;
        mac.update(KEY_LABEL);
        let key = mac.finalize().into_bytes();
        let mac = <HmacSha256 as KeyInit>::new_from_slice(&key)
            .map_err(|_| DpopNonceError::InvalidKey)?;
        Ok(Self { mac, lifetime_secs })
    }

    fn slot(&self, now: i64) -> u64 {
        u64::try_from(now).unwrap_or(0) / self.lifetime_secs
    }

    fn nonce_for_slot(&self, slot: u64) -> String {
        let mut mac = self.mac.clone();
        mac.update(&slot.to_be_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// The nonce to hand out in a `DPoP-Nonce` header at time `now`.
    pub fn issue(&self, now: i64) -> String {
        self.nonce_for_slot(self.slot(now))
    }

    /// Nonces a proof may carry at time `now`: the current and the previous
    /// slot. Feed it to
    /// [`DpopProofContext::accepted_nonces`](super::dpop::DpopProofContext).
    pub fn accepted(&self, now: i64) -> Vec<String> {
        let slot = self.slot(now);
        let mut nonces = vec![self.nonce_for_slot(slot)];
        if let Some(previous) = slot.checked_sub(1) {
            nonces.push(self.nonce_for_slot(previous));
        }
        nonces
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_760_000_000;

    fn generator(salt: &[u8]) -> DpopNonceGenerator {
        DpopNonceGenerator::new(salt, 300).unwrap()
    }

    #[test]
    fn test_same_salt_same_nonce_on_every_node() {
        assert_eq!(generator(b"salt").issue(NOW), generator(b"salt").issue(NOW));
    }

    #[test]
    fn test_different_salt_different_nonce() {
        assert_ne!(
            generator(b"salt").issue(NOW),
            generator(b"other").issue(NOW)
        );
    }

    #[test]
    fn test_nonce_stable_within_slot_and_changes_after() {
        let g = generator(b"salt");
        let slot_start = NOW - NOW % 300;
        assert_eq!(g.issue(slot_start), g.issue(slot_start + 299));
        assert_ne!(g.issue(slot_start), g.issue(slot_start + 300));
    }

    #[test]
    fn test_current_and_previous_slot_accepted() {
        let g = generator(b"salt");
        let issued = g.issue(NOW);
        // Valid for the rest of its slot and for the whole next one.
        assert!(g.accepted(NOW).contains(&issued));
        assert!(g.accepted(NOW + 300).contains(&issued));
        // Expired two slots later.
        assert!(!g.accepted(NOW + 600).contains(&issued));
    }

    #[test]
    fn test_foreign_nonce_not_accepted() {
        let g = generator(b"salt");
        let foreign = generator(b"other").issue(NOW);
        assert!(!g.accepted(NOW).contains(&foreign));
    }

    #[test]
    fn test_invalid_construction() {
        assert_eq!(
            DpopNonceGenerator::new(b"", 300).err(),
            Some(DpopNonceError::EmptySalt)
        );
        assert_eq!(
            DpopNonceGenerator::new(b"salt", 0).err(),
            Some(DpopNonceError::ZeroLifetime)
        );
    }

    #[test]
    fn test_accepted_at_epoch_start() {
        assert_eq!(generator(b"salt").accepted(0).len(), 1);
    }
}
