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
// Crypto inventory: AUD-2; see doc/src/contributor/crypto-inventory.md
//! Per-node HMAC key derivation for the CADF audit framework (ADR 0023).
//!
//! The derivation formula is full HKDF-SHA256 (RFC 5869):
//!
//! ```text
//! HKDF(salt = "{service_name}-audit-hmac-salt-v1",
//!      IKM  = KEK,
//!      info = "{service_name}-audit-hmac-v1:" ++ node_id_utf8,
//!      L    = 32)
//! ```
//!
//! `KEK` is the root key material (>= 32 uniform random bytes).  The
//! `node_id` suffix ensures each node receives a **distinct** signing key;
//! a compromised node therefore cannot forge audit records attributed to
//! other nodes.  Extract-then-Expand with a fixed, non-empty salt is used
//! (rather than Expand-only) because it is the flow the FIPS 140-3 validated
//! module documents as an approved key-derivation service.

use crate::ServiceIdentity;
use crate::crypto::{self, CryptoError};

/// Derive a 32-byte HMAC signing key for the given node from a root KEK.
///
/// `kek` MUST be at least 32 bytes of uniform random key material.
pub fn derive_audit_hmac_key(
    service: &ServiceIdentity,
    kek: &[u8],
    node_id: &str,
) -> Result<[u8; 32], CryptoError> {
    let info = service.kdf_info(node_id);
    let salt = service.kdf_salt();
    let mut out = [0u8; 32];
    crypto::hkdf_extract_expand(salt.as_bytes(), kek, info.as_bytes(), &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE: ServiceIdentity = ServiceIdentity::new("keystone");
    const KEK: &[u8] = b"test-kek-32-bytes-0123456789abcd";

    #[test]
    fn different_nodes_yield_different_keys() {
        let k1 = derive_audit_hmac_key(&SERVICE, KEK, "node-1").unwrap();
        let k2 = derive_audit_hmac_key(&SERVICE, KEK, "node-2").unwrap();
        assert_ne!(k1, k2, "distinct node IDs must produce distinct keys");
    }

    #[test]
    fn derivation_is_deterministic() {
        let k1 = derive_audit_hmac_key(&SERVICE, KEK, "node-1").unwrap();
        let k2 = derive_audit_hmac_key(&SERVICE, KEK, "node-1").unwrap();
        assert_eq!(k1, k2, "same inputs must always yield the same key");
    }

    #[test]
    fn known_vector() {
        // Pre-computed reference value for SIEM implementors and cross-language
        // verification. Regenerate with:
        //   cargo test -p cadf kdf::tests::known_vector --
        // --nocapture
        let key = derive_audit_hmac_key(&SERVICE, KEK, "keystone-node-1").unwrap();
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "2f35c5d70caf6e454245b6e88f79a351314b5645d485f84dd302d3d3cc5834c2"
        );
    }
}
