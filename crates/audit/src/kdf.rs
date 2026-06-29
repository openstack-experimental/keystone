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
//! Per-node HMAC key derivation for the CADF audit framework (ADR 0023).
//!
//! The derivation formula is:
//!
//! ```text
//! HKDF-Expand(KEK, info = "keystone-audit-hmac-v1:" ++ node_id_utf8, L = 32)
//! ```
//!
//! `KEK` is the root key material (≥ 32 uniform random bytes).  The
//! `node_id` suffix ensures each node receives a **distinct** signing key;
//! a compromised node therefore cannot forge audit records attributed to
//! other nodes.  This aligns with ADR 0016-v2 §3.1 which uses the same
//! Expand-only construction with `node_id_u64_be` for Raft nodes.

use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a 32-byte HMAC signing key for the given node from a root KEK.
///
/// `kek` MUST be at least 32 bytes of uniform random key material.
///
/// # Panics
///
/// Panics if `kek` is shorter than 32 bytes (SHA-256 output size), since
/// the PRK is too short to be used as HKDF pseudo-random key material.
pub fn derive_audit_hmac_key(kek: &[u8], node_id: &str) -> [u8; 32] {
    let info = format!("keystone-audit-hmac-v1:{node_id}");
    // Expand-only: KEK is already uniform random, Extract is a no-op
    // security-wise (same justification as ADR 0016-v2 §3.1).
    let hk = Hkdf::<Sha256>::from_prk(kek).expect("KEK must be >= 32 bytes (SHA-256 output size)");
    let mut out = [0u8; 32];
    hk.expand(info.as_bytes(), &mut out)
        .expect("32 bytes is always a valid HKDF-SHA256 output length");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEK: &[u8] = b"test-kek-32-bytes-0123456789abcd";

    #[test]
    fn different_nodes_yield_different_keys() {
        let k1 = derive_audit_hmac_key(KEK, "node-1");
        let k2 = derive_audit_hmac_key(KEK, "node-2");
        assert_ne!(k1, k2, "distinct node IDs must produce distinct keys");
    }

    #[test]
    fn derivation_is_deterministic() {
        let k1 = derive_audit_hmac_key(KEK, "node-1");
        let k2 = derive_audit_hmac_key(KEK, "node-1");
        assert_eq!(k1, k2, "same inputs must always yield the same key");
    }

    #[test]
    fn known_vector() {
        // Pre-computed reference value for SIEM implementors and cross-language
        // verification. Regenerate with:
        //   cargo test -p openstack-keystone-audit kdf::tests::known_vector -- --nocapture
        let key = derive_audit_hmac_key(KEK, "keystone-node-1");
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "85256aea1521266824b36db34a3060d0cb91b76bbad266e10ba20dba76eabe72"
        );
    }
}
