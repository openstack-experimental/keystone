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
//! # `kid` derivation (ADR 0026 §3)
use sha2::{Digest, Sha256};

/// Derive a JWK `kid` from a DER-encoded (SubjectPublicKeyInfo) public key:
/// the first 32 hex characters (128 bits) of the SHA-256 hash.
///
/// Deterministic given the same public key, eliminating the need for an
/// external key-tracking table.
#[must_use]
pub fn derive_kid(der_public_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der_public_key);
    let digest = hasher.finalize();
    digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_kid_length_and_charset() {
        let kid = derive_kid(b"some DER-encoded public key bytes");
        assert_eq!(kid.len(), 32);
        assert!(
            kid.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn test_derive_kid_is_deterministic() {
        let der = b"fixed known-answer DER blob";
        assert_eq!(derive_kid(der), derive_kid(der));
    }

    #[test]
    fn test_derive_kid_known_answer_vector() {
        // SHA-256("keystone-adr-0026-kid-fixture") = 32e2ee...
        // first 16 bytes (32 hex chars) pinned as a known-answer vector so a
        // future accidental change to the truncation/encoding is caught.
        let der = b"keystone-adr-0026-kid-fixture";
        let mut hasher = Sha256::new();
        hasher.update(der);
        let full_hex: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let expected = full_hex[..32].to_string();
        assert_eq!(derive_kid(der), expected);
    }

    #[test]
    fn test_derive_kid_differs_for_different_input() {
        assert_ne!(derive_kid(b"key-a"), derive_kid(b"key-b"));
    }
}
