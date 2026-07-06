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

//! Deterministic user id generation, bit-compatible with python-keystone's
//! `keystone.identity.id_generators.sha256.Generator.generate_public_ID`.
//!
//! python-keystone derives shadow/nonlocal user ids as `sha256` over the
//! *values* of `{domain_id, local_id, entity_type}`, iterated in
//! alphabetically-sorted key order (`domain_id`, `entity_type`, `local_id`),
//! UTF-8 encoded, no separators, hex digest. This is a pure function: the
//! same triple always yields the same id, which is what lets SCIM-provisioned
//! users and JIT-provisioned federated users converge on one user row when
//! `local_id` (SCIM `externalId` / the IdP's `sub` claim) matches, without
//! any lookup table.
use sha2::{Digest, Sha256};

/// Deterministically derive a user id from `(domain_id, local_id,
/// entity_type)`, matching python-keystone's sha256 id generator exactly.
pub fn generate_public_id(domain_id: &str, local_id: &str, entity_type: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain_id.as_bytes());
    hasher.update(entity_type.as_bytes());
    hasher.update(local_id.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden value computed directly from python-keystone's
    /// `keystone/identity/id_generators/sha256.py`:
    /// ```python
    /// import hashlib
    /// m = hashlib.sha256()
    /// mapping = {'domain_id': 'd1', 'local_id': 'ext-1', 'entity_type': 'user'}
    /// for key in sorted(mapping.keys()):
    ///     m.update(mapping[key].encode('utf-8'))
    /// m.hexdigest()
    /// ```
    #[test]
    fn test_matches_python_keystone_golden_value() {
        assert_eq!(
            generate_public_id("d1", "ext-1", "user"),
            "706be650a00d566f9d10d02258a814a7049afa6ccebf52f278a44f83c09daa5d"
        );
    }

    #[test]
    fn test_deterministic() {
        assert_eq!(
            generate_public_id("domain", "local", "user"),
            generate_public_id("domain", "local", "user")
        );
    }

    #[test]
    fn test_distinguishes_inputs() {
        assert_ne!(
            generate_public_id("domain-a", "local", "user"),
            generate_public_id("domain-b", "local", "user")
        );
        assert_ne!(
            generate_public_id("domain", "local-a", "user"),
            generate_public_id("domain", "local-b", "user")
        );
    }
}
