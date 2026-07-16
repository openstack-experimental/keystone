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

//! Key-namespace builders for the local emergency store (ADR 0028 §2).
//!
//! Every implementation and every subsystem must build keys through these
//! functions rather than formatting the `_local:...` prefix by hand, so the
//! namespace stays consistent across the Fjall-backed store, gossip
//! payloads, and the reconciliation/audit pointer records.

use crate::Subsystem;

/// Prefix for every key this crate owns, so a generic prefix scan can find
/// all locally-written emergency state regardless of subsystem.
pub const ROOT_PREFIX: &str = "_local";

/// Prefix for every candidate written under a given subsystem, regardless of
/// scope. Distinct from [`ROOT_PREFIX`] alone so a subsystem-wide scan never
/// picks up unrelated `_local:...` records (e.g. the audit pointer keys from
/// [`audit_pointer_key`], which do not have a scope segment).
pub fn candidate_subsystem_prefix(subsystem: Subsystem) -> String {
    format!("{ROOT_PREFIX}:{}:", subsystem.as_str())
}

/// Prefix for every candidate written under a given subsystem/scope, without
/// a trailing rotation id. Used to list/scan all candidates for that scope.
pub fn candidate_scope_prefix(subsystem: Subsystem, scope_id: &str) -> String {
    format!(
        "{}{scope_id}:emergency:",
        candidate_subsystem_prefix(subsystem)
    )
}

/// Full key for one emergency rotation candidate.
pub fn candidate_key(subsystem: Subsystem, scope_id: &str, rotation_id: &str) -> String {
    format!(
        "{}{rotation_id}",
        candidate_scope_prefix(subsystem, scope_id)
    )
}

/// Full key for the compact audit pointer record for a rotation id
/// (ADR 0028 implementation plan, design gap 2) — kept separate from the
/// candidate record itself so reconciliation tooling can enumerate audit
/// entries without touching (or accidentally clearing) candidate data.
pub fn audit_pointer_key(rotation_id: &str) -> String {
    format!("{ROOT_PREFIX}:emergency:audit:{rotation_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_key_layout() {
        assert_eq!(
            candidate_key(Subsystem::Oauth2SigningKey, "default", "rot-1"),
            "_local:oauth2_signing_key:default:emergency:rot-1"
        );
        assert_eq!(
            candidate_key(Subsystem::Dek, "cluster", "rot-2"),
            "_local:dek:cluster:emergency:rot-2"
        );
    }

    #[test]
    fn candidate_key_is_prefixed_by_scope_prefix() {
        let prefix = candidate_scope_prefix(Subsystem::Dek, "cluster");
        let key = candidate_key(Subsystem::Dek, "cluster", "rot-2");
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn audit_pointer_key_layout() {
        assert_eq!(audit_pointer_key("rot-1"), "_local:emergency:audit:rot-1");
    }
}
