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

//! Gossip conflict detection (ADR 0028 §5).
//!
//! Pure decision logic only — the actual peer enumeration, network probe,
//! and RPC transport live in the consuming crate (`storage`), which already
//! owns the Raft membership handle and gRPC client. Kept here so the
//! decision of "is this a conflict" is defined once and tested without any
//! network machinery.

use crate::EmergencyCandidate;

/// Outcome of receiving a gossiped candidate against this node's existing
/// candidates for the same `(subsystem, scope_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipOutcome {
    /// No active candidate exists locally for this scope yet: adopt the
    /// incoming candidate as-is.
    Adopt,
    /// An active local candidate with the same `rotation_id` already exists
    /// (a re-gossip, e.g. after a retry or a peer reconnecting) — no-op.
    AlreadyPresent,
    /// An active local candidate exists for the same scope but with a
    /// *different* `rotation_id` — both candidates must be marked
    /// conflicted; reconciliation makes the final call (ADR 0028 §6).
    Conflict {
        /// `rotation_id` of the pre-existing local candidate that conflicts
        /// with the incoming one.
        existing_rotation_id: String,
    },
}

/// Decide how to handle a gossiped candidate given this node's existing,
/// non-revoked candidates for the same `(subsystem, scope_id)`.
///
/// `existing_active` must already be filtered to the same subsystem/scope
/// and to non-revoked candidates; this function does not do that filtering
/// itself so callers can reuse a single `list_candidates` result across
/// several incoming gossip messages.
pub fn decide_gossip_outcome(
    existing_active: &[EmergencyCandidate],
    incoming: &EmergencyCandidate,
) -> GossipOutcome {
    match existing_active
        .iter()
        .find(|c| !c.revoked && c.rotation_id != incoming.rotation_id)
    {
        Some(conflicting) => GossipOutcome::Conflict {
            existing_rotation_id: conflicting.rotation_id.clone(),
        },
        None => {
            if existing_active
                .iter()
                .any(|c| c.rotation_id == incoming.rotation_id)
            {
                GossipOutcome::AlreadyPresent
            } else {
                GossipOutcome::Adopt
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::Subsystem;

    fn candidate(rotation_id: &str, revoked: bool) -> EmergencyCandidate {
        EmergencyCandidate {
            subsystem: Subsystem::Dek,
            scope_id: "cluster".to_string(),
            rotation_id: rotation_id.to_string(),
            payload: vec![1, 2, 3],
            initiator: "spiffe://example.org/operator/alice".to_string(),
            justification: "suspected key compromise".to_string(),
            created_at: Utc::now(),
            revoked,
            origin_node_id: None,
            conflicted: false,
        }
    }

    #[test]
    fn adopts_when_nothing_active_locally() {
        let incoming = candidate("rot-remote", false);
        assert_eq!(decide_gossip_outcome(&[], &incoming), GossipOutcome::Adopt);
    }

    #[test]
    fn adopts_when_only_revoked_candidates_present() {
        let existing = vec![candidate("rot-old", true)];
        let incoming = candidate("rot-remote", false);
        assert_eq!(
            decide_gossip_outcome(&existing, &incoming),
            GossipOutcome::Adopt
        );
    }

    #[test]
    fn already_present_is_a_noop() {
        let existing = vec![candidate("rot-remote", false)];
        let incoming = candidate("rot-remote", false);
        assert_eq!(
            decide_gossip_outcome(&existing, &incoming),
            GossipOutcome::AlreadyPresent
        );
    }

    #[test]
    fn different_active_rotation_is_a_conflict() {
        let existing = vec![candidate("rot-local", false)];
        let incoming = candidate("rot-remote", false);
        assert_eq!(
            decide_gossip_outcome(&existing, &incoming),
            GossipOutcome::Conflict {
                existing_rotation_id: "rot-local".to_string()
            }
        );
    }
}
