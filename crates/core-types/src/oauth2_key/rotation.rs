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
//! # Signing key rotation DTOs (ADR 0026 §3)

/// Returned when an emergency rotation is staged: the confirming operator
/// needs `rotation_id`, and callers surface `expires_at` so they know the
/// dual-control confirmation window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRotationInfo {
    /// Opaque identifier the second operator passes to confirm the
    /// rotation.
    pub rotation_id: String,
    /// Unix epoch seconds after which this pending rotation auto-aborts.
    pub expires_at: i64,
}

/// Returned when a `--local-quorum-bypass` emergency rotation is staged
/// (ADR 0028 §2).
///
/// Unlike [`PendingRotationInfo`], there is no `expires_at`: a local
/// candidate persists until an operator explicitly reconciles it once Raft
/// quorum returns (ADR 0028 §4) — there is no fixed confirmation window to
/// auto-abort against, since the whole point is that it may stay
/// unreachable for an unknown, possibly long, duration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEmergencyRotationInfo {
    /// Opaque identifier the reconciliation tool/operator uses to select
    /// this candidate among any others staged during the same outage.
    pub rotation_id: String,
    /// The operator-supplied justification recorded with the candidate.
    pub justification: String,
}

/// One node-local emergency rotation candidate, as surfaced to an operator
/// deciding which `rotation_id` to reconcile (ADR 0028 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEmergencyCandidateSummary {
    /// Opaque identifier to pass to reconciliation.
    pub rotation_id: String,
    /// Identity of the operator who staged this candidate.
    pub initiator: String,
    /// The operator-supplied justification recorded with the candidate.
    pub justification: String,
    /// Unix epoch seconds the candidate was created.
    pub created_at_unix: i64,
    /// `None` if staged on the node answering this request; `Some(node_id)`
    /// if it arrived via gossip from another node (ADR 0028 §5).
    pub origin_node_id: Option<u64>,
    /// Set if gossip detected a different active candidate for this domain
    /// on another node (`LOCAL_EMERGENCY_CONFLICT`) — the operator must
    /// explicitly pick one side.
    pub conflicted: bool,
    /// Set once this candidate has lost reconciliation (superseded by a
    /// sibling that was promoted instead). Never reconcilable.
    pub revoked: bool,
}
