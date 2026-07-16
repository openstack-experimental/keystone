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

//! # Local emergency store (ADR 0028)
//!
//! Generic, node-local write path used by an emergency rotation subsystem
//! (OAuth2 signing keys, DEKs) when Raft quorum is unavailable. Values
//! written through this crate never go through `StorageApi`/Raft — they live
//! only in the local node's own storage until an operator explicitly
//! reconciles them back into the replicated state once quorum returns
//! (ADR 0028 §4).
//!
//! This crate provides only the shared, subsystem-agnostic pieces:
//!
//! - [`LocalEmergencyStore`] — the storage trait candidates are written through
//! - [`key`] — the `_local:<subsystem>:<scope_id>:emergency:<rotation_id>`
//!   namespace key-builders, so every backend and every subsystem agrees on the
//!   same layout
//! - [`EmergencyCandidate`] — the record shape stored per rotation attempt
//! - [`Subsystem`] — the two ADR 0028 instantiations
//!
//! Subsystem-specific logic (key generation, DEK re-encryption sweeps,
//! reconciliation-to-Raft) lives in the consuming crates
//! (`oauth2-key-driver-raft`, `storage`), which depend on this crate rather
//! than duplicating the namespace/guardrail/gossip plumbing.

pub mod gossip;
mod guardrail;
pub mod key;
mod mock;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use gossip::{GossipOutcome, decide_gossip_outcome};
pub use guardrail::{GuardrailConfig, LeaderlessTracker, is_quorum_bypass_allowed};
pub use mock::InMemoryLocalEmergencyStore;

/// The two ADR 0028 subsystem instantiations.
///
/// Deliberately a closed enum, not a free-form string: every namespace
/// segment must be agreed on ahead of time so gossip/reconciliation code
/// never has to guess how to interpret an unrecognized subsystem tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Subsystem {
    /// OAuth2 signing-key emergency rotation (amends ADR 0026 §3).
    Oauth2SigningKey,
    /// DEK emergency rotation (amends ADR 0016-v2 §6.2).
    Dek,
}

impl Subsystem {
    /// The namespace segment used in local emergency store keys.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Oauth2SigningKey => "oauth2_signing_key",
            Self::Dek => "dek",
        }
    }
}

/// A single locally-written emergency rotation candidate.
///
/// The `payload` is opaque to this crate — subsystem crates serialize their
/// own candidate shape (e.g. the staged signing key, or the wrapped DEK)
/// into it. Only bookkeeping fields needed by the shared guardrail, gossip,
/// and reconciliation logic are typed here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyCandidate {
    /// Subsystem this candidate belongs to.
    pub subsystem: Subsystem,
    /// Scope the rotation applies to (e.g. domain id).
    pub scope_id: String,
    /// Unique id for this rotation attempt, chosen by the initiating
    /// operator/CLI invocation.
    pub rotation_id: String,
    /// Opaque, subsystem-serialized candidate payload.
    pub payload: Vec<u8>,
    /// Identity of the operator who staged this candidate (from the SPIFFE
    /// identity on the admin UDS connection, never from request body).
    pub initiator: String,
    /// Mandatory operator-supplied justification for the bypass
    /// (ADR 0028 §1).
    pub justification: String,
    /// When this candidate was written.
    pub created_at: DateTime<Utc>,
    /// Set once reconciliation determines this candidate lost to a
    /// conflicting candidate from another node (ADR 0028 §4). A revoked
    /// candidate is retained for operator visibility/audit but must never be
    /// promoted.
    pub revoked: bool,
    /// `None` if this candidate was staged locally on the node that is
    /// currently storing it; `Some(node_id)` if it arrived via gossip from
    /// another node (ADR 0028 §5).
    #[serde(default)]
    pub origin_node_id: Option<u64>,
    /// Set when gossip observes another node holding an active candidate
    /// for the same `(subsystem, scope_id)` with a different `rotation_id`
    /// (`LOCAL_EMERGENCY_CONFLICT`, ADR 0028 §5). Surfaced to operators so
    /// reconciliation (ADR 0028 §6) can make an explicit choice rather than
    /// silently picking one side.
    #[serde(default)]
    pub conflicted: bool,
}

/// Errors returned by [`LocalEmergencyStore`] implementations.
#[derive(Error, Debug)]
pub enum LocalEmergencyStoreError {
    /// A candidate already exists for this exact
    /// `(subsystem, scope_id, rotation_id)` triple.
    #[error("emergency candidate already exists: {0}")]
    AlreadyExists(String),

    /// No candidate exists for this key.
    #[error("no emergency candidate found: {0}")]
    NotFound(String),

    /// Implementation-specific storage failure (Fjall I/O, etc).
    #[error("{0}")]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl LocalEmergencyStoreError {
    /// Wrap an implementation-specific error into [`Self::Other`].
    pub fn other<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self::Other(err.into())
    }
}

/// Storage trait for the node-local emergency write path.
///
/// Implementations must never route writes through Raft/`StorageApi` — that
/// would defeat the purpose of a quorum-bypass path. The reference
/// production implementation (Phase 2 of the ADR 0028 implementation plan)
/// wraps a dedicated Fjall keyspace opened directly off the same
/// `fjall::Database` handle `StateMachineStore` uses, but never touched by
/// its `apply()`.
#[async_trait]
pub trait LocalEmergencyStore: Send + Sync {
    /// Write a new candidate. Fails with
    /// [`LocalEmergencyStoreError::AlreadyExists`] if the same
    /// `(subsystem, scope_id, rotation_id)` triple is already present —
    /// callers must pick a fresh `rotation_id` per attempt, never overwrite.
    async fn put_candidate(
        &self,
        candidate: EmergencyCandidate,
    ) -> Result<(), LocalEmergencyStoreError>;

    /// Fetch a single candidate by its full key.
    async fn get_candidate(
        &self,
        subsystem: Subsystem,
        scope_id: &str,
        rotation_id: &str,
    ) -> Result<Option<EmergencyCandidate>, LocalEmergencyStoreError>;

    /// List every candidate (including revoked ones) for a given
    /// subsystem/scope, e.g. to detect that two operators raced and staged
    /// conflicting candidates on different nodes (`LOCAL_EMERGENCY_CONFLICT`,
    /// ADR 0028 §3).
    async fn list_candidates(
        &self,
        subsystem: Subsystem,
        scope_id: &str,
    ) -> Result<Vec<EmergencyCandidate>, LocalEmergencyStoreError>;

    /// List every candidate for a subsystem across all scopes, e.g. so a
    /// background gossip sweep (ADR 0028 §5) can find every locally-staged
    /// candidate without needing to know which scopes (domains) exist.
    async fn list_candidates_for_subsystem(
        &self,
        subsystem: Subsystem,
    ) -> Result<Vec<EmergencyCandidate>, LocalEmergencyStoreError>;

    /// Mark a candidate as revoked (lost reconciliation to another
    /// candidate). The record is kept, not deleted, so operators and audit
    /// tooling retain visibility into what was rejected and why.
    async fn revoke_candidate(
        &self,
        subsystem: Subsystem,
        scope_id: &str,
        rotation_id: &str,
    ) -> Result<(), LocalEmergencyStoreError>;

    /// Mark a candidate as conflicted: gossip observed another node with an
    /// active candidate for the same `(subsystem, scope_id)` but a different
    /// `rotation_id` (ADR 0028 §5). Does not revoke it — reconciliation (ADR
    /// 0028 §6) makes the explicit choice between conflicting candidates.
    async fn mark_conflicted(
        &self,
        subsystem: Subsystem,
        scope_id: &str,
        rotation_id: &str,
    ) -> Result<(), LocalEmergencyStoreError>;

    /// Permanently remove a candidate. Only valid once reconciliation has
    /// promoted it into a committed Raft rotation (or once it is revoked and
    /// no longer needed for audit) — this is local storage housekeeping, not
    /// a state-machine mutation.
    async fn clear_candidate(
        &self,
        subsystem: Subsystem,
        scope_id: &str,
        rotation_id: &str,
    ) -> Result<(), LocalEmergencyStoreError>;

    /// Record the CADF audit event id emitted for a reconciled `rotation_id`
    /// (ADR 0028 implementation plan, design gap 2), at
    /// [`key::audit_pointer_key`]. Lets reconciliation/audit tooling find
    /// the spool entry for a given rotation without scanning the whole
    /// audit spool -- the event id itself is an opaque, unrelated UUID
    /// minted at emission time, not derivable from `rotation_id`.
    async fn put_audit_pointer(
        &self,
        rotation_id: &str,
        event_id: &str,
    ) -> Result<(), LocalEmergencyStoreError>;

    /// Fetch the audit event id previously recorded for `rotation_id`, if
    /// any.
    async fn get_audit_pointer(
        &self,
        rotation_id: &str,
    ) -> Result<Option<String>, LocalEmergencyStoreError>;
}
