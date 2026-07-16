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
//! # OAuth2 signing key provider error

use thiserror::Error;

use crate::error::BuilderError;

/// OAuth2 per-domain signing key provider error (ADR 0026 §3).
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Oauth2KeyProviderError {
    /// Asymmetric keypair generation, DER encoding, or JWK conversion
    /// failed.
    #[error("OAuth2 signing key cryptographic operation failed: {0}")]
    Crypto(String),

    /// No signing keys are present for the requested domain (not yet
    /// provisioned, or the domain does not exist).
    #[error("no OAuth2 signing keys found for domain {0}")]
    NotFound(String),

    /// Raft storage is not available for the OAuth2 signing key provider.
    #[error("raft storage is not available in the oauth2 key provider")]
    RaftNotAvailable,

    /// Raft storage error.
    #[error("raft storage error in the oauth2 key provider: {source}")]
    RaftStoreError {
        /// The source of the error.
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder {
        /// The source of the error.
        #[from]
        source: Box<BuilderError>,
    },

    /// Unsupported driver.
    #[error("unsupported driver `{0}` for the oauth2 key provider")]
    UnsupportedDriver(String),

    /// No pending emergency rotation exists for this `rotation_id`
    /// (ADR 0026 §3, Emergency Rotation).
    #[error("no pending emergency rotation with id {0}")]
    NoPendingRotation(String),

    /// The pending emergency rotation's 15-minute confirmation window has
    /// elapsed.
    #[error("pending emergency rotation {0} has expired")]
    RotationExpired(String),

    /// The confirming operator was the same identity that staged the
    /// rotation (ADR 0026 §3 dual-control requirement).
    #[error("the confirming operator must differ from the initiating operator")]
    DualControlViolation,

    /// A pending emergency rotation already exists for this domain and
    /// hasn't expired. Staging a second one would silently orphan the
    /// first's `rotation_id`.
    #[error("an emergency rotation (id {0}) is already pending for this domain")]
    EmergencyRotationAlreadyPending(String),

    /// `--local-quorum-bypass` was requested but the node's quorum-bypass
    /// guardrail refused it (ADR 0028 §1): either `[local_emergency]` is
    /// disabled on this node, or Raft quorum is currently reachable, or the
    /// leaderless grace period has not yet elapsed.
    #[error("local quorum-bypass emergency rotation is not permitted on this node right now")]
    LocalEmergencyBypassNotAllowed,

    /// A local (non-revoked) emergency rotation candidate already exists for
    /// this domain on this node (ADR 0028 §2). Staging a second one would
    /// make reconciliation ambiguous about which candidate the operator
    /// meant.
    #[error(
        "a local emergency rotation candidate (id {0}) already exists for this domain on this node"
    )]
    LocalEmergencyAlreadyStaged(String),

    /// The local emergency store rejected the write (Fjall I/O, etc).
    #[error("local emergency store error in the oauth2 key provider: {source}")]
    LocalEmergencyStoreError {
        /// The source of the error.
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// No local emergency rotation candidate exists with this `rotation_id`
    /// on this node (ADR 0028 §6). Reconciliation must be run against the
    /// specific node that holds the chosen candidate.
    #[error("no local emergency rotation candidate with id {0} on this node")]
    LocalEmergencyCandidateNotFound(String),

    /// The chosen candidate was already revoked (e.g. it lost a prior
    /// reconciliation or gossip conflict) and must never be promoted
    /// (ADR 0028 §6).
    #[error("local emergency rotation candidate {0} has been revoked and cannot be reconciled")]
    LocalEmergencyCandidateRevoked(String),
}

impl Oauth2KeyProviderError {
    /// Wrap a crypto error.
    pub fn crypto<E>(source: E) -> Self
    where
        E: std::fmt::Display,
    {
        Self::Crypto(source.to_string())
    }

    /// Wrap a raft storage error.
    pub fn raft<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::RaftStoreError {
            source: Box::new(source),
        }
    }

    /// Wrap a local emergency store error (ADR 0028).
    pub fn local_emergency<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::LocalEmergencyStoreError {
            source: Box::new(source),
        }
    }
}

impl From<BuilderError> for Oauth2KeyProviderError {
    fn from(value: BuilderError) -> Self {
        Self::StructBuilder {
            source: Box::new(value),
        }
    }
}
