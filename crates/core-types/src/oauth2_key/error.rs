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
}

impl From<BuilderError> for Oauth2KeyProviderError {
    fn from(value: BuilderError) -> Self {
        Self::StructBuilder {
            source: Box::new(value),
        }
    }
}
