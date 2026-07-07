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
//! # SCIM realm provider error

use thiserror::Error;

use crate::error::BuilderError;

/// SCIM realm (`ScimRealmResource`) provider error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ScimRealmProviderError {
    /// Realm not found.
    #[error("SCIM realm for provider `{0}` not found")]
    NotFound(String),

    /// Conflict — a realm already exists for this `(domain_id, provider_id)`.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Driver error.
    #[error("backend driver error: {source}")]
    Driver {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Raft storage is not available.
    #[error("raft storage is not available in the scim_realm provider")]
    RaftNotAvailable,

    /// Raft storage error.
    #[error("raft storage error in the scim_realm provider: {source}")]
    RaftStoreError {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder(#[from] Box<BuilderError>),

    /// Unsupported driver.
    #[error("unsupported driver `{0}` for the scim_realm provider")]
    UnsupportedDriver(String),
}

impl ScimRealmProviderError {
    /// Wrap a raft storage error.
    pub fn raft<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::RaftStoreError {
            source: Box::new(source),
        }
    }

    /// Wrap a generic driver error.
    pub fn driver<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Driver {
            source: Box::new(source),
        }
    }
}

impl From<BuilderError> for ScimRealmProviderError {
    fn from(value: BuilderError) -> Self {
        Self::StructBuilder(Box::new(value))
    }
}

/// SCIM resource ownership index (`ScimResourceIndex`) provider error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ScimResourceProviderError {
    /// No ownership anchor found for the given coordinate.
    #[error("SCIM resource index for `{0}` not found")]
    NotFound(String),

    /// Conflict — e.g. the `externalId` is already claimed within this
    /// realm (ADR 0024 §3.C/§3.D).
    #[error("conflict: {0}")]
    Conflict(String),

    /// `If-Match` precondition failed — the caller's expected `version`
    /// doesn't match the resource's current one, either because it was
    /// already stale when read, or because a concurrent write won the race
    /// between this write's read and its compare-and-swap (ADR 0024 §5.E).
    #[error("ETag precondition failed: {0}")]
    VersionMismatch(String),

    /// Driver error.
    #[error("backend driver error: {source}")]
    Driver {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Raft storage is not available.
    #[error("raft storage is not available in the scim_resource provider")]
    RaftNotAvailable,

    /// Raft storage error.
    #[error("raft storage error in the scim_resource provider: {source}")]
    RaftStoreError {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder(#[from] Box<BuilderError>),

    /// Unsupported driver.
    #[error("unsupported driver `{0}` for the scim_resource provider")]
    UnsupportedDriver(String),
}

impl ScimResourceProviderError {
    /// Wrap a raft storage error.
    pub fn raft<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::RaftStoreError {
            source: Box::new(source),
        }
    }

    /// Wrap a generic driver error.
    pub fn driver<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Driver {
            source: Box::new(source),
        }
    }
}

impl From<BuilderError> for ScimResourceProviderError {
    fn from(value: BuilderError) -> Self {
        Self::StructBuilder(Box::new(value))
    }
}
