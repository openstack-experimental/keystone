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
//! # Service grant provider error

use thiserror::Error;

use crate::error::BuilderError;

/// Service grant provider error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ServiceGrantProviderError {
    /// Service grant not found.
    #[error("service grant {0} not found")]
    NotFound(String),

    /// Conflict (e.g. a concurrent update changed the record).
    #[error("conflict: {0}")]
    Conflict(String),

    /// The request is invalid (unknown or ineligible client, roles outside
    /// the caller's own, lifetime above the client's ceiling, ...).
    #[error("{0}")]
    Validation(String),

    /// The caller may not create a grant (not a user, or a delegated
    /// authentication chain).
    #[error("{0}")]
    Forbidden(String),

    /// The deployment-wide grant backstop of the project is reached.
    #[error("{0}")]
    QuotaExceeded(String),

    /// Error from another provider (identity, resource, assignment, ...).
    #[error("{0}")]
    Provider(String),

    /// Raft storage is not available for the service grant provider.
    #[error("raft storage is not available in the service_grant provider")]
    RaftNotAvailable,

    /// Raft storage error.
    #[error("raft storage error in the service_grant provider: {source}")]
    RaftStoreError {
        /// The source of the error.
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Record (de)serialization error.
    #[error("serialization error in the service_grant provider: {0}")]
    Serialization(String),

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder {
        /// The source of the error.
        #[from]
        source: Box<BuilderError>,
    },

    /// The fail-closed audit record could not be written, so the operation
    /// was not performed.
    #[error("audit dispatch failed in the service_grant provider; operation not performed")]
    AuditUnavailable,

    /// Unsupported driver.
    #[error("unsupported driver `{0}` for the service_grant provider")]
    UnsupportedDriver(String),
}

impl ServiceGrantProviderError {
    /// Wrap a raft storage error.
    pub fn raft<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::RaftStoreError {
            source: Box::new(source),
        }
    }

    /// Wrap an error of another provider.
    pub fn provider<E>(source: E) -> Self
    where
        E: std::fmt::Display,
    {
        Self::Provider(source.to_string())
    }
}

impl From<BuilderError> for ServiceGrantProviderError {
    fn from(value: BuilderError) -> Self {
        Self::StructBuilder {
            source: Box::new(value),
        }
    }
}
