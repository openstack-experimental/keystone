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
//! Mapping provider error type.

use thiserror::Error;
use validator::ValidationErrors;

use crate::error::BuilderError;

/// Mapping provider error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum MappingProviderError {
    /// Mapping not found.
    #[error("mapping ruleset `{0}` is not found")]
    NotFound(String),

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Driver error.
    #[error("backend driver error: {source}")]
    Driver {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Raft storage is not available.
    #[error("raft storage is not available in the mapping provider")]
    RaftNotAvailable,

    /// Raft storage error.
    #[error("raft storage error in the mapping provider: {source}")]
    RaftStoreError {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder(#[from] Box<BuilderError>),

    /// Unsupported driver.
    #[error("unsupported driver `{0}` for the mapping provider")]
    UnsupportedDriver(String),

    /// Request validation error.
    #[error("request validation error: {source}")]
    Validation {
        #[source]
        source: ValidationErrors,
    },
}

impl MappingProviderError {
    /// Create a Raft storage error.
    pub fn raft<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::RaftStoreError {
            source: Box::new(source),
        }
    }
}

impl From<ValidationErrors> for MappingProviderError {
    fn from(value: ValidationErrors) -> Self {
        Self::Validation { source: value }
    }
}
