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
//! # K8s Auth error

use thiserror::Error;

use crate::error::BuilderError;

/// Spiffe provider error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum SpiffeProviderError {
    /// Binding not found.
    #[error("SVID binding is not found")]
    BindingNotFound(String),

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Driver error.
    #[error("backend driver error: {source}")]
    Driver {
        /// The source of the error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Raft storage is not available.
    #[error("raft storage is not available in the spiffe identity provider")]
    RaftNotAvailable,

    /// Raft storage error.
    #[error("raft storage error in the spiffe provider")]
    RaftStoreError {
        /// The source of the error.
        #[from]
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
    #[error("unsupported driver `{0}` for the spiffe provider")]
    UnsupportedDriver(String),
}

impl SpiffeProviderError {
    /// Raft storage error.
    pub fn raft<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::RaftStoreError {
            source: Box::new(source),
        }
    }
}

impl From<BuilderError> for SpiffeProviderError {
    fn from(value: BuilderError) -> Self {
        Self::StructBuilder {
            source: Box::new(value),
        }
    }
}
