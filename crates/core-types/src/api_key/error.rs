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
//! # API Key provider error

use thiserror::Error;

use crate::auth::AuthenticationError;
use crate::error::BuilderError;

/// API Key (`ApiClientResource`) provider error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ApiKeyProviderError {
    /// Authentication error.
    #[error(transparent)]
    Authentication {
        /// The source of the error.
        #[from]
        source: AuthenticationError,
    },

    /// API key not found.
    #[error("API key {0} not found")]
    NotFound(String),

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Argon2id hashing or verification error (token generation, secret
    /// hashing, lazy re-hash). Stored as a message rather than a boxed
    /// source because `argon2::password_hash::Error` does not implement
    /// `std::error::Error` (the crate targets `no_std`).
    #[error("crypto error in the api_key provider: {0}")]
    Crypto(String),

    /// Raft storage is not available for the API Key provider.
    #[error("raft storage is not available in the api_key provider")]
    RaftNotAvailable,

    /// Raft storage error.
    #[error("raft storage error in the api_key provider: {source}")]
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
    #[error("unsupported driver `{0}` for the api_key provider")]
    UnsupportedDriver(String),
}

impl ApiKeyProviderError {
    /// Wrap a raft storage error.
    pub fn raft<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::RaftStoreError {
            source: Box::new(source),
        }
    }

    /// Wrap a crypto (Argon2id) error.
    pub fn crypto<E>(source: E) -> Self
    where
        E: std::fmt::Display,
    {
        Self::Crypto(source.to_string())
    }
}

impl From<BuilderError> for ApiKeyProviderError {
    fn from(value: BuilderError) -> Self {
        Self::StructBuilder {
            source: Box::new(value),
        }
    }
}
