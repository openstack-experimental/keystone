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
//! # OAuth2 client provider error

use thiserror::Error;

use crate::error::BuilderError;

/// OAuth2 client (`OAuth2ClientResource`) provider error (ADR 0026 §5).
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Oauth2ClientProviderError {
    /// Conflict (`provider_id` already registered in the domain, or
    /// `client_id` collision).
    #[error("conflict: {0}")]
    Conflict(String),

    /// Argon2id hashing error (client secret generation/hashing). Stored as
    /// a message rather than a boxed source because
    /// `argon2::password_hash::Error` does not implement
    /// `std::error::Error` (the crate targets `no_std`).
    #[error("crypto error in the oauth2 client provider: {0}")]
    Crypto(String),

    /// OAuth2 client not found.
    #[error("OAuth2 client {0} not found")]
    NotFound(String),

    /// Raft storage is not available for the OAuth2 client provider.
    #[error("raft storage is not available in the oauth2 client provider")]
    RaftNotAvailable,

    /// Raft storage error.
    #[error("raft storage error in the oauth2 client provider: {source}")]
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
    #[error("unsupported driver `{0}` for the oauth2 client provider")]
    UnsupportedDriver(String),

    /// Request validation error (redirect URI scheme, PKCE requirement,
    /// reserved claim template key).
    #[error("validation error in the oauth2 client provider: {0}")]
    Validation(String),
}

impl Oauth2ClientProviderError {
    /// Wrap a crypto (Argon2id) error.
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

impl From<BuilderError> for Oauth2ClientProviderError {
    fn from(value: BuilderError) -> Self {
        Self::StructBuilder {
            source: Box::new(value),
        }
    }
}
