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
use crate::token::TokenProviderError;

/// K8s auth provider error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum K8sAuthProviderError {
    /// K8s auth instance disabled.
    #[error("k8s instance {0} not active")]
    AuthInstanceNotActive(String),

    /// K8s auth instance not found.
    #[error("k8s instance {0} not found")]
    AuthInstanceNotFound(String),

    /// K8s CA certificate is unknown.
    #[error("CA certificate of the k8s cannot be identified")]
    CaCertificateUnknown,

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

    /// JWT error.
    #[error("jwt validation error: {source}")]
    Jwt {
        /// The source of the error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// JWT audience mismatch.
    #[error("audience mismatch")]
    AudienceMismatch,

    /// Expired token.
    #[error("expired token")]
    ExpiredToken,

    /// Http client error.
    #[error("{}", source)]
    Http {
        /// The source of the error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Insecure JWT signature algorithm.
    #[error("insecure jwt signature algorithm")]
    InsecureAlgorithm,

    /// Invalid token.
    #[error("invalid token")]
    InvalidToken,

    /// Mapping engine error.
    #[error("mapping engine error: {0}")]
    MappingEngine(String),

    /// Invalid token review response.
    #[error("invalid token review response")]
    InvalidTokenReviewResponse,

    /// Raft storage is not available.
    #[error("raft storage is not available in the k8s_auth provider")]
    RaftNotAvailable,

    /// Raft storage error.
    #[error("raft storage error in the k8s_auth provider")]
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

    /// Token provider error.
    #[error(transparent)]
    TokenProvider {
        /// The source of the error.
        #[from]
        source: Box<TokenProviderError>,
    },

    /// Unsupported driver.
    #[error("unsupported driver `{0}` for the k8s provider")]
    UnsupportedDriver(String),
}

impl K8sAuthProviderError {
    pub fn jwt<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Jwt {
            source: Box::new(source),
        }
    }

    pub fn http<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Http {
            source: Box::new(source),
        }
    }

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

impl From<TokenProviderError> for K8sAuthProviderError {
    fn from(value: TokenProviderError) -> Self {
        Self::TokenProvider {
            source: Box::new(value),
        }
    }
}

impl From<BuilderError> for K8sAuthProviderError {
    fn from(value: BuilderError) -> Self {
        Self::StructBuilder {
            source: Box::new(value),
        }
    }
}
