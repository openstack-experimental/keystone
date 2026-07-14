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
//! # OAuth2 session provider error

use thiserror::Error;

/// OAuth2 browser session provider error (ADR 0026 §10 Phase 4).
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Oauth2SessionProviderError {
    /// The referenced pre-auth session, authorization code, or refresh
    /// token was not found (never existed, already consumed, or expired).
    #[error("oauth2 session record {0} not found")]
    NotFound(String),

    /// Raft storage is not available for the OAuth2 session provider.
    #[error("raft storage is not available in the oauth2 session provider")]
    RaftNotAvailable,

    /// Raft storage error.
    #[error("raft storage error in the oauth2 session provider: {source}")]
    RaftStoreError {
        /// The source of the error.
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Unsupported driver.
    #[error("unsupported driver `{0}` for the oauth2 session provider")]
    UnsupportedDriver(String),
}

impl Oauth2SessionProviderError {
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
