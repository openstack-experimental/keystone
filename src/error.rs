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
//! # Error
//!
//! Diverse errors that can occur during the Keystone processing (not the API).
use thiserror::Error;

use crate::assignment::error::*;
use crate::catalog::error::*;
use crate::federation::error::*;
use crate::identity::error::*;
use crate::policy::*;
use crate::resource::error::*;
use crate::revoke::error::*;
use crate::token::TokenProviderError;

/// Keystone error.
#[derive(Debug, Error)]
pub enum KeystoneError {
    #[error(transparent)]
    AssignmentError {
        #[from]
        source: AssignmentProviderError,
    },

    #[error(transparent)]
    CatalogError {
        #[from]
        source: CatalogProviderError,
    },

    #[error(transparent)]
    FederationError {
        #[from]
        source: FederationProviderError,
    },

    #[error(transparent)]
    IdentityError {
        #[from]
        source: IdentityProviderError,
    },

    #[error(transparent)]
    IO {
        #[from]
        source: std::io::Error,
    },

    #[error(transparent)]
    Policy {
        #[from]
        source: PolicyError,
    },

    /// Policy engine is not available.
    #[error("policy enforcement is requested, but not available with the enabled features")]
    PolicyEnforcementNotAvailable,

    #[error(transparent)]
    ResourceError {
        #[from]
        source: ResourceProviderError,
    },

    /// Revoke provider error.
    #[error(transparent)]
    RevokeProvider {
        /// The source of the error.
        #[from]
        source: RevokeProviderError,
    },

    #[error(transparent)]
    TokenProvider {
        #[from]
        source: TokenProviderError,
    },

    #[error("cloud {0} is not present in clouds.yaml")]
    CloudConfig(String),

    /// Json serialization error.
    #[error("json serde error: {}", source)]
    JsonError {
        /// The source of the error.
        #[from]
        source: serde_json::Error,
    },

    /// Url parsing error
    #[error(transparent)]
    UrlParse {
        #[from]
        source: url::ParseError,
    },

    /// WebauthN error.
    #[error("webauthn error: {}", source)]
    Webauthn {
        /// The source of the error.
        #[from]
        source: webauthn_rs::prelude::WebauthnError,
    },
}
