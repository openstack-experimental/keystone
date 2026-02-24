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

/// K8s auth provider error.
#[derive(Error, Debug)]
pub enum K8sAuthProviderError {
    /// Role audience does not match.
    #[error("role `bound_audience` does not match")]
    AudienceMismatch,

    /// K8s CA certificate is unknown.
    #[error("CA certificate of the k8s cannot be identified")]
    CaCertificateUnknown,

    /// K8s auth configuration disabled.
    #[error("k8s configuration {0} not active")]
    ConfigurationNotActive(String),

    /// K8s auth configuration not found.
    #[error("k8s configuration {0} not found")]
    ConfigurationNotFound(String),

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

    /// Service account name of the token not matching the
    /// `bound_service_account_names`.
    #[error("invalid service account name of the token")]
    FailedBoundServiceAccountName(String),

    /// Service account name of the token not matching the
    /// `bound_service_account_namespaces`.
    #[error("invalid service account namespace of the token")]
    FailedBoundServiceAccountNamespace(String),

    /// JWT error.
    #[error("jwt validation error: {source}")]
    Jwt {
        /// The source of the error.
        #[from]
        source: jsonwebtoken::errors::Error,
    },

    /// Expired token.
    #[error("expired token")]
    ExpiredToken,

    /// Http client error.
    #[error(transparent)]
    Http {
        /// The source of the error.
        #[from]
        source: reqwest::Error,
    },

    /// Identity provider error.
    #[error(transparent)]
    IdentityProvider {
        /// The source of the error.
        #[from]
        source: crate::identity::error::IdentityProviderError,
    },

    /// Insecure JWT signature algorithm.
    #[error("insecure jwt signature algorithm")]
    InsecureAlgorithm,

    /// Invalid token.
    #[error("invalid token")]
    InvalidToken,

    /// Invalid token review response.
    #[error("invalid token review response")]
    InvalidTokenReviewResponse,

    /// K8s auth role not found.
    #[error("k8s role {0} not found")]
    RoleNotFound(String),

    /// K8s auth role not active.
    #[error("k8s role {0} not active")]
    RoleNotActive(String),

    /// Role is bound to the other configuration.
    #[error("k8s role {0} belongs to the other configuration")]
    RoleConfigurationOwnershipMismatch(String),

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder {
        /// The source of the error.
        #[from]
        source: BuilderError,
    },

    /// Token provider error.
    #[error(transparent)]
    TokenProvider {
        /// The source of the error.
        #[from]
        source: crate::token::TokenProviderError,
    },

    /// Token restriction not found.
    #[error("token restriction {0} not found")]
    TokenRestrictionNotFound(String),

    /// Token restriction MUST specify the `user_id`.
    #[error("token restriction must specify `user_id`")]
    TokenRestrictionMustSpecifyUserId,

    /// Unsupported driver.
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),

    /// User not found.
    #[error("user {0} not found")]
    UserNotFound(String),

    /// User disabled.
    #[error("user {0} disabled")]
    UserDisabled(String),
}
