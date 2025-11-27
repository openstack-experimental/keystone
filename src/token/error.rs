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
//! Token provider errors.

use sea_orm::SqlErr;
use std::num::TryFromIntError;

use thiserror::Error;

/// Token provider error.
#[derive(Error, Debug)]
pub enum TokenProviderError {
    /// IO error.
    #[error("io error: {}", source)]
    Io {
        /// The source of the error.
        #[from]
        source: std::io::Error,
    },

    /// Fernet payload timestamp overflow error.
    #[error("fernet payload timestamp overflow ({value}): {}", source)]
    TokenTimestampOverflow {
        /// Token timestamp.
        value: u64,
        /// The source of the error.
        source: std::num::TryFromIntError,
    },

    /// Fernet key read error.
    #[error("fernet key read error: {}", source)]
    FernetKeyRead {
        /// The source of the error.
        source: std::io::Error,
        /// Key file name.
        path: std::path::PathBuf,
    },

    /// Fernet Decryption
    #[error("fernet decryption error")]
    FernetDecryption {
        /// The source of the error.
        #[from]
        source: fernet::DecryptionError,
    },

    /// Missing fernet keys
    #[error("no usable fernet keys has been found")]
    FernetKeysMissing,

    /// Invalid token data
    #[error("invalid token error")]
    InvalidToken,

    /// Unsupported token version
    #[error("token version {0} is not supported")]
    InvalidTokenType(u8),
    ///
    /// Unsupported token uuid
    #[error("token uuid is not supported")]
    InvalidTokenUuid,

    /// Unsupported token uuid coding
    #[error("token uuid coding {0:?} is not supported")]
    InvalidTokenUuidMarker(rmp::Marker),

    /// Expired token
    #[error("token expired")]
    Expired,

    /// Expired token
    #[error("token expiry calculation failed")]
    ExpiryCalculation,

    /// MSGPack Decryption
    #[error("rmp value error")]
    RmpValueRead {
        /// The source of the error.
        #[from]
        source: rmp::decode::ValueReadError,
    },

    /// MSGPack Encryption
    #[error("rmp value encoding error")]
    RmpEncode(String),

    #[error("b64 decryption error")]
    Base64Decode {
        /// The source of the error.
        #[from]
        source: base64::DecodeError,
    },

    #[error("uuid decryption error")]
    Uuid {
        /// The source of the error.
        #[from]
        source: uuid::Error,
    },

    #[error("int parse")]
    TryFromIntError {
        /// The source of the error.
        #[from]
        source: TryFromIntError,
    },

    #[error(transparent)]
    UnscopedBuilder {
        /// The source of the error.
        #[from]
        source: crate::token::types::unscoped::UnscopedPayloadBuilderError,
    },

    #[error(transparent)]
    ProjectScopeBuilder {
        /// The source of the error.
        #[from]
        source: crate::token::types::project_scoped::ProjectScopePayloadBuilderError,
    },

    #[error(transparent)]
    DomainScopeBuilder {
        /// The source of the error.
        #[from]
        source: crate::token::types::domain_scoped::DomainScopePayloadBuilderError,
    },

    #[error(transparent)]
    FederationUnscopedBuilder {
        /// The source of the error.
        #[from]
        source: crate::token::types::federation_unscoped::FederationUnscopedPayloadBuilderError,
    },

    #[error(transparent)]
    FederationProjectScopeBuilder {
        /// The source of the error.
        #[from]
        source: crate::token::types::federation_project_scoped::FederationProjectScopePayloadBuilderError,
    },

    #[error(transparent)]
    FederationDomainScopeBuilder {
        /// The source of the error.
        #[from]
        source: crate::token::types::federation_domain_scoped::FederationDomainScopePayloadBuilderError,
    },

    #[error(transparent)]
    RestrictedBuilder {
        /// The source of the error.
        #[from]
        source: crate::token::types::restricted::RestrictedPayloadBuilderError,
    },

    #[error(transparent)]
    AssignmentProvider {
        /// The source of the error.
        #[from]
        source: crate::assignment::error::AssignmentProviderError,
    },

    #[error(transparent)]
    AuthenticationInfo {
        #[from]
        source: crate::auth::AuthenticationError,
    },

    #[error(transparent)]
    IdentityProvider {
        /// The source of the error.
        #[from]
        source: crate::identity::error::IdentityProviderError,
    },

    #[error(transparent)]
    ResourceProvider {
        /// The source of the error.
        #[from]
        source: crate::resource::error::ResourceProviderError,
    },

    /// Revoke Provider error.
    #[error(transparent)]
    RevokeProvider {
        /// The source of the error.
        #[from]
        source: crate::revoke::error::RevokeProviderError,
    },

    #[error("actor has no roles on scope")]
    ActorHasNoRolesOnTarget,

    #[error("federated payload must contain idp_id and protocol_id")]
    FederatedPayloadMissingData,

    #[error("user cannot be found: {0}")]
    UserNotFound(String),

    #[error("unsupported authentication methods {0} in token payload")]
    UnsupportedAuthMethods(String),

    #[error("token with restrictions can be only project scoped")]
    RestrictedTokenNotProjectScoped,

    #[error("token restriction {0} not found")]
    TokenRestrictionNotFound(String),

    /// Revoked token
    #[error("token has been revoked")]
    TokenRevoked,

    /// Conflict
    #[error("{message}")]
    Conflict { message: String, context: String },

    /// SqlError
    #[error("{message}")]
    Sql { message: String, context: String },

    #[error("Database error while {context}")]
    Database {
        source: sea_orm::DbErr,
        context: String,
    },

    /// AuditID must be urlsafe base64 encoded value.
    #[error("audit_id must be urlsafe base64 encoded value")]
    AuditIdWrongFormat,
}

/// Convert the DB error into the TokenProviderError with the context
/// information.
pub fn db_err(e: sea_orm::DbErr, context: &str) -> TokenProviderError {
    e.sql_err().map_or_else(
        || TokenProviderError::Database {
            source: e,
            context: context.to_string(),
        },
        |err| match err {
            SqlErr::UniqueConstraintViolation(descr) => TokenProviderError::Conflict {
                message: descr.to_string(),
                context: context.to_string(),
            },
            SqlErr::ForeignKeyConstraintViolation(descr) => TokenProviderError::Conflict {
                message: descr.to_string(),
                context: context.to_string(),
            },
            other => TokenProviderError::Sql {
                message: other.to_string(),
                context: context.to_string(),
            },
        },
    )
}
