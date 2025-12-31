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

use std::num::TryFromIntError;

use thiserror::Error;

use crate::error::{BuilderError, DatabaseError};

/// Token provider error.
#[derive(Error, Debug)]
pub enum TokenProviderError {
    /// Actor has no roles on the target scope.
    #[error("actor has no roles on scope")]
    ActorHasNoRolesOnTarget,

    /// Application Credential used in the token is not found.
    #[error("application credential with id: {0} not found")]
    ApplicationCredentialNotFound(String),

    /// Application Credential has expired.
    #[error("application credential has expired")]
    ApplicationCredentialExpired,

    /// Application credential provider error.
    #[error(transparent)]
    ApplicationCredentialProvider {
        /// The source of the error.
        #[from]
        source: crate::application_credential::error::ApplicationCredentialProviderError,
    },

    /// Application Credential is bound to the other project.
    #[error("application credential is bound to another project")]
    ApplicationCredentialScopeMismatch,

    #[error(transparent)]
    AssignmentProvider {
        /// The source of the error.
        #[from]
        source: crate::assignment::error::AssignmentProviderError,
    },

    /// AuditID must be urlsafe base64 encoded value.
    #[error("audit_id must be urlsafe base64 encoded value")]
    AuditIdWrongFormat,

    #[error(transparent)]
    AuthenticationInfo(#[from] crate::auth::AuthenticationError),

    #[error("b64 decryption error")]
    Base64Decode(#[from] base64::DecodeError),

    /// Conflict
    #[error("{message}")]
    Conflict { message: String, context: String },

    /// Database error.
    #[error(transparent)]
    Database(#[from] DatabaseError),

    /// The domain is disabled.
    #[error("domain is disabled")]
    DomainDisabled(String),

    /// Expired token
    #[error("token expired")]
    Expired,

    /// Expired token
    #[error("token expiry calculation failed")]
    ExpiryCalculation,

    #[error("federated payload must contain idp_id and protocol_id")]
    FederatedPayloadMissingData,

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
    FernetDecryption(#[from] fernet::DecryptionError),

    /// Missing fernet keys
    #[error("no usable fernet keys has been found")]
    FernetKeysMissing,

    #[error(transparent)]
    IdentityProvider(#[from] crate::identity::error::IdentityProviderError),

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

    /// IO error.
    #[error("io error: {}", source)]
    Io {
        /// The source of the error.
        #[from]
        source: std::io::Error,
    },

    /// Nix errno.
    #[error("unix error {source} while {context}")]
    NixErrno {
        /// Context.
        context: String,
        /// The source of the error.
        source: nix::errno::Errno,
    },

    /// tempfile persisting error
    #[error(transparent)]
    Persist(#[from] tempfile::PersistError),

    /// The project is disabled.
    #[error("project disabled")]
    ProjectDisabled(String),

    #[error(transparent)]
    ResourceProvider(#[from] crate::resource::error::ResourceProviderError),

    #[error("token with restrictions can be only project scoped")]
    RestrictedTokenNotProjectScoped,

    /// Revoke Provider error.
    #[error(transparent)]
    RevokeProvider(#[from] crate::revoke::error::RevokeProviderError),

    /// MSGPack Decryption
    #[error("rmp value error")]
    RmpValueRead(#[from] rmp::decode::ValueReadError),

    /// MSGPack Encryption
    #[error("rmp value encoding error")]
    RmpEncode(String),

    /// Target scope information is not found in the token.
    #[error("scope information missing")]
    ScopeMissing,

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder(#[from] BuilderError),

    /// Target subject information is not found in the token.
    #[error("subject information missing")]
    SubjectMissing,

    /// Fernet payload timestamp overflow error.
    #[error("fernet payload timestamp overflow ({value}): {}", source)]
    TokenTimestampOverflow {
        /// Token timestamp.
        value: u64,
        /// The source of the error.
        source: std::num::TryFromIntError,
    },

    #[error("token restriction {0} not found")]
    TokenRestrictionNotFound(String),

    /// Revoked token
    #[error("token has been revoked")]
    TokenRevoked,

    #[error("int parse")]
    TryFromIntError(#[from] TryFromIntError),

    /// Trust provider error.
    #[error(transparent)]
    TrustProvider(#[from] crate::trust::TrustError),

    /// The user is disabled.
    #[error("user disabled")]
    UserDisabled(String),

    #[error("user cannot be found: {0}")]
    UserNotFound(String),

    #[error("unsupported authentication methods {0} in token payload")]
    UnsupportedAuthMethods(String),

    #[error("uuid decryption error")]
    Uuid(#[from] uuid::Error),

    #[error("Token validation error: {0}")]
    Validation(#[from] validator::ValidationErrors),
}
