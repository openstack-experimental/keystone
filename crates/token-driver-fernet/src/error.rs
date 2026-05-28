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

use openstack_keystone_core::token::TokenProviderError;

/// Token provider error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum FernetDriverError {
    /// AuditID must be urlsafe base64 encoded value.
    #[error("audit_id must be urlsafe base64 encoded value")]
    AuditIdWrongFormat,

    /// Base64 Decode error.
    #[error("b64 decryption error")]
    Base64Decode(#[from] base64::DecodeError),

    /// Fernet Decryption.
    #[error("fernet decryption error")]
    FernetDecryption(#[from] fernet::DecryptionError),

    /// Missing fernet keys.
    #[error("no usable fernet keys has been found")]
    FernetKeysMissing,

    /// Fernet key read error.
    #[error("fernet key read error: {}", source)]
    FernetKeyRead {
        /// The source of the error.
        source: std::io::Error,
        /// Key file name.
        path: std::path::PathBuf,
    },

    /// Invalid token data.
    #[error("invalid token error")]
    InvalidToken,

    /// Unsupported token version.
    #[error("token version {0} is not supported")]
    InvalidTokenType(u8),

    /// Unsupported token uuid.
    #[error("token uuid is not supported")]
    InvalidTokenUuid,

    /// Unsupported token uuid coding.
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

    /// tempfile persisting error.
    #[error(transparent)]
    Persist(#[from] tempfile::PersistError),

    /// MSGPack Encryption.
    #[error("rmp value encoding error")]
    RmpEncode(String),

    /// MSGPack Decryption.
    #[error("rmp value error")]
    RmpValueRead(#[from] rmp::decode::ValueReadError),

    /// Fernet payload timestamp overflow error.
    #[error("fernet payload timestamp overflow ({value}): {}", source)]
    TokenTimestampOverflow {
        /// Token timestamp.
        value: u64,
        /// The source of the error.
        source: std::num::TryFromIntError,
    },

    /// Integer conversion error.
    #[error("int parse")]
    TryFromIntError(#[from] TryFromIntError),

    /// Unsupported authentication methods in token payload.
    #[error("unsupported authentication methods {0} in token payload")]
    UnsupportedAuthMethods(String),

    /// UUID decryption error.
    #[error("uuid decryption error")]
    Uuid(#[from] uuid::Error),

    /// Validation error.
    #[error("Token validation error: {0}")]
    Validation(#[from] validator::ValidationErrors),
}

impl From<FernetDriverError> for TokenProviderError {
    fn from(value: FernetDriverError) -> Self {
        Self::Driver {
            source: Box::new(value),
        }
    }
}
