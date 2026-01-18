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
//! # WebAuthN Error
use thiserror::Error;

use crate::error::DatabaseError;

/// WebAuthN extension error.
#[derive(Error, Debug)]
pub enum WebauthnError {
    /// Supported authentication error.
    #[error(transparent)]
    AuthenticationInfo {
        /// The source of the error.
        #[from]
        source: crate::auth::AuthenticationError,
    },

    /// Base64 decode error
    #[error("base64 decoding error")]
    Base64Decode(#[from] base64::DecodeError),

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Counter violation
    #[error("the credential counter verification failure")]
    CounterVerification,

    /// Credential not found.
    #[error("credential with credential_id: `{0}` is not found")]
    CredentialNotFound(String),

    /// Database error.
    #[error(transparent)]
    Database {
        /// The source of the error.
        #[from]
        source: DatabaseError,
    },

    /// (de)serialization error.
    #[error(transparent)]
    Serde {
        /// The source of the error.
        #[from]
        source: serde_json::Error,
    },

    /// Int conversion error.
    #[error(transparent)]
    TryFromIntError(#[from] std::num::TryFromIntError),
}
