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

use thiserror::Error;

use crate::auth::AuthenticationError;
use crate::error::BuilderError;
use crate::resource::ResourceProviderError;

/// Identity provider error.
#[derive(Error, Debug)]
pub enum IdentityProviderError {
    /// Authentication error.
    #[error(transparent)]
    Authentication {
        #[from]
        source: AuthenticationError,
    },

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    #[error("Date calculation error")]
    DateError,

    /// Driver error.
    #[error("backend driver error: {0}")]
    Driver(String),

    /// The group has not been found.
    #[error("group {0} not found")]
    GroupNotFound(String),

    #[error("{}", source)]
    Join {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("corrupted database entries for user {0}")]
    MalformedUser(String),

    /// No data for local_user and passwords.
    #[error("no passwords for the user {0}")]
    NoPasswordsForUser(String),

    /// Row does not contain password hash.
    #[error("no passwords hash on the row id: {0}")]
    NoPasswordHash(String),

    /// No entry in the `user` table for the user.
    #[error("no entry in the `user` table found for user_id: {0}")]
    NoMainUserEntry(String),

    /// Password hashing error.
    #[error("{}", source)]
    PasswordHash {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Resource provider error.
    #[error(transparent)]
    ResourceProvider {
        #[from]
        source: ResourceProviderError,
    },

    /// (de)serialization error.
    #[error("data serialization error")]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder {
        /// The source of the error.
        #[from]
        source: BuilderError,
    },

    /// Unsupported driver.
    #[error("unsupported driver `{0}` for the identity provider")]
    UnsupportedDriver(String),

    #[error("user id must be given")]
    UserIdMissing,

    /// User ID or Name with Domain must be specified.
    #[error("either user id or user name with user domain id or name must be given")]
    UserIdOrNameWithDomain,

    /// The user has not been found.
    #[error("user {0} not found")]
    UserNotFound(String),

    /// Request validation error.
    #[error("request validation error: {}", source)]
    Validation {
        /// The source of the error.
        #[from]
        source: validator::ValidationErrors,
    },
}

impl IdentityProviderError {
    pub fn password_hash<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::PasswordHash {
            source: Box::new(source),
        }
    }

    pub fn join<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Join {
            source: Box::new(source),
        }
    }
}
