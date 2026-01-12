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

use crate::common::password_hashing::PasswordHashError;
use crate::error::BuilderError;
use crate::identity::backend::error::*;
use crate::resource::error::ResourceProviderError;

/// Identity provider error.
#[derive(Error, Debug)]
pub enum IdentityProviderError {
    /// Authentication error.
    #[error(transparent)]
    AuthenticationInfo {
        #[from]
        source: crate::auth::AuthenticationError,
    },

    /// SQL backend error.
    #[error(transparent)]
    Backend {
        /// The source of the error.
        source: IdentityDatabaseError,
    },

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// The group has not been found.
    #[error("group {0} not found")]
    GroupNotFound(String),

    /// Password hashing error.
    #[error("password hashing error")]
    PasswordHash {
        #[from]
        source: PasswordHashError,
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
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),

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

impl From<IdentityDatabaseError> for IdentityProviderError {
    fn from(source: IdentityDatabaseError) -> Self {
        match source {
            IdentityDatabaseError::Database { source } => match source {
                cfl @ crate::error::DatabaseError::Conflict { .. } => {
                    Self::Conflict(cfl.to_string())
                }
                other => Self::Backend {
                    source: IdentityDatabaseError::Database { source: other },
                },
            },
            IdentityDatabaseError::UserNotFound(x) => Self::UserNotFound(x),
            IdentityDatabaseError::GroupNotFound(x) => Self::GroupNotFound(x),
            IdentityDatabaseError::Serde { source } => Self::Serde { source },
            IdentityDatabaseError::StructBuilder { source } => Self::StructBuilder { source },
            IdentityDatabaseError::PasswordHash { source } => Self::PasswordHash { source },
            IdentityDatabaseError::NoPasswordHash(..) => Self::AuthenticationInfo {
                source: crate::auth::AuthenticationError::UserNameOrPasswordWrong,
            },
            IdentityDatabaseError::AuthenticationInfo { source } => {
                Self::AuthenticationInfo { source }
            }
            _ => Self::Backend { source },
        }
    }
}
