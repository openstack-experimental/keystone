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

use crate::identity::backends::error::*;
use crate::identity::types::*;
//{DomainBuilderError, UserResponseBuilderError};
use crate::resource::error::ResourceProviderError;

#[derive(Error, Debug)]
pub enum IdentityProviderError {
    /// Unsupported driver
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),

    /// Identity provider error
    #[error("data serialization error")]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    #[error("user {0} not found")]
    UserNotFound(String),

    #[error("group {0} not found")]
    GroupNotFound(String),

    /// Identity provider error
    #[error(transparent)]
    IdentityDatabase { source: IdentityDatabaseError },

    #[error(transparent)]
    UserBuilder {
        #[from]
        source: UserResponseBuilderError,
    },

    #[error(transparent)]
    UserCreateBuilder {
        #[from]
        source: UserCreateBuilderError,
    },

    #[error(transparent)]
    FederatedUserBuilder {
        #[from]
        source: FederationBuilderError,
    },

    #[error(transparent)]
    DomainBuilder {
        #[from]
        source: DomainBuilderError,
    },

    #[error("either user id or user name with user domain id or name must be given")]
    UserIdOrNameWithDomain,

    #[error("password hashing error")]
    PasswordHash {
        #[from]
        source: IdentityProviderPasswordHashError,
    },

    #[error(transparent)]
    AuthenticationInfo {
        #[from]
        source: crate::auth::AuthenticationError,
    },

    #[error(transparent)]
    ResourceProvider {
        #[from]
        source: ResourceProviderError,
    },

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),
}

impl From<IdentityDatabaseError> for IdentityProviderError {
    fn from(source: IdentityDatabaseError) -> Self {
        match source {
            IdentityDatabaseError::Conflict { message, .. } => Self::Conflict(message),
            IdentityDatabaseError::UserNotFound(x) => Self::UserNotFound(x),
            IdentityDatabaseError::GroupNotFound(x) => Self::GroupNotFound(x),
            IdentityDatabaseError::Serde { source } => Self::Serde { source },
            IdentityDatabaseError::PasswordHash { source } => Self::PasswordHash { source },
            IdentityDatabaseError::NoPasswordHash(..) => Self::AuthenticationInfo {
                source: crate::auth::AuthenticationError::UserNameOrPasswordWrong,
            },
            IdentityDatabaseError::AuthenticationInfo { source } => {
                Self::AuthenticationInfo { source }
            }
            //IdentityDatabaseError::UserLocked(x) => Self::AuthenticationInfo {
            //    source: crate::auth::AuthenticationError::UserLocked(x),
            //},
            _ => Self::IdentityDatabase { source },
        }
    }
}

/// Password hashing related errors.
#[derive(Error, Debug)]
pub enum IdentityProviderPasswordHashError {
    /// Bcrypt error.
    #[error(transparent)]
    BCrypt {
        #[from]
        source: bcrypt::BcryptError,
    },

    /// Async task join error.
    #[error(transparent)]
    Join {
        #[from]
        source: tokio::task::JoinError,
    },
}
