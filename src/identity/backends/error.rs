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

use sea_orm::SqlErr;
use thiserror::Error;

use crate::identity::error::IdentityProviderPasswordHashError;
use crate::identity::types::*;

#[derive(Error, Debug)]
pub enum IdentityDatabaseError {
    #[error("corrupted database entries for user {0}")]
    MalformedUser(String),

    #[error("{0}")]
    UserNotFound(String),

    #[error("{0}")]
    GroupNotFound(String),

    #[error(transparent)]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    #[error(transparent)]
    Join {
        #[from]
        source: tokio::task::JoinError,
    },

    #[error("building user response data")]
    UserBuilderError {
        #[from]
        source: UserResponseBuilderError,
    },

    #[error("building user federation")]
    FederatedUserBuilderError {
        #[from]
        source: FederationBuilderError,
    },

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

    #[error("password hashing error")]
    PasswordHash {
        #[from]
        source: IdentityProviderPasswordHashError,
    },

    #[error("either user id or user name with user domain id or name must be given")]
    UserIdOrNameWithDomain,

    /// No data for local_user and passwords
    #[error("no passwords for the user {0}")]
    NoPasswordsForUser(String),

    /// Row does not contain password hash.
    #[error("no passwords hash on the row id: {0}")]
    NoPasswordHash(String),

    /// No entry in the `user` table for the user.
    #[error("no entry in the `user` table found for user_id: {0}")]
    NoMainUserEntry(String),

    /// Supported authentication error.
    #[error(transparent)]
    AuthenticationInfo {
        #[from]
        source: crate::auth::AuthenticationError,
    },
}

/// Convert the DB error into the [`IdentityDatabaseError`] with the context
/// information.
pub fn db_err(e: sea_orm::DbErr, context: &str) -> IdentityDatabaseError {
    e.sql_err().map_or_else(
        || IdentityDatabaseError::Database {
            source: e,
            context: context.to_string(),
        },
        |err| match err {
            SqlErr::UniqueConstraintViolation(descr) => IdentityDatabaseError::Conflict {
                message: descr.to_string(),
                context: context.to_string(),
            },
            SqlErr::ForeignKeyConstraintViolation(descr) => IdentityDatabaseError::Conflict {
                message: descr.to_string(),
                context: context.to_string(),
            },
            other => IdentityDatabaseError::Sql {
                message: other.to_string(),
                context: context.to_string(),
            },
        },
    )
}
