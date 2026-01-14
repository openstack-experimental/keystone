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
use crate::error::{BuilderError, DatabaseError};

#[derive(Error, Debug)]
pub enum IdentityDatabaseError {
    /// Supported authentication error.
    #[error(transparent)]
    AuthenticationInfo {
        #[from]
        source: crate::auth::AuthenticationError,
    },

    /// Database error.
    #[error(transparent)]
    Database {
        #[from]
        source: DatabaseError,
    },

    #[error("Date calculation error")]
    DateError,

    #[error("{0}")]
    GroupNotFound(String),

    #[error(transparent)]
    Join {
        #[from]
        source: tokio::task::JoinError,
    },

    #[error("corrupted database entries for user {0}")]
    MalformedUser(String),

    /// No data for local_user and passwords
    #[error("no passwords for the user {0}")]
    NoPasswordsForUser(String),

    /// Row does not contain password hash.
    #[error("no passwords hash on the row id: {0}")]
    NoPasswordHash(String),

    /// No entry in the `user` table for the user.
    #[error("no entry in the `user` table found for user_id: {0}")]
    NoMainUserEntry(String),

    /// Password hashing error.
    #[error("password hashing error")]
    PasswordHash {
        /// The source of the error.
        #[from]
        source: PasswordHashError,
    },

    #[error(transparent)]
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

    #[error("either user id or user name with user domain id or name must be given")]
    UserIdOrNameWithDomain,

    #[error("{0}")]
    UserNotFound(String),
}
