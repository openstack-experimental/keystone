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

/// Application credential database backend error.
#[derive(Error, Debug)]
pub enum ApplicationCredentialDatabaseError {
    /// AccessRule with matching ID and another one matching rest of parameters
    /// is found.
    #[error("more than one access rule matching the ID and parameters found")]
    AccessRuleConflict,

    /// Assignment Database error.
    #[error(transparent)]
    Assignment {
        /// The source of the error.
        #[from]
        source: crate::assignment::backend::error::AssignmentDatabaseError,
    },

    /// Database error.
    #[error(transparent)]
    Database {
        #[from]
        source: DatabaseError,
    },

    /// DateTime parsing error.
    #[error("error parsing int column as datetime: {expires_at}")]
    ExpirationDateTimeParse { id: String, expires_at: i64 },

    /// Password hashing error.
    #[error(transparent)]
    PasswordHash {
        /// The source of the error.
        #[from]
        source: PasswordHashError,
    },

    /// Role Database error.
    #[error(transparent)]
    Role {
        /// The source of the error.
        #[from]
        source: crate::role::backend::error::RoleDatabaseError,
    },

    /// Secret is missing.
    #[error("secret missing")]
    SecretMissing,

    /// (de)serialization error.
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
}
