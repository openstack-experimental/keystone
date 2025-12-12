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

use crate::common::password_hashing::PasswordHashError;
use crate::error::BuilderError;

/// Application credential database backend error.
#[derive(Error, Debug)]
pub enum ApplicationCredentialDatabaseError {
    /// AccessRule with matching ID and another one matching rest of parameters
    /// is found.
    #[error("more than one access rule matching the ID and parameters found")]
    AccessRuleConflict,

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder {
        /// The source of the error.
        #[from]
        source: BuilderError,
    },

    /// Assignment Database error.
    #[error(transparent)]
    AssignmentDatabaseError {
        /// The source of the error.
        #[from]
        source: crate::assignment::backend::error::AssignmentDatabaseError,
    },

    /// Conflict.
    #[error("{message} while {context}")]
    Conflict {
        /// Human readable error.
        message: String,
        /// Error context.
        context: String,
    },

    /// Database error.
    #[error("Database error while {context}")]
    Database {
        /// The source of the error.
        source: sea_orm::DbErr,
        /// Error context.
        context: String,
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

    /// (de)serialization error.
    #[error(transparent)]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    /// Secret is missing.
    #[error("secret missing")]
    SecretMissing,

    /// SqlError
    #[error("{message}")]
    Sql { message: String, context: String },
}

/// Convert the DB error into the [ApplicationCredentialDatabaseError] with the
/// context information.
pub fn db_err(e: sea_orm::DbErr, context: &str) -> ApplicationCredentialDatabaseError {
    e.sql_err().map_or_else(
        || ApplicationCredentialDatabaseError::Database {
            source: e,
            context: context.to_string(),
        },
        |err| match err {
            SqlErr::UniqueConstraintViolation(descr) => {
                ApplicationCredentialDatabaseError::Conflict {
                    message: descr.to_string(),
                    context: context.to_string(),
                }
            }
            SqlErr::ForeignKeyConstraintViolation(descr) => {
                ApplicationCredentialDatabaseError::Conflict {
                    message: descr.to_string(),
                    context: context.to_string(),
                }
            }
            other => ApplicationCredentialDatabaseError::Sql {
                message: other.to_string(),
                context: context.to_string(),
            },
        },
    )
}
