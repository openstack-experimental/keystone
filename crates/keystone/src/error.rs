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
//! # Error
//!
//! Diverse errors that can occur during the Keystone processing (not the API).
pub use openstack_keystone_core::error::*;
use thiserror::Error;

/// Context aware database error.
#[derive(Debug, Error)]
pub enum DatabaseError {
    /// Conflict.
    #[error("{message} while {context}")]
    Conflict {
        /// The error message.
        message: String,
        /// The error context.
        context: String,
    },

    /// Database error.
    #[error("Database error {source} while {context}")]
    Database {
        /// The source of the error.
        source: sea_orm::DbErr,
        /// The error context.
        context: String,
    },

    /// SqlError.
    #[error("{message} while {context}")]
    Sql {
        /// The error message.
        message: String,
        /// The error context.
        context: String,
    },
}

/// The trait wrapping the SQL error with the context information.
pub trait DbContextExt<T> {
    fn context(self, msg: impl Into<String>) -> Result<T, DatabaseError>;
}

impl<T> DbContextExt<T> for Result<T, sea_orm::DbErr> {
    /// Adds context information to a database error.
    ///
    /// # Parameters
    /// * `context` - The context message to add.
    ///
    /// # Returns
    /// A `Result` containing the original value if successful, or a
    /// `DatabaseError` with added context.
    fn context(self, context: impl Into<String>) -> Result<T, DatabaseError> {
        self.map_err(|err| match err.sql_err() {
            Some(sea_orm::SqlErr::UniqueConstraintViolation(descr)) => DatabaseError::Conflict {
                message: descr.to_string(),
                context: context.into(),
            },
            Some(sea_orm::SqlErr::ForeignKeyConstraintViolation(descr)) => {
                DatabaseError::Conflict {
                    message: descr.to_string(),
                    context: context.into(),
                }
            }
            Some(other) => DatabaseError::Sql {
                message: other.to_string(),
                context: context.into(),
            },
            None => DatabaseError::Database {
                source: err,
                context: context.into(),
            },
        })
    }
}
