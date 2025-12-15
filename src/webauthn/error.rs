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
use sea_orm::SqlErr;
use thiserror::Error;

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

    /// Generic database backend error.
    #[error("Database error {:?}", source)]
    Database {
        /// The source of the error.
        source: sea_orm::DbErr,
        /// The error context.
        context: String,
    },

    /// Conflict.
    #[error("{message}")]
    Conflict {
        /// The error message.
        message: String,
        /// The error context.
        context: String,
    },

    /// (de)serialization error.
    #[error(transparent)]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    /// SqlError.
    #[error("{message}")]
    Sql {
        /// The error message.
        message: String,
        /// The error context.
        context: String,
    },
}

/// Convert the [`sea_orm::DbErr`] into the [`WebauthnError`] with the context information.
pub fn db_err(e: sea_orm::DbErr, context: &str) -> WebauthnError {
    e.sql_err().map_or_else(
        || WebauthnError::Database {
            source: e,
            context: context.to_string(),
        },
        |err| match err {
            SqlErr::UniqueConstraintViolation(descr) => WebauthnError::Conflict {
                message: descr.to_string(),
                context: context.to_string(),
            },
            SqlErr::ForeignKeyConstraintViolation(descr) => WebauthnError::Conflict {
                message: descr.to_string(),
                context: context.to_string(),
            },
            other => WebauthnError::Sql {
                message: other.to_string(),
                context: context.to_string(),
            },
        },
    )
}
