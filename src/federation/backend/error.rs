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

use crate::federation::types::*;

#[derive(Error, Debug)]
pub enum FederationDatabaseError {
    #[error(transparent)]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    /// Conflict.
    #[error("{message} while {context}")]
    Conflict {
        /// Human readable error.
        message: String,
        /// Error context.
        context: String,
    },

    /// SqlError
    #[error("{message}")]
    Sql { message: String, context: String },

    #[error("Database error while {context}")]
    Database {
        source: sea_orm::DbErr,
        context: String,
    },

    #[error("{0}")]
    IdentityProviderNotFound(String),

    #[error("{0}")]
    MappingNotFound(String),

    #[error("{0}")]
    AuthStateNotFound(String),

    #[error(transparent)]
    AuthStateBuilder {
        #[from]
        source: AuthStateBuilderError,
    },

    #[error(transparent)]
    IdentityProviderBuilder {
        #[from]
        source: IdentityProviderBuilderError,
    },

    #[error(transparent)]
    MappingBuilder {
        #[from]
        source: MappingBuilderError,
    },
}

/// Convert the DB error into the [FederationDatabaseError] with the context
/// information.
pub fn db_err(e: sea_orm::DbErr, context: &str) -> FederationDatabaseError {
    e.sql_err().map_or_else(
        || FederationDatabaseError::Database {
            source: e,
            context: context.to_string(),
        },
        |err| match err {
            SqlErr::UniqueConstraintViolation(descr) => FederationDatabaseError::Conflict {
                message: descr.to_string(),
                context: context.to_string(),
            },
            SqlErr::ForeignKeyConstraintViolation(descr) => FederationDatabaseError::Conflict {
                message: descr.to_string(),
                context: context.to_string(),
            },
            other => FederationDatabaseError::Sql {
                message: other.to_string(),
                context: context.to_string(),
            },
        },
    )
}
