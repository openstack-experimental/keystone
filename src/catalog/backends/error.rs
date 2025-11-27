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

use crate::catalog::types::*;

#[derive(Error, Debug)]
pub enum CatalogDatabaseError {
    #[error("data serialization error")]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    #[error(transparent)]
    EndpointBuilder {
        #[from]
        source: EndpointBuilderError,
    },

    #[error(transparent)]
    ServiceBuilder {
        #[from]
        source: ServiceBuilderError,
    },

    #[error("service {0} not found")]
    ServiceNotFound(String),

    /// Conflict
    #[error("{message}")]
    Conflict { message: String, context: String },

    /// SqlError
    #[error("{message}")]
    Sql { message: String, context: String },

    /// Database error
    #[error("Database error while {context}")]
    Database {
        source: sea_orm::DbErr,
        context: String,
    },
}

/// Convert the DB error into the [CatalogDatabaseError] with the context
/// information.
pub fn db_err(e: sea_orm::DbErr, context: &str) -> CatalogDatabaseError {
    e.sql_err().map_or_else(
        || CatalogDatabaseError::Database {
            source: e,
            context: context.to_string(),
        },
        |err| match err {
            SqlErr::UniqueConstraintViolation(descr) => CatalogDatabaseError::Conflict {
                message: descr.to_string(),
                context: context.to_string(),
            },
            SqlErr::ForeignKeyConstraintViolation(descr) => CatalogDatabaseError::Conflict {
                message: descr.to_string(),
                context: context.to_string(),
            },
            other => CatalogDatabaseError::Sql {
                message: other.to_string(),
                context: context.to_string(),
            },
        },
    )
}
