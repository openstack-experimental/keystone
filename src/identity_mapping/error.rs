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

use crate::api::error::KeystoneApiError;
use crate::error::BuilderError;
use crate::identity_mapping::backend::error::IdentityMappingDatabaseError;

/// Identity mapping provider error.
#[derive(Error, Debug)]
pub enum IdentityMappingError {
    /// SQL backend error.
    #[error(transparent)]
    Backend {
        /// The source of the error.
        source: IdentityMappingDatabaseError,
    },

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

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

    /// Request validation error.
    #[error("request validation error: {}", source)]
    Validation {
        /// The source of the error.
        #[from]
        source: validator::ValidationErrors,
    },

    /// Unsupported driver.
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),
}

impl From<IdentityMappingDatabaseError> for IdentityMappingError {
    fn from(source: IdentityMappingDatabaseError) -> Self {
        match source {
            IdentityMappingDatabaseError::Database { source } => match source {
                cfl @ crate::error::DatabaseError::Conflict { .. } => {
                    Self::Conflict(cfl.to_string())
                }
                other => Self::Backend {
                    source: IdentityMappingDatabaseError::Database { source: other },
                },
            },
            IdentityMappingDatabaseError::Serde { source } => Self::Serde { source },
            IdentityMappingDatabaseError::StructBuilder { source } => {
                Self::StructBuilder { source }
            } // _ => Self::Backend { source },
        }
    }
}

impl From<IdentityMappingError> for KeystoneApiError {
    fn from(source: IdentityMappingError) -> Self {
        match source {
            IdentityMappingError::Conflict(x) => Self::Conflict(x),
            other => Self::InternalError(other.to_string()),
        }
    }
}
