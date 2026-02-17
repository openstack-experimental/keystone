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
//! # Role provider error types
use thiserror::Error;

use crate::role::backend::error::*;

/// Role provider error.
#[derive(Error, Debug)]
pub enum RoleProviderError {
    /// Role provider error.
    #[error(transparent)]
    Backend { source: RoleDatabaseError },

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Role not found.
    #[error("role {0} not found")]
    RoleNotFound(String),

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder {
        /// The source of the error.
        #[from]
        source: crate::error::BuilderError,
    },

    /// Unsupported driver.
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),

    /// Validation error.
    #[error("request validation error: {}", source)]
    Validation {
        /// The source of the error.
        #[from]
        source: validator::ValidationErrors,
    },
}

impl From<RoleDatabaseError> for RoleProviderError {
    fn from(source: RoleDatabaseError) -> Self {
        match source {
            RoleDatabaseError::Database { source } => match source {
                cfl @ crate::error::DatabaseError::Conflict { .. } => {
                    Self::Conflict(cfl.to_string())
                }
                other => Self::Backend {
                    source: RoleDatabaseError::Database { source: other },
                },
            },
            RoleDatabaseError::RoleNotFound(x) => Self::RoleNotFound(x),
            RoleDatabaseError::StructBuilder { source } => Self::StructBuilder { source },
            _ => Self::Backend { source },
        }
    }
}
