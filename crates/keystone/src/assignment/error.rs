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
//! # Assignment provider error types
use thiserror::Error;

use crate::assignment::backend::error::*;
use crate::identity::error::IdentityProviderError;
use crate::resource::error::ResourceProviderError;
use crate::revoke::error::RevokeProviderError;

/// Assignment provider error.
#[derive(Error, Debug)]
pub enum AssignmentProviderError {
    /// Assignment not found.
    #[error("assignment not found: {0}")]
    AssignmentNotFound(String),

    /// Assignment provider error.
    #[error(transparent)]
    Backend { source: AssignmentDatabaseError },

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Identity provider error.
    #[error(transparent)]
    IdentityProvider {
        #[from]
        source: IdentityProviderError,
    },

    /// Resource provider error.
    #[error(transparent)]
    ResourceProvider {
        #[from]
        source: ResourceProviderError,
    },

    /// Revoke provider error.
    #[error(transparent)]
    RevokeProvider {
        #[from]
        source: RevokeProviderError,
    },

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

impl From<AssignmentDatabaseError> for AssignmentProviderError {
    fn from(source: AssignmentDatabaseError) -> Self {
        match source {
            AssignmentDatabaseError::AssignmentNotFound(msg) => {
                AssignmentProviderError::AssignmentNotFound(msg)
            }
            AssignmentDatabaseError::Database { source } => match source {
                cfl @ crate::error::DatabaseError::Conflict { .. } => {
                    Self::Conflict(cfl.to_string())
                }
                other => Self::Backend {
                    source: AssignmentDatabaseError::Database { source: other },
                },
            },
            AssignmentDatabaseError::RoleNotFound(x) => Self::RoleNotFound(x),
            AssignmentDatabaseError::StructBuilder { source } => Self::StructBuilder { source },
            _ => Self::Backend { source },
        }
    }
}
