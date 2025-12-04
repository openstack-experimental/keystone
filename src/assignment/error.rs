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

use crate::assignment::backend::error::*;
use crate::assignment::types::assignment::RoleAssignmentListForMultipleActorTargetParametersBuilderError;
use crate::assignment::types::*;
use crate::identity::error::IdentityProviderError;
use crate::resource::error::ResourceProviderError;

#[derive(Error, Debug)]
pub enum AssignmentProviderError {
    /// Unsupported driver
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),

    /// Identity provider error
    #[error("data serialization error: {}", source)]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    #[error("role {0} not found")]
    RoleNotFound(String),

    /// Assignment provider error
    #[error(transparent)]
    AssignmentDatabaseError { source: AssignmentDatabaseError },

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

    /// Invalid assignment type.
    #[error("{0}")]
    InvalidAssignmentType(String),

    #[error("building role assignment query: {}", source)]
    RoleAssignmentParametersBuilder {
        #[from]
        source: RoleAssignmentListForMultipleActorTargetParametersBuilderError,
    },

    #[error("building role assignment query: {}", source)]
    RoleAssignmentListParametersBuilder {
        #[from]
        source: RoleAssignmentListParametersBuilderError,
    },

    #[error("building role data: {}", source)]
    RoleBuilderError {
        #[from]
        source: RoleBuilderError,
    },

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
            AssignmentDatabaseError::Conflict { message, .. } => Self::Conflict(message),
            AssignmentDatabaseError::RoleNotFound(x) => Self::RoleNotFound(x),
            AssignmentDatabaseError::Serde { source } => Self::Serde { source },
            AssignmentDatabaseError::InvalidAssignmentType(x) => Self::InvalidAssignmentType(x),
            _ => Self::AssignmentDatabaseError { source },
        }
    }
}
