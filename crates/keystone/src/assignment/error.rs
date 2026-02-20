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

use crate::identity::error::IdentityProviderError;
use crate::resource::error::ResourceProviderError;
use crate::revoke::error::RevokeProviderError;

/// Assignment provider error.
#[derive(Error, Debug)]
pub enum AssignmentProviderError {
    /// Assignment not found.
    #[error("assignment not found: {0}")]
    AssignmentNotFound(String),

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Driver error.
    #[error("backend driver error: {0}")]
    Driver(String),

    /// Identity provider error.
    #[error(transparent)]
    IdentityProvider {
        #[from]
        source: IdentityProviderError,
    },

    /// Invalid assignment type.
    #[error("{0}")]
    InvalidAssignmentType(String),

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

    /// Role provider error.
    #[error(transparent)]
    RoleProvider {
        #[from]
        source: crate::role::error::RoleProviderError,
    },

    /// (de)serialize error.
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
