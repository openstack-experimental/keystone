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
//! # Application credential provider error.
use thiserror::Error;

use crate::common::password_hashing::PasswordHashError;
use crate::error::BuilderError;

/// Application credential provider error.
#[derive(Error, Debug)]
pub enum ApplicationCredentialProviderError {
    /// AccessRule with matching ID and another one matching rest of parameters
    /// is found.
    #[error("more than one access rule matching the ID and parameters found")]
    AccessRuleConflict,

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Driver error.
    #[error("backend driver error: {0}")]
    Driver(String),

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

    /// Role Database error.
    #[error(transparent)]
    Role {
        /// The source of the error.
        #[from]
        source: crate::role::RoleProviderError,
    },

    /// Secret is missing.
    #[error("secret missing")]
    SecretMissing,

    /// (de)serialization error.
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
        source: BuilderError,
    },
    /// Unsupported driver.
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),

    /// Request validation error.
    #[error("request validation error: {}", source)]
    Validation {
        /// The source of the error.
        #[from]
        source: validator::ValidationErrors,
    },
}
