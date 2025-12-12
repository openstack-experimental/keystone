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

use crate::application_credential::backend::error::*;

/// Application credential provider error.
#[derive(Error, Debug)]
pub enum ApplicationCredentialProviderError {
    /// Unsupported driver.
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),

    /// (de)serialization error.
    #[error("data serialization error: {}", source)]
    Serde {
        /// The source of the error.
        #[from]
        source: serde_json::Error,
    },

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Application credential SQL backend error.
    #[error(transparent)]
    ApplicationCredentialDatabaseError {
        /// The source of the error.
        source: ApplicationCredentialDatabaseError,
    },

    /// Request validation error.
    #[error("request validation error: {}", source)]
    Validation {
        /// The source of the error.
        #[from]
        source: validator::ValidationErrors,
    },
}

impl From<ApplicationCredentialDatabaseError> for ApplicationCredentialProviderError {
    fn from(source: ApplicationCredentialDatabaseError) -> Self {
        match source {
            ref e @ ApplicationCredentialDatabaseError::Conflict { .. } => {
                Self::Conflict(e.to_string())
            }
            _ => Self::ApplicationCredentialDatabaseError { source },
        }
    }
}
