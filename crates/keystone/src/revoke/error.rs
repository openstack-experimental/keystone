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
//! Token revocation errors.

use thiserror::Error;

use crate::revoke::backend::error::RevokeDatabaseError;

/// Revoke provider error.
#[derive(Error, Debug)]
pub enum RevokeProviderError {
    /// SQL backend error.
    #[error(transparent)]
    Backend {
        /// The source of the error.
        source: RevokeDatabaseError,
    },

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Driver error.
    #[error("backend driver error: {0}")]
    Driver(String),

    /// No audit ID in the token.
    #[error("token does not have the audit_id set")]
    TokenHasNoAuditId,

    /// Unsupported driver.
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),
}

impl From<RevokeDatabaseError> for RevokeProviderError {
    fn from(source: RevokeDatabaseError) -> Self {
        match source {
            RevokeDatabaseError::Database { source } => match source {
                cfl @ crate::error::DatabaseError::Conflict { .. } => {
                    Self::Conflict(cfl.to_string())
                }
                other => Self::Backend {
                    source: RevokeDatabaseError::Database { source: other },
                },
            },
        }
    }
}
