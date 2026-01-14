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
//! # Trust Error
use thiserror::Error;

use crate::trust::backend::error::TrustDatabaseError;

/// Trust extension error.
#[derive(Error, Debug)]
pub enum TrustError {
    /// Supported authentication error.
    #[error(transparent)]
    AuthenticationInfo {
        /// The source of the error.
        #[from]
        source: crate::auth::AuthenticationError,
    },

    /// SQL backend error.
    #[error(transparent)]
    Backend {
        /// The source of the error.
        source: TrustDatabaseError,
    },

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Trust expiration is more than the redelegated trust can provide.
    #[error("requested expiration is more than the redelegated trust can provide")]
    ExpirationImpossible,

    /// Relegated trust does not allow impersonation.
    #[error(
        "impersonation is not allowed because redelegated trust does not specify impersonation"
    )]
    RedelegatedImpersonationNotAllowed,

    /// Relegation trust must not add new roles.
    #[error("some of the requested roles are not in the redelegated trust")]
    RedelegatedRolesNotAvailable,

    /// Redelegation chain is longer than allowed.
    #[error("redelegation depth of {length} is out of allowed range [0..{max_depth}]")]
    RedelegationDeepnessExceed { length: usize, max_depth: usize },

    /// Remaining uses of the trust is exceeded.
    #[error("remaining uses exceed")]
    RemainingUsesExceed,

    /// Remaining uses must be unset to redelegate a trust.
    #[error("remaining uses is set while it must not be set in order to redelegate a trust")]
    RemainingUsesMustBeUnset,

    /// (de)serialization error.
    #[error(transparent)]
    Serde {
        /// The source of the error.
        #[from]
        source: serde_json::Error,
    },

    /// Unsupported driver.
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),
}

impl From<TrustDatabaseError> for TrustError {
    fn from(source: TrustDatabaseError) -> Self {
        match source {
            TrustDatabaseError::Database { source } => match source {
                cfl @ crate::error::DatabaseError::Conflict { .. } => {
                    Self::Conflict(cfl.to_string())
                }
                other => Self::Backend {
                    source: TrustDatabaseError::Database { source: other },
                },
            },
            _ => Self::Backend { source },
        }
    }
}
