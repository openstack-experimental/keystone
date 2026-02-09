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
//! # Federation provider error
use thiserror::Error;

use crate::federation::backend::error::*;

/// Federation provider error.
#[derive(Error, Debug)]
pub enum FederationProviderError {
    /// SQL backend error.
    #[error(transparent)]
    Backend {
        /// The source of the error.
        source: FederationDatabaseError,
    },

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// IDP not found.
    #[error("identity provider {0} not found")]
    IdentityProviderNotFound(String),

    /// Mapping not found.
    #[error("mapping {0} not found")]
    MappingNotFound(String),

    /// Use of token_project_id requires domain_id to be set.
    #[error("`mapping.domain_id` must be set")]
    MappingTokenProjectDomainUnset,

    /// Use of token_user_id requires domain_id to be set.
    #[error("`mapping.domain_id` must be set")]
    MappingTokenUserDomainUnset,

    /// Identity provider error.
    #[error("data serialization error")]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    /// Unsupported driver.
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),
}

impl From<FederationDatabaseError> for FederationProviderError {
    fn from(source: FederationDatabaseError) -> Self {
        match source {
            FederationDatabaseError::Database { source } => match source {
                cfl @ crate::error::DatabaseError::Conflict { .. } => {
                    Self::Conflict(cfl.to_string())
                }
                other => Self::Backend {
                    source: FederationDatabaseError::Database { source: other },
                },
            },
            FederationDatabaseError::IdentityProviderNotFound(x) => {
                Self::IdentityProviderNotFound(x)
            }
            FederationDatabaseError::MappingNotFound(x) => Self::MappingNotFound(x),
            FederationDatabaseError::Serde { source } => Self::Serde { source },
            _ => Self::Backend { source },
        }
    }
}
