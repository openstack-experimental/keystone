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
//! # K8s Auth error

use thiserror::Error;

use crate::error::DatabaseError;
use crate::k8s_auth::backend::error::K8sAuthDatabaseError;

/// K8s auth provider error.
#[derive(Error, Debug)]
pub enum K8sAuthProviderError {
    /// SQL backend error.
    #[error(transparent)]
    Backend {
        /// The source of the error.
        source: K8sAuthDatabaseError,
    },

    /// K8s auth configuration not found.
    #[error("k8s configuration {0} not found")]
    ConfigurationNotFound(String),

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Database error.
    #[error(transparent)]
    Database(#[from] DatabaseError),

    /// K8s auth role not found.
    #[error("k8s role {0} not found")]
    RoleNotFound(String),

    /// Unsupported driver.
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),
}

impl From<K8sAuthDatabaseError> for K8sAuthProviderError {
    fn from(source: K8sAuthDatabaseError) -> Self {
        match source {
            K8sAuthDatabaseError::Database { source } => match source {
                cfl @ crate::error::DatabaseError::Conflict { .. } => {
                    Self::Conflict(cfl.to_string())
                }
                other => Self::Backend {
                    source: K8sAuthDatabaseError::Database { source: other },
                },
            },
            K8sAuthDatabaseError::ConfigurationNotFound(val) => Self::ConfigurationNotFound(val),
            K8sAuthDatabaseError::RoleNotFound(val) => Self::RoleNotFound(val),

            _ => Self::Backend { source },
        }
    }
}
