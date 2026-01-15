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

use crate::resource::backend::error::*;

#[derive(Error, Debug)]
pub enum ResourceProviderError {
    /// SQL backend error.
    #[error(transparent)]
    Backend {
        /// The source of the error.
        source: ResourceDatabaseError,
    },

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    #[error("domain {0} not found")]
    DomainNotFound(String),

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

impl From<ResourceDatabaseError> for ResourceProviderError {
    fn from(source: ResourceDatabaseError) -> Self {
        match source {
            ResourceDatabaseError::Database { source } => match source {
                cfl @ crate::error::DatabaseError::Conflict { .. } => {
                    Self::Conflict(cfl.to_string())
                }
                other => Self::Backend {
                    source: ResourceDatabaseError::Database { source: other },
                },
            },
            ResourceDatabaseError::DomainNotFound(x) => Self::DomainNotFound(x),
            _ => Self::Backend { source },
        }
    }
}
