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
use crate::resource::types::DomainBuilderError;

#[derive(Error, Debug)]
pub enum ResourceProviderError {
    /// Unsupported driver.
    #[error("unsupported driver {0}")]
    UnsupportedDriver(String),

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Data (de)serialization error.
    #[error("data serialization error")]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    #[error("domain {0} not found")]
    DomainNotFound(String),

    /// Identity provider error
    #[error(transparent)]
    ResourceDatabase { source: ResourceDatabaseError },

    #[error(transparent)]
    DomainBuilder {
        #[from]
        source: DomainBuilderError,
    },
}

impl From<ResourceDatabaseError> for ResourceProviderError {
    fn from(source: ResourceDatabaseError) -> Self {
        match source {
            ResourceDatabaseError::Conflict { message, .. } => Self::Conflict(message),
            ResourceDatabaseError::DomainNotFound(x) => Self::DomainNotFound(x),
            _ => Self::ResourceDatabase { source },
        }
    }
}
