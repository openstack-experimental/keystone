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

use thiserror::Error;

use crate::error::BuilderError;

#[derive(Error, Debug)]
pub enum LimitProviderError {
    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Driver error.
    #[error("backend driver error: {0}")]
    Driver(String),

    /// The limit does not satisfy the enforcement model.
    #[error("the limit does not satisfy the enforcement model: {0}")]
    InvalidLimit(String),

    /// The limit has not been found.
    #[error("limit {0} not found")]
    LimitNotFound(String),

    /// There is no registered limit the limit could refer to.
    #[error("no registered limit exists for the limit: {0}")]
    NoLimitReference(String),

    /// The registered limit has not been found.
    #[error("registered limit {0} not found")]
    RegisteredLimitNotFound(String),

    /// The registered limit is referenced by limits.
    #[error("registered limit {0} is referenced by limits")]
    RegisteredLimitInUse(String),

    #[error("data serialization error")]
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
    #[error("unsupported driver `{0}` for the limit provider.")]
    UnsupportedDriver(String),

    /// Referenced resource (service, region, project, domain) is invalid.
    #[error("invalid reference: {0}")]
    InvalidReference(String),

    /// Validation error.
    #[error("request validation error: {}", source)]
    Validation {
        /// The source of the error.
        #[from]
        source: validator::ValidationErrors,
    },
}
