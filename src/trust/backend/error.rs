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

use crate::assignment::backend::error::AssignmentDatabaseError;
use crate::error::{BuilderError, DatabaseError};

/// Database backend error for the database driver.
#[derive(Error, Debug)]
pub enum TrustDatabaseError {
    /// Assignment database error.
    #[error(transparent)]
    AssignmentDatabase(#[from] AssignmentDatabaseError),

    /// Database error.
    #[error(transparent)]
    Database {
        #[from]
        source: DatabaseError,
    },

    /// DateTime parsing error.
    #[error("error parsing int column as datetime: {expires_at}")]
    ExpirationDateTimeParse { id: String, expires_at: i64 },

    /// The trust has not been found.
    #[error("{0}")]
    TrustNotFound(String),

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
}
