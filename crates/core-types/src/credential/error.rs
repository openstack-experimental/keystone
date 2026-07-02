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
//! # Credential provider error.
use thiserror::Error;

use crate::error::BuilderError;

/// Credential provider error.
#[derive(Error, Debug)]
pub enum CredentialProviderError {
    /// Credential with the given ID was not found.
    #[error("credential with id: {0} not found")]
    CredentialNotFound(String),

    /// EC2 access key hash collision on create (id derived from
    /// `SHA-256(blob['access'])` already exists), or another uniqueness
    /// conflict reported by the backend.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Driver error.
    #[error("backend driver error: {0}")]
    Driver(String),

    /// Fernet encryption/decryption error (e.g. all active keys failed to
    /// decrypt `encrypted_blob`, or the key repository is unavailable).
    #[error("credential encryption error: {0}")]
    Encryption(String),

    /// The `blob` field is not valid JSON, or is missing a mandatory
    /// per-type field (e.g. `access` for `ec2`).
    #[error("invalid credential blob: {0}")]
    InvalidBlob(String),

    /// Attempt to change a field that is immutable on update (`user_id`,
    /// `project_id`, or the delegation fields inside the EC2 blob).
    #[error("field `{0}` is immutable and cannot be updated")]
    ImmutableField(String),

    /// `user_id` was not provided on create and could not be defaulted
    /// (e.g. the caller holds a system-scoped token).
    #[error("user_id is required")]
    MissingUserId,

    /// `project_id` is mandatory for `ec2` credentials.
    #[error("project_id is required for ec2 credentials")]
    MissingProjectId,

    /// (de)serialization error.
    #[error(transparent)]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder {
        #[from]
        source: BuilderError,
    },

    /// Unsupported driver.
    #[error("unsupported driver `{0}` for the credential provider")]
    UnsupportedDriver(String),

    /// Request validation error.
    #[error("request validation error: {}", source)]
    Validation {
        #[from]
        source: validator::ValidationErrors,
    },
}
