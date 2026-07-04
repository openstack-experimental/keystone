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
//! # Key repository error.
use std::path::PathBuf;

use thiserror::Error;

/// Error returned by a [`crate::KeySource`] or [`crate::KeyRepository`].
#[derive(Error, Debug)]
pub enum KeyRepositoryError {
    /// I/O error accessing the underlying key source.
    #[error("key repository I/O error at {path:?}: {source}")]
    Io {
        source: std::io::Error,
        path: PathBuf,
    },

    /// No key files/entries are present at all (repository not yet set up).
    #[error("no keys found in the key repository")]
    KeysMissing,

    /// A key entry's contents do not decode as a valid Fernet key.
    #[error("key at index {0} is not a usable Fernet key")]
    InvalidKey(i8),

    /// A key entry decodes to the well-known Null Key
    /// (`base64.urlsafe_b64encode(b'\x00' * 32)`) and
    /// `insecure_allow_null_key` was not set.
    #[error(
        "key repository contains the well-known Null Key; refusing to proceed \
         (set insecure_allow_null_key to override, at your own risk)"
    )]
    NullKeyDetected,

    /// Persisting a new key entry failed.
    #[error("failed to persist key entry: {0}")]
    Persist(String),

    /// Rotation would overflow the key index space.
    #[error("key index overflow during rotation")]
    IndexOverflow,

    /// Dropping to the configured `run_as` uid/gid failed.
    #[error("{context}: {source}")]
    NixErrno { context: String, source: nix::Error },
}
