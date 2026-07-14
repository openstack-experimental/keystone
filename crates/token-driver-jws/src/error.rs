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
//! Token provider errors.

use openstack_keystone_core::token::TokenProviderError;
use openstack_keystone_key_repository::error::KeyRepositoryError;
use thiserror::Error;

/// JWS token provider error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum JwsDriverError {
    /// The JWS claims are missing exactly one of
    /// `openstack_project_id`/`openstack_domain_id`/`openstack_system`, or
    /// carry more than one.
    #[error("JWS claims must carry exactly one scope claim, found {0}")]
    AmbiguousOrMissingScopeClaim(usize),

    /// JSON (de)serialization of the claims payload failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Underlying `jsonwebtoken` encode/decode/verify failure.
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// Key material could not be converted into the format the underlying
    /// JWT library expects.
    #[error("key conversion failed: {0}")]
    KeyConversion(String),

    /// The key repository backing this provider is missing keys.
    #[error(transparent)]
    KeyRepository(#[from] KeyRepositoryError),

    /// No usable JWS signing key has been loaded yet (`load_keys` has not
    /// run, or the key repository is empty).
    #[error("no usable JWS signing key has been loaded")]
    KeysNotLoaded,

    /// A [`TokenPayload`](openstack_keystone_core_types::token::TokenPayload)
    /// variant has no representation in Python Keystone's v3 JWS claim
    /// layout (ADR 0026 §10, Phase 0).
    #[error("token variant {0} has no JWS representation")]
    UnsupportedTokenVariant(&'static str),
}

impl From<JwsDriverError> for TokenProviderError {
    fn from(value: JwsDriverError) -> Self {
        Self::Driver {
            source: Box::new(value),
        }
    }
}
