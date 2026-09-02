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
//! # SPIFFE attestation signing key provider error

use thiserror::Error;

use crate::error::BuilderError;

/// SPIFFE attestation signing key provider error (SPIRE integration plan,
/// Phase 2, "Attestation key isolation"). Deliberately smaller than
/// [`crate::oauth2_key::Oauth2KeyProviderError`]: the attestation key has
/// no emergency-rotation or JTI-revocation machinery of its own.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum SpiffeKeyProviderError {
    /// Asymmetric keypair generation, DER encoding, or JWK conversion
    /// failed.
    #[error("SPIFFE attestation signing key cryptographic operation failed: {0}")]
    Crypto(String),

    /// No signing keys are present for the requested domain (not yet
    /// provisioned, or the domain does not exist).
    #[error("no SPIFFE attestation signing keys found for domain {0}")]
    NotFound(String),

    /// The filesystem key repository could not be read or written.
    #[error("SPIFFE attestation signing key repository I/O error: {0}")]
    Io(String),

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder {
        /// The source of the error.
        #[from]
        source: Box<BuilderError>,
    },
}

impl From<BuilderError> for SpiffeKeyProviderError {
    fn from(value: BuilderError) -> Self {
        Self::StructBuilder {
            source: Box::new(value),
        }
    }
}
