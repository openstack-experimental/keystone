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
//! # Vendor data JWT (SPIRE integration plan, Phase 2)
//!
//! `POST /v4/vendordata` signs a short-lived JWT scoped to a booting VM
//! instance, used by the (external, Phase 5) SPIRE `jwt_keystone` node
//! attestor to mint the VM's project-scoped SPIFFE SVID.
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::BuilderError;

/// Vendor data JWT provider error.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum VendordataProviderError {
    /// The calling compute host's claimed `project_id`/`instance_id` does
    /// not match Nova's record for `instance_id` (Fix 1, "Ownership
    /// verification"). Maps to `403 Forbidden`.
    #[error("compute host is not authorized to attest for this instance")]
    OwnershipMismatch,

    /// The Nova ownership cross-check could not be completed (Nova
    /// unreachable, timed out, or `[vendordata] nova_api_base_url` is not
    /// configured). Fails closed: maps to `503 Service Unavailable`, never
    /// a signed JWT.
    #[error("nova ownership verification unavailable: {0}")]
    NovaUnavailable(String),

    /// The calling SPIFFE ID does not match the expected
    /// `.../service/nova-compute/host/{hostname}` shape (Phase 3's
    /// strict path-segment matching). Maps to `403 Forbidden`: this is an
    /// authorization decision (which identities may request attestation
    /// JWTs), not an authentication failure.
    #[error("caller SPIFFE ID is not a recognized nova-compute host identity")]
    NotAComputeHost,

    /// The request did not arrive over the internal SPIFFE mTLS interface
    /// (`[interface:internal]`, port 8444). `POST /v4/vendordata` is
    /// internal-only: Nova-compute authenticates with its SPIFFE SVID,
    /// which only that interface presents.
    #[error("vendor data JWT issuance is only available on the internal SPIFFE interface")]
    WrongInterface,

    /// `ttl_seconds` was outside the accepted 60-600 second range.
    #[error("ttl_seconds must be between 60 and 600, got {0}")]
    InvalidTtl(u32),

    /// Cryptographic signing failed, or no attestation signing key is
    /// provisioned for the domain.
    #[error("vendor data JWT signing failed: {0}")]
    Crypto(String),

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder {
        /// The source of the error.
        #[from]
        source: Box<BuilderError>,
    },
}

impl From<BuilderError> for VendordataProviderError {
    fn from(value: BuilderError) -> Self {
        Self::StructBuilder {
            source: Box::new(value),
        }
    }
}

/// `openstack` claims nested inside the attestation JWT payload.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct OpenstackAttestationClaims {
    /// Owning project ID.
    pub project_id: String,
    /// The booting instance's ID.
    pub instance_id: String,
    /// Fixed role marker consumed by the SPIRE server plugin (Phase 5) when
    /// constructing selectors.
    pub spiffe_role: String,
}

/// Attestation JWT payload signed by `POST /v4/vendordata` (SPIRE
/// integration plan, Phase 2).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SpiffeAttestationClaims {
    /// Issuer: the internal SPIFFE interface's spiffe JWKS base, e.g.
    /// `https://keystone:8444/v4/spiffe/{domain_id}`.
    pub iss: String,
    /// Fixed audience, `spiffe-attestation`. Prevents JWT misuse for any
    /// other purpose.
    pub aud: String,
    /// Expiry, unix epoch seconds.
    pub exp: i64,
    /// Issued-at, unix epoch seconds.
    pub iat: i64,
    /// Freshly generated random identifier per issued JWT (never
    /// `instance_id` -- see the plan's "Duplicate/re-attestation"
    /// discussion), consumed by the SPIRE server plugin's anti-replay
    /// cache.
    pub jti: String,
    /// Subject: `vm:{instance_id}`.
    pub sub: String,
    /// OpenStack-specific claims.
    pub openstack: OpenstackAttestationClaims,
}
