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
//! Vendor data JWT API types (SPIRE integration plan, Phase 2).

use serde::{Deserialize, Serialize};

/// Request body for `POST /v4/vendordata`, sent by Nova's `vendor_data_url`
/// mechanism.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VendorDataRequest {
    /// Owning project ID.
    pub project_id: String,
    /// The booting instance's ID.
    pub instance_id: String,
    /// Domain owning the signing key used to sign the attestation JWT.
    /// Defaults to `default` when omitted.
    #[serde(default)]
    pub domain_id: Option<String>,
    /// Requested JWT lifetime in seconds. Accepted range 60-600; defaults
    /// to `[vendordata] default_ttl_seconds` when omitted, and is capped at
    /// `[oauth2] access_token_lifetime_minutes` regardless of what is
    /// requested.
    #[serde(default)]
    pub ttl_seconds: Option<u32>,
}

/// The signed attestation JWT, nested under `spiffe_jwt` in the response
/// body (matching Nova's `vendor_data_key_name` convention).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SpiffeJwt {
    /// JWS signing algorithm, e.g. `ES256`.
    pub algorithm: String,
    /// The JWT's `jti` claim, echoed here for convenience.
    pub jti: String,
    /// The encoded JWT.
    pub token: String,
    /// Human-readable ISO 8601 echo of the JWT's `exp` claim. Expiry
    /// validation uses the unix-timestamp `exp` claim inside the JWT
    /// payload itself, not this field.
    pub expires_at: String,
}

/// Response body for `POST /v4/vendordata` (`201 Created`).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VendorDataResponse {
    /// The signed attestation JWT.
    pub spiffe_jwt: SpiffeJwt,
}
