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
//! `POST /v3/ec2tokens` wire types (ADR 0019 §5).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

/// The `credentials` object: a signed AWS-style request description used to
/// authenticate the owner of the referenced EC2 access key.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Ec2SignatureCredentials {
    /// The EC2 access key identifying the credential record.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub access: String,

    /// The client-computed signature to verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,

    /// The `Host` the request was signed against.
    #[serde(default)]
    pub host: String,

    /// The HTTP verb the request was signed with (e.g. `GET`, `POST`).
    #[serde(default)]
    pub verb: String,

    /// The HTTP path the request was signed against.
    #[serde(default)]
    pub path: String,

    /// Query parameters included in the signed request.
    #[serde(default)]
    pub params: HashMap<String, String>,

    /// Headers included in the signed request (used for SigV4).
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// SHA-256 hex digest of the request body (required for SigV4; use the
    /// empty-string hash for requests with no body).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_hash: Option<String>,
}

/// `POST /v3/ec2tokens` request body. Python Keystone accepts the
/// `credentials` object under either the `credentials` key or the legacy
/// `ec2Credentials` key.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Ec2TokenAuthRequest {
    /// The signed request description.
    #[serde(alias = "ec2Credentials")]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub credentials: Ec2SignatureCredentials,
}
