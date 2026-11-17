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
//! OAuth2.0 Client Credentials Grant types (RFC 6749 §4.4).

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::common;
/// OAuth2 token request (RFC 6749 §4.4 — client credentials grant).
///
/// Submitted as `application/x-www-form-urlencoded`. Client credentials
/// may arrive here (`client_id` + `client_secret` in the form body) or
/// via the `Authorization: Basic` header (RFC 6749 §2.3.1); the handler
/// merges both sources.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams, utoipa::ToSchema))]
pub struct OAuth2TokenRequest {
    /// The OAuth2 grant type. Only `client_credentials` is supported.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub grant_type: Option<String>,

    /// Application credential ID (optional when supplied via Basic auth).
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub client_id: Option<String>,

    /// Application credential secret (optional when supplied via Basic auth).
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[cfg_attr(feature = "openapi", param(value_type = Option<String>))]
    #[serde(default, deserialize_with = "common::deserialize_optional_secret")]
    pub client_secret: Option<SecretString>,
}

/// OAuth2 access token response (RFC 6749 §4.4.3).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OAuth2TokenResponse {
    /// The Fernet-encoded access token.
    pub access_token: String,

    /// Token type. Always `Bearer` (RFC 6749 §7.1).
    pub token_type: String,

    /// Token lifetime in seconds.
    pub expires_in: i64,
}
