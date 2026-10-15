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
//! OAuth2 bulk revocation API types (ADR 0026 §9).

use serde::{Deserialize, Serialize};

/// Request body for `POST /v4/oauth2/{domain_id}/revocations`. Exactly one of
/// `user_id`, `client_id` or `all` must be given.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Oauth2RevocationRequest {
    /// Revoke every refresh token family of this user in the domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Revoke every refresh token family issued to this `client_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Revoke every refresh token family in the domain.
    #[serde(default)]
    pub all: bool,
    /// Free-text reason recorded in the log (at most 256 characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Response body for `POST /v4/oauth2/{domain_id}/revocations`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Oauth2RevocationResponse {
    /// Refresh token families processed by the request. Selecting a client
    /// counts every family issued to it, including ones already revoked;
    /// selecting a user or the whole domain counts only newly revoked ones.
    pub revoked_families: usize,
}
