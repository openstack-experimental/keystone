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
//! OAuth2 signing key rotation API types (ADR 0026 §3).

use serde::{Deserialize, Serialize};

/// Request body for `POST /v4/oauth2/{domain_id}/rotate-signing-key`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RotateSigningKeyRequest {
    /// Stage an emergency (dual-control) rotation instead of committing
    /// immediately.
    #[serde(default)]
    pub emergency: bool,
}

/// Response body for `POST /v4/oauth2/{domain_id}/rotate-signing-key`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RotateSigningKeyResponse {
    /// Set when `emergency` was `false`: the newly active `Primary` key's
    /// `kid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Set when `emergency` was `true`: pass this to
    /// `confirm-rotate-signing-key`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_rotation_id: Option<String>,
    /// Set when `emergency` was `true`: Unix epoch seconds after which the
    /// pending rotation auto-aborts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

/// Request body for `POST /v4/oauth2/{domain_id}/confirm-rotate-signing-key`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConfirmRotateSigningKeyRequest {
    /// The `pending_rotation_id` returned by `rotate-signing-key`.
    pub rotation_id: String,
    /// JTIs known to have been issued by the compromised key during the
    /// incident window, to add to the JTI revocation list (ADR 0026 §3).
    #[serde(default)]
    pub revoke_jtis: Vec<String>,
}

/// Response body for `POST /v4/oauth2/{domain_id}/confirm-rotate-signing-key`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConfirmRotateSigningKeyResponse {
    /// The newly active `Primary` key's `kid`.
    pub kid: String,
}
