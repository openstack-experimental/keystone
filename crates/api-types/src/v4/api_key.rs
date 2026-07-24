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
//! API Key (SCIM ingress machine identity) API types (ADR 0021).

use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

/// A domain-owned machine identity credential used for stateless SCIM
/// ingress authentication. Never carries `secret_hash`/`lookup_hash` -- those
/// are internal to the authentication hot path and are not part of the admin
/// surface (ADR 0021 §2.B).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiKey {
    /// CIDR allowlist restricting the source IP of the request. `None` means
    /// no restriction applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_ips: Option<Vec<String>>,

    /// Public UUID used for management API references.
    pub client_id: String,

    /// UTC timestamp the key was created.
    pub created_at: DateTime<Utc>,

    /// Free-form administrative description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Domain owning this machine identity.
    pub domain_id: String,

    /// Whether the key currently authenticates.
    pub enabled: bool,

    /// Mandatory TTL.
    pub expires_at: DateTime<Utc>,

    /// UTC timestamp of the last successful authentication. Updated
    /// asynchronously and may lag actual usage (ADR 0021 §6.F).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,

    /// The Unified Mapping Engine (ADR 0020) `provider_id` this key
    /// authenticates against.
    pub provider_id: String,

    /// UTC timestamp the key was revoked, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,

    /// User ID of the operator who revoked the key, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
}

/// API Key creation request payload.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ApiKeyCreate {
    /// CIDR allowlist restricting the source IP of the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ips: Option<Vec<String>>,

    /// Free-form administrative description.
    #[cfg_attr(feature = "validate", validate(length(max = 512)))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Domain owning this machine identity.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: String,

    /// Mandatory TTL.
    pub expires_at: DateTime<Utc>,

    /// The Unified Mapping Engine (ADR 0020) `provider_id` this key
    /// authenticates against.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 256)))]
    pub provider_id: String,
}

/// API Key creation request wrapper.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ApiKeyCreateRequest {
    /// API Key creation payload.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub api_key: ApiKeyCreate,
}

/// API Key creation response. `token` is the full opaque bearer value and is
/// returned exactly once -- it is never retrievable again after this
/// response (ADR 0021 §2.C).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiKeyCreateResponse {
    /// The created API Key's metadata.
    pub api_key: ApiKey,

    /// The full `kscim_...` bearer token. Shown once; store it now.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[serde(serialize_with = "crate::common::serialize_secret_string")]
    pub token: SecretString,
}

/// API Key update request payload (`PUT /v4/api-keys/{client_id}`).
///
/// `allowed_ips` and `description` use nested `Option`s: the field being
/// absent from the JSON body means "leave unchanged", while an explicit
/// `null` clears it.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ApiKeyUpdate {
    /// Absent = unchanged. `null` = clear. Present = set.
    #[serde(default)]
    pub allowed_ips: Option<Option<Vec<String>>>,

    /// Absent = unchanged. `null` = clear. Present = set.
    #[serde(default)]
    pub description: Option<Option<String>>,

    /// Absent = unchanged.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// API Key update request wrapper.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ApiKeyUpdateRequest {
    /// API Key update payload.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub api_key: ApiKeyUpdate,
}

/// API Key response wrapper (show, update, revoke).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiKeyResponse {
    /// API Key object.
    pub api_key: ApiKey,
}

/// API Key list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiKeyList {
    /// Collection of API Keys.
    pub api_keys: Vec<ApiKey>,

    /// Pagination links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<crate::Link>>,
}

/// API Key list query parameters.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ApiKeyListParameters {
    /// Domain to list keys for.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: String,

    /// Restrict to enabled/disabled keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Restrict to keys bound to this `provider_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
}

/// Dry-run auditing request (`POST /v4/api-keys/simulate-access`). Shifted
/// to the body to prevent `client_id` leakage in proxy access logs (ADR 0021
/// §5.E).
///
/// ADR 0021 specifies the payload as `{"client_id": "<uuid>"}` only.
/// `domain_id` is added here because this implementation's storage partitions
/// `ApiClientResource` by domain (ADR 0021 §2.A), so a lookup by `client_id`
/// alone is not possible without it -- the same constraint applies to
/// show/update/revoke, which take `domain_id` as a query parameter.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ApiKeySimulateAccessRequest {
    /// Public UUID of the key to simulate.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub client_id: String,

    /// Domain the key belongs to.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: String,
}

/// The scope an API Key would be granted, were it to authenticate right now.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SimulatedScope {
    /// Domain-level scope.
    Domain {
        /// Domain ID the key would be scoped to.
        domain_id: String,
    },
    /// Project-level scope.
    Project {
        /// Project domain ID.
        project_domain_id: String,
        /// Project ID the key would be scoped to.
        project_id: String,
    },
}

/// Dry-run auditing response: the API Key's fully resolved authorization
/// topology, as it would be hydrated by a real SCIM ingress request right
/// now, without presenting the bearer token or performing cryptographic
/// verification (ADR 0021 §5.E).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiKeySimulateAccessResponse {
    /// Public UUID of the simulated key.
    pub client_id: String,

    /// Domain owning the key.
    pub domain_id: String,

    /// Whether the key would successfully authenticate.
    pub matched: bool,

    /// The `provider_id` the key is bound to.
    pub provider_id: String,

    /// Explains why `matched` is `false`. Absent when `matched` is `true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Effective role names, deduplicated and sorted. Empty when `matched`
    /// is `false`.
    pub roles: Vec<String>,

    /// The scope the key would be granted. Absent when `matched` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<SimulatedScope>,
}
