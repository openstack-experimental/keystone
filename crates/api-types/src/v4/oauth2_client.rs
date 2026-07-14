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
//! OAuth2 client (relying party registration) API types (ADR 0026 §5).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

use crate::Link;

/// OAuth2/OIDC grant type a client is authorized to use.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    /// RFC 6749 `authorization_code`, optionally with PKCE (RFC 7636).
    AuthorizationCode,
    /// RFC 6749 `client_credentials` (machine-to-machine).
    ClientCredentials,
    /// OAuth 2.0 Device Authorization Grant (RFC 8628).
    DeviceCode,
    /// RFC 6749 `refresh_token`.
    RefreshToken,
}

/// A registered OAuth2/OIDC relying party. Never carries `client_secret` or
/// its hash -- the plaintext secret is only ever returned once, by `create`
/// or `rotate-secret`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct OAuth2Client {
    /// Scopes this client may request.
    pub allowed_scopes: Vec<String>,

    /// Per-client output claim templates (ADR 0026 §4, "Claim Safety").
    pub claims_template: HashMap<String, String>,

    /// Whether this is a confidential client (has a `client_secret`).
    pub confidential: bool,

    /// Globally unique public client identifier (server-generated).
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub client_id: String,

    /// UTC epoch seconds.
    pub created_at: i64,

    /// UTC epoch seconds of soft-delete, if revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,

    /// Domain owning this client registration.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: String,

    /// Whether the client is currently usable.
    pub enabled: bool,

    /// Grant types this client is authorized to use.
    pub grant_types: Vec<GrantType>,

    /// Whether consent is pre-authorized. SystemAdmin-only to set.
    pub pre_authorized: bool,

    /// The Unified Mapping Engine (ADR 0020) `provider_id` coordinate.
    /// Unique within `domain_id`.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub provider_id: String,

    /// Allowed redirect URIs for the `authorization_code` grant.
    pub redirect_uris: Vec<String>,

    /// Whether PKCE (RFC 7636) is mandatory for this client.
    pub require_pkce: bool,

    /// Token endpoint authentication method. Immutable after creation.
    pub token_endpoint_auth_method: String,

    /// UTC epoch seconds.
    pub updated_at: i64,
}

/// OAuth2 client creation payload.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct OAuth2ClientCreate {
    /// Scopes this client may request.
    #[serde(default)]
    pub allowed_scopes: Vec<String>,

    /// Per-client output claim templates.
    #[serde(default)]
    pub claims_template: HashMap<String, String>,

    /// Whether to register a confidential client (server generates and
    /// returns a `client_secret` exactly once) or a public client (no
    /// secret, PKCE mandatory).
    pub confidential: bool,

    /// Grant types this client is authorized to use.
    #[serde(default)]
    pub grant_types: Vec<GrantType>,

    /// Whether consent is pre-authorized. SystemAdmin-only to set.
    #[serde(default)]
    pub pre_authorized: bool,

    /// The `provider_id` coordinate this client registers under. `domain_id`
    /// comes from the URL path, not the body.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub provider_id: String,

    /// Allowed redirect URIs for the `authorization_code` grant.
    #[serde(default)]
    pub redirect_uris: Vec<String>,

    /// Whether PKCE is mandatory. Always `true` for public clients.
    #[serde(default)]
    pub require_pkce: bool,

    /// Token endpoint authentication method (e.g. `client_secret_basic`,
    /// `none`).
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub token_endpoint_auth_method: String,
}

/// OAuth2 client creation request wrapper.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct OAuth2ClientCreateRequest {
    /// OAuth2 client creation payload.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub oauth2_client: OAuth2ClientCreate,
}

/// OAuth2 client creation response. `client_secret` is populated exactly
/// once for a confidential client, and never again on any subsequent read.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OAuth2ClientCreateResponse {
    /// One-time plaintext client secret. `None` for a public client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    /// The created OAuth2 client.
    pub oauth2_client: OAuth2Client,
}

/// OAuth2 client update payload. `None` fields are left unchanged.
/// `client_id`, `provider_id`, `domain_id`, and `token_endpoint_auth_method`
/// are immutable after creation.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct OAuth2ClientUpdate {
    /// New allowed scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_scopes: Option<Vec<String>>,

    /// New claim templates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_template: Option<HashMap<String, String>>,

    /// Enable/disable toggle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// New grant types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<GrantType>>,

    /// New pre-authorized flag. SystemAdmin-only to set to `true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_authorized: Option<bool>,

    /// New redirect URIs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,

    /// New PKCE requirement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pkce: Option<bool>,
}

/// OAuth2 client update request wrapper.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct OAuth2ClientUpdateRequest {
    /// OAuth2 client update payload.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub oauth2_client: OAuth2ClientUpdate,
}

/// OAuth2 client response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OAuth2ClientResponse {
    /// OAuth2 client object.
    pub oauth2_client: OAuth2Client,
}

/// OAuth2 client list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OAuth2ClientList {
    /// Pagination links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
    /// Collection of OAuth2 clients.
    pub oauth2_clients: Vec<OAuth2Client>,
}

/// OAuth2 client list query parameters.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct OAuth2ClientListParameters {
    /// Filter by enabled/disabled state. `domain_id` comes from the URL
    /// path, not the query string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

/// Response to `POST .../{provider_id}/rotate-secret`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OAuth2ClientRotateSecretResponse {
    /// One-time plaintext client secret.
    pub client_secret: String,
}
