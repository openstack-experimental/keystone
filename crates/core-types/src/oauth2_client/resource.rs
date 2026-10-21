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
//! # OAuth2 client (relying party registration) resource (ADR 0026 §5)

use std::collections::HashMap;

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::error::BuilderError;

/// OAuth2/OIDC grant type an [`OAuth2ClientResource`] is authorized to use.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
    /// RFC 8693 Token Exchange (ADR 0026 §12 v2 shape): trades an existing
    /// Keystone-native delegated credential (trust, application credential)
    /// for a native `OpenStackAccessTokenClaims` access token.
    #[serde(rename = "urn:ietf:params:oauth:grant-type:token-exchange")]
    TokenExchange,
}

/// Apply an optional-string update: `None` keeps the current value, an empty
/// string clears it, anything else replaces it.
fn apply_optional(update: Option<String>, current: Option<String>) -> Option<String> {
    match update {
        None => current,
        Some(v) if v.is_empty() => None,
        Some(v) => Some(v),
    }
}

/// Delegation capabilities of a registered service client (ADR 0036 §3).
///
/// Present only on clients an operator registered as delegatable
/// services. Such clients authenticate with `tls_client_auth` against one of
/// the client's `spiffe_ids` patterns.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DelegationPolicy {
    /// Users may create service grants naming this client (ADR 0036 §4).
    #[serde(default)]
    pub service_grants: bool,

    /// The client may exchange a user token for an operation token (ADR
    /// 0036 §6). Stored now; consumed by the on-behalf-of exchange.
    #[serde(default)]
    pub on_behalf_of: bool,

    /// Users of other domains, or users on projects of other domains, may
    /// delegate to this client.
    #[serde(default)]
    pub cross_domain: bool,

    /// Role ids a delegation to this client may carry. Empty = no ceiling
    /// beyond the user's own roles.
    #[serde(default)]
    pub max_role_ids: Vec<String>,

    /// Upper bound, in seconds, on a service grant's lifetime.
    #[serde(default)]
    pub max_grant_lifetime: Option<u64>,

    /// Upper bound, in seconds, on an operation token's lifetime. Required
    /// when `on_behalf_of` is set.
    #[serde(default)]
    pub max_operation_lifetime: Option<u64>,

    /// Upper bound on live grants per (project, client).
    #[serde(default)]
    pub max_grants_per_project: Option<u32>,
}

impl OAuth2ClientResource {
    /// Delegation policy, when the client is an enabled delegatable service
    /// accepting service grants.
    pub fn service_grant_policy(&self) -> Option<&DelegationPolicy> {
        if !self.enabled || self.deleted_at.is_some() {
            return None;
        }
        self.delegation.as_ref().filter(|d| d.service_grants)
    }
}

/// A registered OAuth2/OIDC relying party (ADR 0026 §5, "Amendment to ADR
/// 0020: OAuth2 Client as a Fourth Provider Resource").
///
/// Indexed in storage by `(domain_id, provider_id)` under
/// `oauth2:client:v1:<domain_id>:<provider_id>`, with `client_id` resolved
/// globally (not domain-scoped) via
/// `oauth2:client:client_id_idx:v1:<client_id>`.
#[derive(Builder, Clone, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct OAuth2ClientResource {
    /// Globally unique public client identifier (server-generated UUIDv4).
    pub client_id: String,

    /// The Unified Mapping Engine (ADR 0020) `provider_id` coordinate this
    /// client is registered under. Unique within `domain_id`.
    pub provider_id: String,

    /// Domain owning this client registration.
    pub domain_id: String,

    /// Argon2id PHC hash of the client secret. `None` for a public client
    /// (e.g. SPA or native app using PKCE, no client authentication).
    #[builder(default)]
    pub client_secret_hash: Option<String>,

    /// Allowed redirect URIs for the `authorization_code` grant. Confidential
    /// clients (`client_secret_hash.is_some()`) must use `https://` only;
    /// public clients may additionally use `http://localhost:*`.
    #[builder(default)]
    pub redirect_uris: Vec<String>,

    /// Token endpoint authentication method (e.g. `client_secret_basic`,
    /// `none`). Immutable after creation.
    pub token_endpoint_auth_method: String,

    /// Grant types this client is authorized to use.
    #[builder(default)]
    pub grant_types: Vec<GrantType>,

    /// Whether PKCE (RFC 7636) is mandatory for this client. Always `true`
    /// for public clients.
    #[builder(default)]
    pub require_pkce: bool,

    /// Scopes this client may request.
    #[builder(default)]
    pub allowed_scopes: Vec<String>,

    /// Whether consent is pre-authorized (skips the interactive consent
    /// screen). SystemAdmin-only to set (ADR 0026 §5).
    #[builder(default)]
    pub pre_authorized: bool,

    /// Whether the client is currently usable. Cleared by soft-delete.
    pub enabled: bool,

    /// Per-client output claim templates, interpolated at `/token` issuance
    /// (ADR 0026 §4, "Claim Safety"). Keys colliding with the reserved claim
    /// set are rejected at save time.
    #[builder(default)]
    pub claims_template: HashMap<String, String>,

    /// UTC epoch seconds.
    pub created_at: i64,

    /// UTC epoch seconds.
    pub updated_at: i64,

    /// UTC epoch seconds of soft-delete (`DELETE`). Record retained (not
    /// hard-deleted) as a tombstone so redemption of any leftover token
    /// still fails closed; refresh families are revoked at delete time.
    #[builder(default)]
    pub deleted_at: Option<i64>,

    /// Human-readable client name shown on login and consent pages (RFC 7591
    /// `client_name`). Empty for records created before the field existed;
    /// use [`OAuth2ClientResource::display_name`].
    ///
    /// Appended after `deleted_at` (like every later field) because records
    /// are stored as positional MessagePack arrays: older, shorter records
    /// deserialize with these defaults.
    #[serde(default)]
    #[builder(default)]
    pub name: String,

    /// Short description of the client (RFC 7591 `client_uri` neighbour).
    #[serde(default)]
    #[builder(default)]
    pub description: Option<String>,

    /// `https://` URL of the client logo (RFC 7591 `logo_uri`).
    #[serde(default)]
    #[builder(default)]
    pub logo_uri: Option<String>,

    /// `https://` URL of the client's privacy policy (RFC 7591 `policy_uri`).
    #[serde(default)]
    #[builder(default)]
    pub policy_uri: Option<String>,

    /// `https://` URL of the client's terms of service (RFC 7591 `tos_uri`).
    #[serde(default)]
    #[builder(default)]
    pub tos_uri: Option<String>,

    /// Contact addresses of the client's operators (RFC 7591 `contacts`).
    #[serde(default)]
    #[builder(default)]
    pub contacts: Vec<String>,

    /// URIs the OP may redirect to after RP-initiated logout (OIDC
    /// RP-Initiated Logout 1.0 `post_logout_redirect_uris`); matched exactly.
    #[serde(default)]
    #[builder(default)]
    pub post_logout_redirect_uris: Vec<String>,

    /// `https://` endpoint receiving OIDC Back-Channel Logout 1.0 logout
    /// tokens when the user's session ends.
    #[serde(default)]
    #[builder(default)]
    pub backchannel_logout_uri: Option<String>,

    /// Whether the RP requires the `sid` claim in logout tokens (OIDC
    /// Back-Channel Logout 1.0 `backchannel_logout_session_required`).
    #[serde(default)]
    #[builder(default)]
    pub backchannel_logout_session_required: bool,

    /// `https://` endpoint rendered in a hidden iframe at logout (OIDC
    /// Front-Channel Logout 1.0 `frontchannel_logout_uri`).
    #[serde(default)]
    #[builder(default)]
    pub frontchannel_logout_uri: Option<String>,

    /// Whether the RP requires `iss` and `sid` query parameters on the
    /// front-channel logout request.
    #[serde(default)]
    #[builder(default)]
    pub frontchannel_logout_session_required: bool,

    /// SPIFFE ID patterns the client authenticates with under
    /// `tls_client_auth` (ADR 0036 §3.1). Validated at write time.
    #[serde(default)]
    #[builder(default)]
    pub spiffe_ids: Vec<String>,

    /// Delegation capabilities (ADR 0036 §3). `None` for every client that
    /// is not a delegatable service.
    #[serde(default)]
    #[builder(default)]
    pub delegation: Option<DelegationPolicy>,

    /// Issue only DPoP-bound access tokens to this client (ADR 0043 §1):
    /// `true` makes DPoP `required` for it, the narrowest enforcement level.
    /// Trailing `#[serde(default)]` field of the positional msgpack record.
    #[serde(default)]
    #[builder(default)]
    pub dpop_bound_access_tokens: bool,
}

impl std::fmt::Debug for OAuth2ClientResource {
    /// Redacts `client_secret_hash` to prevent leaking the Argon2id PHC
    /// string into application error logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2ClientResource")
            .field("client_id", &self.client_id)
            .field("provider_id", &self.provider_id)
            .field("domain_id", &self.domain_id)
            .field(
                "client_secret_hash",
                &self.client_secret_hash.as_ref().map(|_| "[REDACTED]"),
            )
            .field("redirect_uris", &self.redirect_uris)
            .field(
                "token_endpoint_auth_method",
                &self.token_endpoint_auth_method,
            )
            .field("grant_types", &self.grant_types)
            .field("require_pkce", &self.require_pkce)
            .field("allowed_scopes", &self.allowed_scopes)
            .field("pre_authorized", &self.pre_authorized)
            .field("enabled", &self.enabled)
            .field("claims_template", &self.claims_template)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("deleted_at", &self.deleted_at)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("logo_uri", &self.logo_uri)
            .field("policy_uri", &self.policy_uri)
            .field("tos_uri", &self.tos_uri)
            .field("contacts", &self.contacts)
            .field("post_logout_redirect_uris", &self.post_logout_redirect_uris)
            .field("backchannel_logout_uri", &self.backchannel_logout_uri)
            .field(
                "backchannel_logout_session_required",
                &self.backchannel_logout_session_required,
            )
            .field("frontchannel_logout_uri", &self.frontchannel_logout_uri)
            .field(
                "frontchannel_logout_session_required",
                &self.frontchannel_logout_session_required,
            )
            .field("spiffe_ids", &self.spiffe_ids)
            .field("delegation", &self.delegation)
            .field("dpop_bound_access_tokens", &self.dpop_bound_access_tokens)
            .finish()
    }
}

impl OAuth2ClientResource {
    /// Apply a partial [`OAuth2ClientResourceUpdate`], returning the new
    /// version to persist.
    ///
    /// Defense in depth: the service layer (`Oauth2ClientService::update`)
    /// already refuses to update a soft-deleted client at all, so this path
    /// should never see `self.deleted_at.is_some()`. If it ever does anyway
    /// (a future caller bypassing the service layer), `deleted_at` is
    /// cleared here rather than left stale alongside a newly `enabled` flag
    /// -- `enabled: true` and a set `deleted_at` must never coexist.
    pub fn with_update(self, update: OAuth2ClientResourceUpdate, now: i64) -> Self {
        let enabled = update.enabled.unwrap_or(self.enabled);
        let deleted_at = if enabled { None } else { self.deleted_at };
        Self {
            redirect_uris: update.redirect_uris.unwrap_or(self.redirect_uris),
            grant_types: update.grant_types.unwrap_or(self.grant_types),
            require_pkce: update.require_pkce.unwrap_or(self.require_pkce),
            allowed_scopes: update.allowed_scopes.unwrap_or(self.allowed_scopes),
            pre_authorized: update.pre_authorized.unwrap_or(self.pre_authorized),
            enabled,
            claims_template: update.claims_template.unwrap_or(self.claims_template),
            name: update.name.unwrap_or(self.name),
            description: apply_optional(update.description, self.description),
            logo_uri: apply_optional(update.logo_uri, self.logo_uri),
            policy_uri: apply_optional(update.policy_uri, self.policy_uri),
            tos_uri: apply_optional(update.tos_uri, self.tos_uri),
            contacts: update.contacts.unwrap_or(self.contacts),
            post_logout_redirect_uris: update
                .post_logout_redirect_uris
                .unwrap_or(self.post_logout_redirect_uris),
            backchannel_logout_uri: apply_optional(
                update.backchannel_logout_uri,
                self.backchannel_logout_uri,
            ),
            backchannel_logout_session_required: update
                .backchannel_logout_session_required
                .unwrap_or(self.backchannel_logout_session_required),
            frontchannel_logout_uri: apply_optional(
                update.frontchannel_logout_uri,
                self.frontchannel_logout_uri,
            ),
            frontchannel_logout_session_required: update
                .frontchannel_logout_session_required
                .unwrap_or(self.frontchannel_logout_session_required),
            spiffe_ids: update.spiffe_ids.unwrap_or(self.spiffe_ids),
            delegation: if update.remove_delegation {
                None
            } else {
                update.delegation.or(self.delegation)
            },
            dpop_bound_access_tokens: update
                .dpop_bound_access_tokens
                .unwrap_or(self.dpop_bound_access_tokens),
            updated_at: now,
            deleted_at,
            ..self
        }
    }

    /// Name to show to users: the registered `name`, or the `provider_id`
    /// for clients registered before names existed.
    pub fn display_name(&self) -> &str {
        if self.name.trim().is_empty() {
            &self.provider_id
        } else {
            &self.name
        }
    }

    /// Apply the soft-delete path: disables the client and stamps the
    /// tombstone, without deleting the record (the client service revokes
    /// the client's refresh token families right after this is persisted).
    pub fn soft_delete(self, now: i64) -> Self {
        Self {
            enabled: false,
            deleted_at: Some(now),
            updated_at: now,
            ..self
        }
    }
}

/// Input to create a new [`OAuth2ClientResource`]. `client_id` is
/// server-generated; `client_secret_hash` is pre-hashed by the service layer
/// before reaching the backend.
#[derive(Builder, Clone, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct OAuth2ClientResourceCreate {
    /// Globally unique public client identifier (server-generated UUIDv4).
    pub client_id: String,

    /// The Unified Mapping Engine (ADR 0020) `provider_id` coordinate.
    pub provider_id: String,

    /// Domain owning this client registration.
    pub domain_id: String,

    /// Argon2id PHC hash of the client secret. `None` for a public client.
    #[builder(default)]
    pub client_secret_hash: Option<String>,

    /// Allowed redirect URIs for the `authorization_code` grant.
    #[builder(default)]
    pub redirect_uris: Vec<String>,

    /// Token endpoint authentication method.
    pub token_endpoint_auth_method: String,

    /// Grant types this client is authorized to use.
    #[builder(default)]
    pub grant_types: Vec<GrantType>,

    /// Whether PKCE is mandatory for this client.
    #[builder(default)]
    pub require_pkce: bool,

    /// Scopes this client may request.
    #[builder(default)]
    pub allowed_scopes: Vec<String>,

    /// Whether consent is pre-authorized. SystemAdmin-only to set.
    #[builder(default)]
    pub pre_authorized: bool,

    /// Per-client output claim templates.
    #[builder(default)]
    pub claims_template: HashMap<String, String>,

    /// Human-readable client name (1-128 characters, validated by the
    /// service layer).
    #[builder(default)]
    pub name: String,

    /// Short description of the client.
    #[builder(default)]
    pub description: Option<String>,

    /// `https://` URL of the client logo.
    #[builder(default)]
    pub logo_uri: Option<String>,

    /// `https://` URL of the client's privacy policy.
    #[builder(default)]
    pub policy_uri: Option<String>,

    /// `https://` URL of the client's terms of service.
    #[builder(default)]
    pub tos_uri: Option<String>,

    /// Contact addresses of the client's operators.
    #[builder(default)]
    pub contacts: Vec<String>,

    /// URIs the OP may redirect to after RP-initiated logout.
    #[builder(default)]
    pub post_logout_redirect_uris: Vec<String>,

    /// `https://` Back-Channel Logout endpoint.
    #[builder(default)]
    pub backchannel_logout_uri: Option<String>,

    /// Require the `sid` claim in logout tokens.
    #[builder(default)]
    pub backchannel_logout_session_required: bool,

    /// `https://` Front-Channel Logout endpoint.
    #[builder(default)]
    pub frontchannel_logout_uri: Option<String>,

    /// Require `iss` and `sid` on front-channel logout requests.
    #[builder(default)]
    pub frontchannel_logout_session_required: bool,

    /// SPIFFE ID patterns for `tls_client_auth` (ADR 0036 §3.1).
    #[builder(default)]
    pub spiffe_ids: Vec<String>,

    /// Delegation capabilities (ADR 0036 §3).
    #[builder(default)]
    pub delegation: Option<DelegationPolicy>,

    /// Issue only DPoP-bound access tokens to this client (ADR 0043 §1).
    #[builder(default)]
    pub dpop_bound_access_tokens: bool,
}

impl std::fmt::Debug for OAuth2ClientResourceCreate {
    /// Redacts `client_secret_hash`; see [`OAuth2ClientResource::fmt`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2ClientResourceCreate")
            .field("client_id", &self.client_id)
            .field("provider_id", &self.provider_id)
            .field("domain_id", &self.domain_id)
            .field(
                "client_secret_hash",
                &self.client_secret_hash.as_ref().map(|_| "[REDACTED]"),
            )
            .field("redirect_uris", &self.redirect_uris)
            .field(
                "token_endpoint_auth_method",
                &self.token_endpoint_auth_method,
            )
            .field("grant_types", &self.grant_types)
            .field("require_pkce", &self.require_pkce)
            .field("allowed_scopes", &self.allowed_scopes)
            .field("pre_authorized", &self.pre_authorized)
            .field("claims_template", &self.claims_template)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("logo_uri", &self.logo_uri)
            .field("policy_uri", &self.policy_uri)
            .field("tos_uri", &self.tos_uri)
            .field("contacts", &self.contacts)
            .field("post_logout_redirect_uris", &self.post_logout_redirect_uris)
            .field("backchannel_logout_uri", &self.backchannel_logout_uri)
            .field(
                "backchannel_logout_session_required",
                &self.backchannel_logout_session_required,
            )
            .field("frontchannel_logout_uri", &self.frontchannel_logout_uri)
            .field(
                "frontchannel_logout_session_required",
                &self.frontchannel_logout_session_required,
            )
            .field("spiffe_ids", &self.spiffe_ids)
            .field("delegation", &self.delegation)
            .field("dpop_bound_access_tokens", &self.dpop_bound_access_tokens)
            .finish()
    }
}

/// Partial update for an [`OAuth2ClientResource`]
/// (`PUT /v4/oauth2/{domain_id}/clients/{provider_id}`).
///
/// `client_id`, `provider_id`, `domain_id`, and `token_endpoint_auth_method`
/// are immutable after creation and therefore absent from this type.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(build_fn(error = "BuilderError"))]
pub struct OAuth2ClientResourceUpdate {
    /// `None` = unchanged.
    pub redirect_uris: Option<Vec<String>>,

    /// `None` = unchanged.
    pub grant_types: Option<Vec<GrantType>>,

    /// `None` = unchanged.
    pub require_pkce: Option<bool>,

    /// `None` = unchanged.
    pub allowed_scopes: Option<Vec<String>>,

    /// `None` = unchanged. Setting `Some(true)` requires SystemAdmin
    /// (enforced by Rego policy, not this type).
    pub pre_authorized: Option<bool>,

    /// `None` = unchanged.
    pub enabled: Option<bool>,

    /// `None` = unchanged.
    pub claims_template: Option<HashMap<String, String>>,

    /// `None` = unchanged.
    pub name: Option<String>,

    /// `None` = unchanged, empty string = clear.
    pub description: Option<String>,

    /// `None` = unchanged, empty string = clear.
    pub logo_uri: Option<String>,

    /// `None` = unchanged, empty string = clear.
    pub policy_uri: Option<String>,

    /// `None` = unchanged, empty string = clear.
    pub tos_uri: Option<String>,

    /// `None` = unchanged.
    pub contacts: Option<Vec<String>>,

    /// `None` = unchanged.
    pub post_logout_redirect_uris: Option<Vec<String>>,

    /// `None` = unchanged, empty string = clear.
    pub backchannel_logout_uri: Option<String>,

    /// `None` = unchanged.
    pub backchannel_logout_session_required: Option<bool>,

    /// `None` = unchanged, empty string = clear.
    pub frontchannel_logout_uri: Option<String>,

    /// `None` = unchanged.
    pub frontchannel_logout_session_required: Option<bool>,

    /// `None` = unchanged.
    #[serde(default)]
    #[builder(default)]
    pub spiffe_ids: Option<Vec<String>>,

    /// `None` = unchanged, otherwise replaces the whole policy.
    #[serde(default)]
    #[builder(default)]
    pub delegation: Option<DelegationPolicy>,

    /// Remove the delegation policy. Mutually exclusive with `delegation`.
    #[serde(default)]
    #[builder(default)]
    pub remove_delegation: bool,

    /// `None` = unchanged.
    #[serde(default)]
    #[builder(default)]
    pub dpop_bound_access_tokens: Option<bool>,
}

/// Filter parameters for `GET /v4/oauth2/{domain_id}/clients`.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct OAuth2ClientResourceListParameters {
    /// Domain to list clients for.
    pub domain_id: String,

    /// Restrict to enabled/disabled clients.
    #[builder(default)]
    pub enabled: Option<bool>,

    /// Restrict to clients whose name contains this substring
    /// (case-insensitive).
    #[builder(default)]
    pub name: Option<String>,

    #[builder(default)]
    pub pagination: crate::ListPagination,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> OAuth2ClientResource {
        OAuth2ClientResourceBuilder::default()
            .client_id("c")
            .provider_id("p")
            .domain_id("d")
            .token_endpoint_auth_method("client_secret_basic")
            .enabled(true)
            .created_at(0)
            .updated_at(0)
            .build()
            .unwrap()
    }

    fn update(value: Option<bool>) -> OAuth2ClientResourceUpdate {
        OAuth2ClientResourceUpdate {
            dpop_bound_access_tokens: value,
            ..Default::default()
        }
    }

    #[test]
    fn test_with_update_dpop_bound_access_tokens_tristate() {
        let off = sample();
        assert!(!off.dpop_bound_access_tokens);

        let on = off.with_update(update(Some(true)), 1);
        assert!(on.dpop_bound_access_tokens);
        // `None` leaves the flag unchanged in either state.
        let on = on.with_update(update(None), 2);
        assert!(on.dpop_bound_access_tokens);
        let off = on.with_update(update(Some(false)), 3);
        assert!(!off.dpop_bound_access_tokens);
        let off = off.with_update(update(None), 4);
        assert!(!off.dpop_bound_access_tokens);
    }

    /// A record stored before the flag existed must stay readable and
    /// default to bearer.
    #[test]
    fn test_dpop_bound_access_tokens_defaults_for_old_records() {
        let mut value = serde_json::to_value(sample()).unwrap();
        assert!(
            value
                .as_object_mut()
                .unwrap()
                .remove("dpop_bound_access_tokens")
                .is_some()
        );
        let record: OAuth2ClientResource = serde_json::from_value(value).unwrap();
        assert!(!record.dpop_bound_access_tokens);
    }
}
