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
//! # API Key (SCIM ingress) resource
//!
//! See ADR 0021 (Stateless API-Key Ingress & Ephemeral Security Contexts for
//! SCIM) for the full design.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::error::BuilderError;

/// A domain-owned machine identity credential used for stateless SCIM
/// ingress authentication (ADR 0021 §2).
///
/// Indexed in storage by `lookup_hash` (fast, non-secret SHA-256 digest of
/// the token entropy) under
/// `data:api_client:v1:<domain_id>:<lookup_hash>`. `client_id` is the public
/// UUID handed to administrators for CRUD operations and is never embedded
/// in the token itself.
#[derive(Builder, Clone, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ApiClientResource {
    /// Domain owning this machine identity.
    pub domain_id: String,

    /// The Unified Mapping Engine (ADR 0020) `provider_id` this key
    /// authenticates against. Multiple keys may share a `provider_id` to
    /// support zero-downtime rotation (ADR 0021 §5.D).
    pub provider_id: String,

    /// Public UUID used for management API references. Never embedded in
    /// the token or HTTP headers.
    pub client_id: String,

    /// `SHA-256(entropy)`, used as the fast O(1) storage index.
    pub lookup_hash: String,

    /// PHC-formatted Argon2id hash of the token entropy, used for
    /// cryptographic verification.
    pub secret_hash: String,

    /// CIDR allowlist restricting the source IP of the request. `None`
    /// means no restriction applies (ADR 0021 Invariant 5); a missing field
    /// and `Some(vec![])` MUST be treated identically.
    #[builder(default)]
    pub allowed_ips: Option<Vec<String>>,

    /// Free-form administrative description.
    #[builder(default)]
    pub description: Option<String>,

    /// Whether the key currently authenticates. Cleared by revocation and
    /// by the janitor on inactivity (ADR 0021 §6.F).
    pub enabled: bool,

    /// UTC epoch seconds.
    pub created_at: i64,

    /// Mandatory TTL, UTC epoch seconds.
    pub expires_at: i64,

    /// UTC epoch seconds of the last successful authentication. Updated
    /// asynchronously and thus may lag actual usage (ADR 0021 §6.F).
    #[builder(default)]
    pub last_used_at: Option<i64>,

    /// Tombstone timestamp for audit retention. Set by revocation; the key
    /// is never hard-deleted at revoke time (ADR 0021 §5.C).
    #[builder(default)]
    pub revoked_at: Option<i64>,

    /// User ID of the operator who revoked the key.
    #[builder(default)]
    pub revoked_by: Option<String>,
}

impl std::fmt::Debug for ApiClientResource {
    /// Redacts `secret_hash` to prevent leaking the Argon2id PHC string into
    /// application error logs (ADR 0021 §2.B).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiClientResource")
            .field("domain_id", &self.domain_id)
            .field("provider_id", &self.provider_id)
            .field("client_id", &self.client_id)
            .field("lookup_hash", &self.lookup_hash)
            .field("secret_hash", &"[REDACTED]")
            .field("allowed_ips", &self.allowed_ips)
            .field("description", &self.description)
            .field("enabled", &self.enabled)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("last_used_at", &self.last_used_at)
            .field("revoked_at", &self.revoked_at)
            .field("revoked_by", &self.revoked_by)
            .finish()
    }
}

impl ApiClientResource {
    /// Whether the key is currently usable for authentication: enabled and
    /// not past its TTL (ADR 0021 §3 Step 2).
    pub fn is_active(&self, now_utc_seconds: i64) -> bool {
        self.enabled && now_utc_seconds < self.expires_at
    }

    /// Apply a partial [`ApiClientResourceUpdate`], returning the new
    /// version to persist.
    pub fn with_update(self, update: ApiClientResourceUpdate) -> Self {
        Self {
            description: match update.description {
                Some(new_description) => new_description,
                None => self.description,
            },
            allowed_ips: match update.allowed_ips {
                Some(new_allowed_ips) => new_allowed_ips,
                None => self.allowed_ips,
            },
            enabled: update.enabled.unwrap_or(self.enabled),
            ..self
        }
    }

    /// Apply the emergency revocation path (ADR 0021 §5.C): disables the
    /// key and stamps the tombstone, without deleting the record.
    pub fn revoke(self, revoked_by: impl Into<String>, revoked_at: i64) -> Self {
        Self {
            enabled: false,
            revoked_at: Some(revoked_at),
            revoked_by: Some(revoked_by.into()),
            ..self
        }
    }
}

/// Input to create a new [`ApiClientResource`]. `lookup_hash` and
/// `secret_hash` are computed by the token generation utility before
/// reaching the provider; the plaintext token is never part of this
/// structure.
#[derive(Builder, Clone, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ApiClientResourceCreate {
    /// Domain owning this machine identity.
    pub domain_id: String,

    /// The Unified Mapping Engine (ADR 0020) `provider_id` this key
    /// authenticates against.
    pub provider_id: String,

    /// Public UUID used for management API references.
    pub client_id: String,

    /// `SHA-256(entropy)`, used as the fast O(1) storage index.
    pub lookup_hash: String,

    /// PHC-formatted Argon2id hash of the token entropy.
    pub secret_hash: String,

    /// CIDR allowlist restricting the source IP of the request.
    #[builder(default)]
    pub allowed_ips: Option<Vec<String>>,

    /// Free-form administrative description.
    #[builder(default)]
    pub description: Option<String>,

    /// Mandatory TTL, UTC epoch seconds.
    pub expires_at: i64,
}

impl std::fmt::Debug for ApiClientResourceCreate {
    /// Redacts `secret_hash`; see [`ApiClientResource::fmt`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiClientResourceCreate")
            .field("domain_id", &self.domain_id)
            .field("provider_id", &self.provider_id)
            .field("client_id", &self.client_id)
            .field("lookup_hash", &self.lookup_hash)
            .field("secret_hash", &"[REDACTED]")
            .field("allowed_ips", &self.allowed_ips)
            .field("description", &self.description)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Partial update for an [`ApiClientResource`] (`PUT
/// /v4/api-keys/{client_id}`).
///
/// `allowed_ips` and `description` use nested `Option`s: the outer `None`
/// means "leave unchanged", while `Some(None)` explicitly clears the field
/// (for `allowed_ips`, `Some(None)` removes the IP restriction entirely per
/// ADR 0021 Invariant 5).
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(build_fn(error = "BuilderError"))]
pub struct ApiClientResourceUpdate {
    /// `None` = unchanged. `Some(None)` = clear. `Some(Some(ips))` = set.
    pub allowed_ips: Option<Option<Vec<String>>>,

    /// `None` = unchanged. `Some(None)` = clear. `Some(Some(desc))` = set.
    pub description: Option<Option<String>>,

    /// `None` = unchanged.
    pub enabled: Option<bool>,
}

/// Filter parameters for `GET /v4/api-keys`.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ApiClientResourceListParameters {
    /// Domain to list keys for.
    pub domain_id: String,

    /// Restrict to keys bound to this `provider_id`.
    #[builder(default)]
    pub provider_id: Option<String>,

    /// Restrict to enabled/disabled keys.
    #[builder(default)]
    pub enabled: Option<bool>,

    #[builder(default)]
    pub pagination: crate::ListPagination,
}
