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
//! # SCIM realm resource
//!
//! See ADR 0024 (SCIM v2 Resource Provisioning) §2 for the full design.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::error::BuilderError;

/// A registered SCIM realm: the explicit administrative act that enables
/// SCIM Users/Groups resource provisioning for an `(domain_id, provider_id)`
/// coordinate already used by the Unified Mapping Engine (ADR 0020) and API
/// Key ingress (ADR 0021).
///
/// Creating an `ApiClientResource` (ADR 0021) alone does **not** enable SCIM
/// resource provisioning — a realm must be separately registered (ADR 0024
/// §2.A). Indexed in storage at `data:scim_realm:v1:<domain_id>:<provider_id>`.
#[derive(Builder, Clone, Debug, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ScimRealmResource {
    /// Domain owning this realm.
    pub domain_id: String,

    /// The Unified Mapping Engine (ADR 0020) / API Key (ADR 0021)
    /// `provider_id` this realm authorizes for SCIM resource provisioning.
    pub provider_id: String,

    /// The federation `IdentityProvider.id` this realm provisions users for.
    /// Mandatory: SCIM users are always created as `nonlocal_user` shadow
    /// identities keyed by a deterministic id derived from their `externalId`
    /// (see `openstack_keystone_core::identity::generate_public_id`), so
    /// there is no meaningful SCIM realm that isn't tied to a real IdP.
    pub idp_id: String,

    /// Administrative display name for the realm.
    pub display_name: String,

    /// Whether the realm currently authorizes SCIM resource provisioning
    /// (ADR 0024 §2.B, the Realm Activation Gate).
    pub enabled: bool,

    /// UTC epoch seconds.
    pub created_at: i64,

    /// UTC epoch seconds.
    pub updated_at: i64,
}

impl ScimRealmResource {
    /// Apply a partial [`ScimRealmResourceUpdate`], returning the new
    /// version to persist.
    pub fn with_update(self, update: ScimRealmResourceUpdate, updated_at: i64) -> Self {
        Self {
            idp_id: update.idp_id.unwrap_or(self.idp_id),
            display_name: update.display_name.unwrap_or(self.display_name),
            enabled: update.enabled.unwrap_or(self.enabled),
            updated_at,
            ..self
        }
    }
}

/// Input to register a new [`ScimRealmResource`] (ADR 0024 §2.A).
#[derive(Builder, Clone, Debug, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ScimRealmResourceCreate {
    /// Domain owning this realm.
    pub domain_id: String,

    /// The `provider_id` coordinate this realm authorizes.
    pub provider_id: String,

    /// The federation `IdentityProvider.id` this realm provisions users for.
    /// Must resolve to an existing `IdentityProvider` (validated by the
    /// caller) — realm creation is rejected otherwise.
    pub idp_id: String,

    /// Administrative display name for the realm.
    pub display_name: String,
}

/// Partial update for a [`ScimRealmResource`] (`PATCH
/// /v4/scim-realms/{domain_id}/{provider_id}`). `None` fields are left
/// unchanged.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(build_fn(error = "BuilderError"))]
pub struct ScimRealmResourceUpdate {
    /// `None` = unchanged. If set, must resolve to an existing
    /// `IdentityProvider` (validated by the caller) — rejected otherwise.
    pub idp_id: Option<String>,

    /// `None` = unchanged.
    pub display_name: Option<String>,

    /// `None` = unchanged. Used for the disable/enable toggle (ADR 0024 §2.B).
    pub enabled: Option<bool>,
}

/// Filter parameters for `GET /v4/scim-realms`.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ScimRealmResourceListParameters {
    /// Domain to list realms for.
    pub domain_id: String,

    /// Restrict to enabled/disabled realms.
    #[builder(default)]
    pub enabled: Option<bool>,

    #[builder(default)]
    pub pagination: crate::ListPagination,
}
