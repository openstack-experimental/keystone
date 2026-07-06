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
//! # SCIM resource ownership index
//!
//! See ADR 0024 (SCIM v2 Resource Provisioning) §3.A for the full design.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::error::BuilderError;

/// The kind of core Identity resource a [`ScimResourceIndex`] anchors.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScimResourceType {
    /// A Keystone `User`.
    User,
    /// A Keystone `Group`.
    Group,
}

impl ScimResourceType {
    /// The lowercase key-segment representation used in storage keys.
    pub fn as_key_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
        }
    }
}

impl std::fmt::Display for ScimResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_key_str())
    }
}

/// Ownership anchor for a single SCIM-provisioned `User`/`Group`.
///
/// The sole authority for the Ownership Fencing Algorithm (ADR 0024 §3.C):
/// a resource is visible to a realm if and only if this index exists for
/// the caller's own `(domain_id, provider_id)` coordinate. Indexed in
/// storage at `data:scim_resource:v1:<domain_id>:<provider_id>:<type>:
/// <keystone_id>`.
#[derive(Builder, Clone, Debug, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ScimResourceIndex {
    /// Domain owning this resource.
    pub domain_id: String,

    /// The realm (`provider_id`) that created and exclusively owns this
    /// resource (ADR 0024 §3.C).
    pub provider_id: String,

    /// Whether this anchors a `User` or a `Group`.
    pub resource_type: ScimResourceType,

    /// The Keystone `User.id`/`Group.id` — also the SCIM `id`.
    pub keystone_id: String,

    /// The SCIM `externalId`, if the IdP supplied one. Realm-scoped unique
    /// (ADR 0024 §3.B/§3.C).
    #[builder(default)]
    pub external_id: Option<String>,

    /// Monotonic version, bumped on every write. Source of the SCIM ETag
    /// (§5.E, a later PR).
    #[builder(default)]
    pub version: u64,

    /// Set on soft-disable (ADR 0024 §6.A step 2). Once set, the resource is
    /// treated as absent (`404`) by all SCIM reads under this realm.
    #[builder(default)]
    pub deprovisioned_at: Option<i64>,

    /// UTC epoch seconds.
    pub created_at: i64,

    /// UTC epoch seconds.
    pub updated_at: i64,
}

impl ScimResourceIndex {
    /// Apply a partial [`ScimResourceIndexUpdate`], bumping `version` and
    /// `updated_at`.
    pub fn with_update(self, update: ScimResourceIndexUpdate, updated_at: i64) -> Self {
        Self {
            external_id: update.external_id.unwrap_or(self.external_id),
            deprovisioned_at: update.deprovisioned_at.unwrap_or(self.deprovisioned_at),
            version: self.version + 1,
            updated_at,
            ..self
        }
    }
}

/// Input to anchor a newly-created SCIM resource (ADR 0024 §3.A).
#[derive(Builder, Clone, Debug, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ScimResourceIndexCreate {
    /// Domain owning this resource.
    pub domain_id: String,

    /// The realm (`provider_id`) creating this resource.
    pub provider_id: String,

    /// Whether this anchors a `User` or a `Group`.
    pub resource_type: ScimResourceType,

    /// The Keystone `User.id`/`Group.id`.
    pub keystone_id: String,

    /// The SCIM `externalId`, if supplied.
    #[builder(default)]
    pub external_id: Option<String>,
}

/// Partial update for a [`ScimResourceIndex`]. `None` fields are left
/// unchanged; `Some(None)` explicitly clears the field.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(build_fn(error = "BuilderError"))]
pub struct ScimResourceIndexUpdate {
    /// `None` = unchanged. `Some(None)` clears `externalId`.
    #[builder(default)]
    pub external_id: Option<Option<String>>,

    /// `None` = unchanged. Stamped with `Some(Some(now))` on soft-disable
    /// (ADR 0024 §6.A step 2).
    #[builder(default)]
    pub deprovisioned_at: Option<Option<i64>>,
}
