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
//! SCIM realm API types (ADR 0024 §2).

use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

use crate::Link;

/// A registered SCIM realm.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ScimRealm {
    /// Domain owning this realm.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: String,

    /// The `provider_id` coordinate this realm authorizes for SCIM resource
    /// provisioning.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub provider_id: String,

    /// The federation `IdentityProvider.id` this realm provisions users for.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub idp_id: String,

    /// Administrative display name for the realm.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 256)))]
    pub display_name: String,

    /// Whether the realm currently authorizes SCIM resource provisioning.
    pub enabled: bool,

    /// UTC epoch seconds.
    pub created_at: i64,

    /// UTC epoch seconds.
    pub updated_at: i64,
}

/// SCIM realm creation payload.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ScimRealmCreate {
    /// Domain owning this realm.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: String,

    /// The `provider_id` coordinate this realm authorizes.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub provider_id: String,

    /// The federation `IdentityProvider.id` this realm provisions users for.
    /// Must resolve to an existing identity provider.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub idp_id: String,

    /// Administrative display name for the realm.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 256)))]
    pub display_name: String,
}

/// SCIM realm creation request wrapper.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ScimRealmCreateRequest {
    /// SCIM realm creation payload.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub scim_realm: ScimRealmCreate,
}

/// SCIM realm update payload. `None` fields are left unchanged.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ScimRealmUpdate {
    /// New linked `IdentityProvider.id`. Must resolve to an existing
    /// identity provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub idp_id: Option<String>,

    /// New display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 256)))]
    pub display_name: Option<String>,

    /// Enable/disable toggle (ADR 0024 §2.B, the Realm Activation Gate).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

/// SCIM realm update request wrapper.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ScimRealmUpdateRequest {
    /// SCIM realm update payload.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub scim_realm: ScimRealmUpdate,
}

/// SCIM realm response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ScimRealmResponse {
    /// SCIM realm object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub scim_realm: ScimRealm,
}

/// SCIM realm list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ScimRealmList {
    /// Pagination links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
    /// Collection of SCIM realms.
    pub scim_realms: Vec<ScimRealm>,
}

/// SCIM realm list query parameters.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ScimRealmListParameters {
    /// Domain to list realms for.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: String,

    /// Filter by enabled/disabled state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}
