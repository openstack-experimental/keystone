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
//! Token restriction types.
use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

use crate::v3::role::RoleRef;

/// Token restriction data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "builder", derive(derive_builder::Builder))]
#[cfg_attr(feature = "builder", builder(setter(strip_option, into)))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TokenRestriction {
    /// Allow token renew.
    pub allow_renew: bool,

    /// Allow token rescope.
    pub allow_rescope: bool,

    /// Domain ID the token restriction belongs to.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: String,

    /// Token restriction ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: String,

    /// Project ID that the token must be bound to.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub project_id: Option<String>,

    /// User ID that the token must be bound to.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub user_id: Option<String>,

    /// Bound token roles.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub roles: Vec<RoleRef>,
}

/// New token restriction data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "builder", derive(derive_builder::Builder))]
#[cfg_attr(feature = "builder", builder(setter(strip_option, into)))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TokenRestrictionCreate {
    /// Allow token renew.
    pub allow_renew: bool,

    /// Allow token rescope.
    pub allow_rescope: bool,

    /// Domain ID the token restriction belongs to.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: String,

    /// Project ID that the token must be bound to.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub project_id: Option<String>,

    /// User ID that the token must be bound to.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    /// Bound token roles.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub roles: Vec<RoleRef>,
}

/// New token restriction data.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "builder", derive(derive_builder::Builder))]
#[cfg_attr(feature = "builder", builder(setter(strip_option, into)))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TokenRestrictionUpdate {
    /// Allow token renew.
    pub allow_renew: Option<bool>,

    /// Allow token rescope.
    pub allow_rescope: Option<bool>,

    /// Project ID that the token must be bound to.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub project_id: Option<Option<String>>,

    /// User ID that the token must be bound to.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub user_id: Option<Option<String>>,

    /// Bound token roles.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub roles: Option<Vec<RoleRef>>,
}

/// Token restriction data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "builder", derive(derive_builder::Builder))]
#[cfg_attr(feature = "builder", builder(setter(strip_option, into)))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TokenRestrictionResponse {
    /// Restriction object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub restriction: TokenRestriction,
}

/// Token restriction creation request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TokenRestrictionCreateRequest {
    /// Restriction object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub restriction: TokenRestrictionCreate,
}

/// Token restriction update request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TokenRestrictionUpdateRequest {
    /// Restriction object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub restriction: TokenRestrictionUpdate,
}

/// Token restriction list filters.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "builder", derive(derive_builder::Builder))]
#[cfg_attr(feature = "builder", builder(setter(strip_option, into)))]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TokenRestrictionListParameters {
    /// Domain id.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: Option<String>,
    /// User id.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub user_id: Option<String>,
    /// Project id.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub project_id: Option<String>,
}

/// Token restrictions.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TokenRestrictionList {
    /// Token restrictions.
    pub restrictions: Vec<TokenRestriction>,
}
