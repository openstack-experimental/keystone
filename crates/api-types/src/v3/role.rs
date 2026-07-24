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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "validate")]
use validator::Validate;

use crate::Link;

/// The role data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Role {
    /// Role ID.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,
    /// Role domain ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: Option<String>,
    /// Role name.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: String,
    /// Role description.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub description: Option<String>,

    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// The role reference data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RoleRef {
    /// Role domain ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: Option<String>,

    /// Role ID.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,

    /// Role name.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: String,
}

/// The role imply data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RoleImply {
    /// The prior role that implies another role.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub prior_role: RoleRef,

    /// The role that is implied by the prior role.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub implies: RoleRef,
}

/// Response for a single role inference rule.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RoleImplyResponse {
    /// The role inference rule.
    #[serde(rename = "role_inference")]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub role_inference: RoleImply,
}

/// Response for listing all role inference rules.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RoleInferencesList {
    /// Collection of role inference rules.
    #[serde(rename = "role_inferences")]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub role_inferences: Vec<ImplyGroup>,
}

/// Grouped structure for listing implied roles of a specific prior role.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ImplyGroup {
    /// The prior role.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub prior_role: RoleRef,
    /// List of roles that are implied by the prior role.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub implies: Vec<RoleRef>,
}

/// Response for listing implied roles by prior role.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RoleInferenceRules {
    /// The role inference group.
    #[serde(rename = "role_inference")]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub role_inference: ImplyGroup,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RoleResponse {
    /// Role object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub role: Role,
}

/// Roles.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RoleList {
    /// Collection of role objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub roles: Vec<Role>,

    /// Pagination links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RoleListParameters {
    /// Filter users by Domain ID.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: Option<String>,
    /// Filter users by Name.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: Option<String>,
}

/// Role create request body.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RoleCreate {
    /// The role description.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub description: Option<String>,

    /// The domain ID of the role.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: Option<String>,

    /// The role name.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: String,

    /// Extra attributes for the role.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// New role creation request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RoleCreateRequest {
    /// Role object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub role: RoleCreate,
}

/// Update role data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RoleUpdate {
    /// The role description.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub description: Option<String>,

    /// The role name.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: Option<String>,

    /// Extra attributes for the role.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Role update request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RoleUpdateRequest {
    /// Role object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub role: RoleUpdate,
}

impl From<&Role> for RoleRef {
    fn from(value: &Role) -> Self {
        Self {
            domain_id: value.domain_id.clone(),
            id: value.id.clone(),
            name: value.name.clone(),
        }
    }
}
