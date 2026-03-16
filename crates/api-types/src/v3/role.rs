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

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use validator::Validate;

/// The role data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Role {
    /// Role ID.
    #[validate(length(min = 1, max = 64))]
    pub id: String,
    /// Role domain ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(min = 1, max = 64))]
    pub domain_id: Option<String>,
    /// Role name.
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    /// Role description.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(min = 1, max = 255))]
    pub description: Option<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

/// The role reference data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RoleRef {
    /// Role domain ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(min = 1, max = 64))]
    pub domain_id: Option<String>,

    /// Role ID.
    #[validate(length(min = 1, max = 64))]
    pub id: String,

    /// Role name.
    #[validate(length(min = 1, max = 255))]
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RoleResponse {
    /// Role object.
    #[validate(nested)]
    pub role: Role,
}

/// Roles.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RoleList {
    /// Collection of role objects.
    #[validate(nested)]
    pub roles: Vec<Role>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct RoleListParameters {
    /// Filter users by Domain ID.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: Option<String>,
    /// Filter users by Name.
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
}

/// Role create request body.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RoleCreate {
    /// The role description.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(min = 1, max = 255))]
    pub description: Option<String>,

    /// The domain ID of the role.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(min = 1, max = 64))]
    pub domain_id: Option<String>,

    /// The role name.
    #[validate(length(min = 1, max = 255))]
    pub name: String,

    /// Extra attributes for the role.
    #[builder(default)]
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}
