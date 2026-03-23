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

use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

/// Assignment.
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
pub struct Assignment {
    /// Group.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub group: Option<Group>,

    /// Role.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub role: Role,

    /// Target scope.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub scope: Scope,

    /// User.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub user: Option<User>,
}

/// Role.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Role {
    /// The role ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: String,

    /// The role name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct User {
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Group {
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Project {
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Domain {
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct System {
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Project(Project),
    Domain(Domain),
    System(System),
}

#[cfg(feature = "validate")]
impl validator::Validate for Scope {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        match self {
            Self::Project(project) => project.validate(),
            Self::Domain(domain) => domain.validate(),
            Self::System(system) => system.validate(),
        }
    }
}

/// Assignments.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct AssignmentList {
    /// Collection of role assignment objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub role_assignments: Vec<Assignment>,
}

/// List role assignments query parameters.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RoleAssignmentListParameters {
    /// Filters the response by a domain ID.
    #[serde(rename = "scope.domain.id")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: Option<String>,

    /// Filters the response by a group ID.
    #[serde(rename = "group.id")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub group_id: Option<String>,

    /// Returns the effective assignments, including any assignments gained by
    /// virtue of group membership.
    pub effective: Option<bool>,

    /// Filters the response by a project ID.
    #[serde(rename = "scope.project.id")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub project_id: Option<String>,

    /// Filters the response by a role ID.
    #[serde(rename = "role.id")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub role_id: Option<String>,

    /// Filters the response by a user ID.
    #[serde(rename = "user.id")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub user_id: Option<String>,

    /// If set to true, then the names of any entities returned will be include
    /// as well as their IDs. Any value other than 0 (including no value)
    /// will be interpreted as true.
    #[serde(default)]
    pub include_names: Option<bool>,
}
