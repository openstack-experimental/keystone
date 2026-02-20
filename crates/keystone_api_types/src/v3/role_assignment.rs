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

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::{Validate, ValidationErrors};

use crate::error::BuilderError;

/// Assignment.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Assignment {
    /// Group.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub group: Option<Group>,

    /// Role.
    #[validate(nested)]
    pub role: Role,

    /// Target scope.
    #[validate(nested)]
    pub scope: Scope,

    /// User.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub user: Option<User>,
}

/// Role.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct Role {
    /// The role ID.
    #[validate(length(max = 64))]
    pub id: String,

    /// The role name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct User {
    #[validate(length(max = 64))]
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct Group {
    #[validate(length(max = 64))]
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct Project {
    #[validate(length(max = 64))]
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct Domain {
    #[validate(length(max = 64))]
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct System {
    #[validate(length(max = 64))]
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Project(Project),
    Domain(Domain),
    System(System),
}

impl Validate for Scope {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            Self::Project(project) => project.validate(),
            Self::Domain(domain) => domain.validate(),
            Self::System(system) => system.validate(),
        }
    }
}

/// Assignments.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct AssignmentList {
    /// Collection of role assignment objects.
    #[validate(nested)]
    pub role_assignments: Vec<Assignment>,
}

impl IntoResponse for AssignmentList {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// List role assignments query parameters.
#[derive(Clone, Debug, Default, Deserialize, Serialize, IntoParams, Validate)]
pub struct RoleAssignmentListParameters {
    /// Filters the response by a domain ID.
    #[serde(rename = "scope.domain.id")]
    #[validate(length(max = 64))]
    pub domain_id: Option<String>,

    /// Filters the response by a group ID.
    #[serde(rename = "group.id")]
    #[validate(length(max = 64))]
    pub group_id: Option<String>,

    /// Returns the effective assignments, including any assignments gained by
    /// virtue of group membership.
    pub effective: Option<bool>,

    /// Filters the response by a project ID.
    #[serde(rename = "scope.project.id")]
    #[validate(length(max = 64))]
    pub project_id: Option<String>,

    /// Filters the response by a role ID.
    #[serde(rename = "role.id")]
    #[validate(length(max = 64))]
    pub role_id: Option<String>,

    /// Filters the response by a user ID.
    #[serde(rename = "user.id")]
    #[validate(length(max = 64))]
    pub user_id: Option<String>,

    /// If set to true, then the names of any entities returned will be include
    /// as well as their IDs. Any value other than 0 (including no value)
    /// will be interpreted as true.
    #[serde(default)]
    pub include_names: Option<bool>,
}
