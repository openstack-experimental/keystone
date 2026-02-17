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
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::role::types;

/// The role data.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
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

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct RoleResponse {
    /// Role object.
    #[validate(nested)]
    pub role: Role,
}

impl From<types::Role> for Role {
    fn from(value: types::Role) -> Self {
        Self {
            id: value.id,
            domain_id: value.domain_id,
            name: value.name,
            description: value.description,
            extra: value.extra,
        }
    }
}

impl IntoResponse for RoleResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

impl IntoResponse for types::Role {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            Json(RoleResponse {
                role: Role::from(self),
            }),
        )
            .into_response()
    }
}

/// Roles.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct RoleList {
    /// Collection of role objects.
    #[validate(nested)]
    pub roles: Vec<Role>,
}

impl From<Vec<types::Role>> for RoleList {
    fn from(value: Vec<types::Role>) -> Self {
        let objects: Vec<Role> = value.into_iter().map(Role::from).collect();
        Self { roles: objects }
    }
}

impl IntoResponse for RoleList {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, IntoParams, Validate)]
pub struct RoleListParameters {
    /// Filter users by Domain ID.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: Option<String>,
    /// Filter users by Name.
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
}

impl From<RoleListParameters> for types::RoleListParameters {
    fn from(value: RoleListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            name: value.name,
        }
    }
}

/// Role create request body.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct RoleCreate {
    /// The role description.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(min = 1, max = 255))]
    pub description: Option<String>,

    /// The domain ID of the role.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(min = 1, max = 64))]
    pub domain_id: Option<String>,

    /// The role name.
    #[validate(length(min = 1, max = 255))]
    pub name: String,

    /// Extra attributes for the role.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

impl From<RoleCreate> for types::RoleCreate {
    fn from(value: RoleCreate) -> Self {
        Self {
            description: value.description,
            domain_id: value.domain_id,
            extra: value.extra,
            id: None,
            name: value.name,
        }
    }
}
