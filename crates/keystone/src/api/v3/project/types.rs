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
//! Project API types.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use validator::Validate;

use crate::error::BuilderError;
use crate::resource::types as provider_types;

/// Short Project representation.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ProjectShort {
    /// The ID of the domain for the project.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: String,

    /// If set to true, project is enabled. If set to false, project is
    /// disabled.
    pub enabled: bool,

    /// The ID for the project.
    #[validate(length(min = 1, max = 64))]
    pub id: String,

    /// The name of the project.
    #[validate(length(min = 1, max = 255))]
    pub name: String,
}

/// Full project representation.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Project {
    /// The description of the project.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(min = 1, max = 255))]
    pub description: Option<String>,

    /// The ID of the domain for the project.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: String,

    /// If set to true, project is enabled. If set to false, project is
    /// disabled.
    pub enabled: bool,

    /// Additional project properties.
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,

    /// The ID for the project.
    #[validate(length(min = 1, max = 64))]
    pub id: String,

    /// Indicates whether the project also acts as a domain. If set to true,
    /// this project acts as both a project and domain. As a domain, the project
    /// provides a name space in which you can create users, groups, and other
    /// projects. If set to false, this project behaves as a regular project
    /// that contains only resources.
    pub is_domain: bool,

    /// The name of the project.
    #[validate(length(min = 1, max = 255))]
    pub name: String,

    /// The ID of the parent for the project.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(min = 1, max = 64))]
    pub parent_id: Option<String>,
}

/// New project data.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ProjectCreate {
    /// The description of the project.
    #[validate(length(min = 1, max = 255))]
    pub description: Option<String>,

    /// The ID of the domain for the project.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: String,

    /// If set to true, project is enabled. If set to false, project is
    /// disabled.
    pub enabled: bool,

    /// Additional project properties.
    #[serde(flatten)]
    pub extra: Option<Value>,

    /// Indicates whether the project also acts as a domain. If set to true,
    /// this project acts as both a project and domain. As a domain, the project
    /// provides a name space in which you can create users, groups, and other
    /// projects. If set to false, this project behaves as a regular project
    /// that contains only resources. Default is false. You cannot update this
    /// parameter after you create the project.
    pub is_domain: bool,

    /// The name of the project, which must be unique within the owning domain.
    /// A project can have the same name as its domain.
    #[validate(length(min = 1, max = 255))]
    pub name: String,

    // TODO: add options
    /// The ID of the parent of the project.
    ///
    /// If specified on project creation, this places the project within a
    /// hierarchy and implicitly defines the owning domain, which will be the
    /// same domain as the parent specified. If `parent_id` is not specified and
    /// `is_domain` is false, then the project will use its owning domain as its
    /// parent. If `is_domain` is true (i.e. the project is acting as a domain),
    /// then `parent_id` must not specified (or if it is, it must be null) since
    /// domains have no parents.
    ///
    /// `parent_id` is immutable, and can’t be updated after the project is
    /// created - hence a project cannot be moved within the hierarchy.
    #[validate(length(min = 1, max = 64))]
    pub parent_id: Option<String>,
}

/// Complete response with the project data.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct ProjectResponse {
    /// Project object.
    #[validate(nested)]
    pub project: Project,
}

/// New project creation request.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct ProjectCreateRequest {
    /// Project object.
    #[validate(nested)]
    pub project: ProjectCreate,
}

/// List of projects.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct ProjectShortList {
    /// Collection of project objects.
    #[validate(nested)]
    pub projects: Vec<ProjectShort>,
}

impl IntoResponse for ProjectShortList {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

impl From<provider_types::Project> for ProjectShort {
    fn from(value: provider_types::Project) -> Self {
        Self {
            domain_id: value.domain_id,
            enabled: value.enabled,
            id: value.id,
            name: value.name,
        }
    }
}

impl From<&provider_types::Project> for ProjectShort {
    fn from(value: &provider_types::Project) -> Self {
        Self {
            domain_id: value.domain_id.clone(),
            enabled: value.enabled,
            id: value.id.clone(),
            name: value.name.clone(),
        }
    }
}

impl From<provider_types::Project> for Project {
    fn from(value: provider_types::Project) -> Self {
        Self {
            description: value.description,
            domain_id: value.domain_id,
            enabled: value.enabled,
            extra: value.extra,
            id: value.id,
            is_domain: value.is_domain,
            name: value.name,
            parent_id: value.parent_id,
        }
    }
}

impl From<ProjectCreate> for provider_types::ProjectCreate {
    fn from(value: ProjectCreate) -> Self {
        Self {
            description: value.description,
            domain_id: value.domain_id,
            enabled: value.enabled,
            extra: value.extra,
            id: None,
            is_domain: value.is_domain,
            name: value.name,
            parent_id: value.parent_id,
        }
    }
}
