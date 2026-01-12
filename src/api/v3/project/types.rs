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
//! Project API types

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
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
