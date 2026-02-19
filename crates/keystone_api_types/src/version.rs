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
//! Keystone version API types
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::Link;

/// List of the supported API versions as [Values].
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct Versions {
    /// List of the versions.
    #[validate(nested)]
    pub versions: Values,
}

impl IntoResponse for Versions {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// A container with the [Version] list.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct Values {
    #[validate(nested)]
    pub values: Vec<Version>,
}

/// Single API version container.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct SingleVersion {
    /// The version.
    #[validate(nested)]
    pub version: Version,
}

impl IntoResponse for SingleVersion {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// Single API version.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct Version {
    /// Version id.
    #[validate(length(max = 5))]
    pub id: String,
    /// Version status.
    pub status: VersionStatus,
    /// Date of the version update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<DateTime<Utc>>,
    /// Links to the API version.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub links: Option<Vec<Link>>,
    /// Supported media types.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub media_types: Option<Vec<MediaType>>,
}

/// Version status.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub enum VersionStatus {
    /// Stable.
    #[default]
    #[serde(rename = "stable")]
    Stable,
    /// Experimental.
    #[serde(rename = "experimental")]
    Experimental,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct MediaType {
    pub base: String,
    pub r#type: String,
}

impl Default for MediaType {
    fn default() -> Self {
        Self {
            base: "application/json".into(),
            r#type: "application/vnd.openstack.identity-v3+json".into(),
        }
    }
}
