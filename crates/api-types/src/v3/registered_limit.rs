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
//! # Registered limits (`/v3/registered_limits`) API types.

use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

use crate::common::double_option;

/// The registered limit data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RegisteredLimit {
    /// The default limit value (`-1` means unlimited).
    #[cfg_attr(feature = "validate", validate(range(min = -1)))]
    pub default_limit: i32,

    /// The registered limit description.
    pub description: Option<String>,

    /// The registered limit ID.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,

    /// The ID of the region the limit is registered for.
    pub region_id: Option<String>,

    /// The name of the resource.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub resource_name: String,

    /// The ID of the service the limit is registered for.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub service_id: String,
}

/// The registered limit response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RegisteredLimitResponse {
    /// Registered limit object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub registered_limit: RegisteredLimit,
}

/// Registered limits.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RegisteredLimitList {
    /// Pagination links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<crate::Link>>,

    /// Collection of registered limit objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub registered_limits: Vec<RegisteredLimit>,
}

/// Query parameters for listing the registered limits.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RegisteredLimitListParameters {
    /// Filters the response by a region ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub region_id: Option<String>,

    /// Filters the response by a resource name.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub resource_name: Option<String>,

    /// Filters the response by a service ID.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub service_id: Option<String>,
}

/// New registered limit data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
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
pub struct RegisteredLimitCreate {
    /// The default limit value (`-1` means unlimited).
    #[cfg_attr(feature = "validate", validate(range(min = -1)))]
    pub default_limit: i32,

    /// The registered limit description.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The ID of the region the limit is registered for.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub region_id: Option<String>,

    /// The name of the resource.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub resource_name: String,

    /// The ID of the service the limit is registered for.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub service_id: String,
}

/// Registered limits creation request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RegisteredLimitCreateRequest {
    /// The registered limits to create (at least one).
    #[cfg_attr(feature = "validate", validate(length(min = 1), nested))]
    pub registered_limits: Vec<RegisteredLimitCreate>,
}

/// Update registered limit data.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
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
pub struct RegisteredLimitUpdate {
    /// New default limit value.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(range(min = -1)))]
    pub default_limit: Option<i32>,

    /// New description (`null` resets the description).
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, nullable))]
    pub description: Option<Option<String>>,

    /// New region ID (`null` resets the region).
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, nullable))]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub region_id: Option<Option<String>>,

    /// New resource name.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub resource_name: Option<String>,

    /// New service ID.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub service_id: Option<String>,
}

/// Registered limit update request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct RegisteredLimitUpdateRequest {
    /// Registered limit object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub registered_limit: RegisteredLimitUpdate,
}
