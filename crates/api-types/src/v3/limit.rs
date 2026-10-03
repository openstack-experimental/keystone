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
//! # Limits (`/v3/limits`) API types.

use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

use crate::common::double_option;

/// The limit data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Limit {
    /// The limit description.
    pub description: Option<String>,

    /// The ID of the domain the limit is set for.
    pub domain_id: Option<String>,

    /// The limit ID.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,

    /// The ID of the project the limit is set for.
    pub project_id: Option<String>,

    /// The ID of the region.
    pub region_id: Option<String>,

    /// The limit value (`-1` means unlimited).
    #[cfg_attr(feature = "validate", validate(range(min = -1)))]
    pub resource_limit: i32,

    /// The name of the resource.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub resource_name: String,

    /// The ID of the service.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub service_id: String,
}

/// The limit response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct LimitResponse {
    /// Limit object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub limit: Limit,
}

/// Limits.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct LimitList {
    /// Pagination links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<crate::Link>>,

    /// Collection of limit objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub limits: Vec<Limit>,
}

/// Query parameters for listing the limits.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct LimitListParameters {
    /// Filters the response by a domain ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: Option<String>,

    /// Filters the response by a project ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub project_id: Option<String>,

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

/// New limit data.
///
/// Exactly one of `project_id` and `domain_id` must be set.
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
pub struct LimitCreate {
    /// The limit description.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The ID of the domain the limit is set for.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: Option<String>,

    /// The ID of the project the limit is set for.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub project_id: Option<String>,

    /// The ID of the region.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub region_id: Option<String>,

    /// The limit value (`-1` means unlimited).
    #[cfg_attr(feature = "validate", validate(range(min = -1)))]
    pub resource_limit: i32,

    /// The name of the resource.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub resource_name: String,

    /// The ID of the service.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub service_id: String,
}

/// Limits creation request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct LimitCreateRequest {
    /// The limits to create (at least one).
    #[cfg_attr(feature = "validate", validate(length(min = 1), nested))]
    pub limits: Vec<LimitCreate>,
}

/// Update limit data.
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
pub struct LimitUpdate {
    /// New description (`null` resets the description).
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, nullable))]
    pub description: Option<Option<String>>,

    /// New limit value.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(range(min = -1)))]
    pub resource_limit: Option<i32>,
}

/// Limit update request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct LimitUpdateRequest {
    /// Limit object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub limit: LimitUpdate,
}

/// The enforcement model.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LimitModel {
    /// The description of the model.
    pub description: String,

    /// The name of the model.
    pub name: String,
}

/// The enforcement model response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LimitModelResponse {
    /// The enforcement model.
    pub model: LimitModel,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_double_option() {
        let absent: LimitUpdate = serde_json::from_str(r#"{"resource_limit": 1}"#).unwrap();
        assert_eq!(None, absent.description);
        let null: LimitUpdate = serde_json::from_str(r#"{"description": null}"#).unwrap();
        assert_eq!(Some(None), null.description);
        let value: LimitUpdate = serde_json::from_str(r#"{"description": "x"}"#).unwrap();
        assert_eq!(Some(Some("x".to_string())), value.description);
    }

    #[test]
    fn test_unknown_fields_are_rejected() {
        assert!(serde_json::from_str::<LimitUpdate>(r#"{"project_id": "x"}"#).is_err());
        assert!(
            serde_json::from_str::<LimitCreate>(
                r#"{"service_id": "s", "resource_name": "r", "resource_limit": 1, "id": "x"}"#
            )
            .is_err()
        );
    }
}
