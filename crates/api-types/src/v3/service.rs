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

/// The service data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Service {
    /// Service ID.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,
    /// The service type.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub r#type: Option<String>,
    /// Defines whether the service and its endpoints appear in the service
    /// catalog.
    pub enabled: bool,
    /// The service name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: Option<String>,

    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ServiceResponse {
    /// Service object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub service: Service,
}

/// Services.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ServiceList {
    /// Collection of service objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub services: Vec<Service>,

    /// Pagination links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<crate::Link>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ServiceListParameters {
    /// Filters the response by a service name.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: Option<String>,
    /// Filters the response by a service type.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub r#type: Option<String>,
}

/// Service create request body.
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
pub struct ServiceCreate {
    /// The service type.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub r#type: Option<String>,

    /// Defines whether the service and its endpoints appear in the service
    /// catalog.
    #[cfg_attr(feature = "builder", builder(default = "crate::default_true()"))]
    #[serde(default = "crate::default_true")]
    pub enabled: bool,

    /// The service name.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: Option<String>,

    /// Extra attributes for the service.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// New service creation request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ServiceCreateRequest {
    /// Service object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub service: ServiceCreate,
}

/// Update service data.
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
pub struct ServiceUpdate {
    /// The service type.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub r#type: Option<String>,

    /// Defines whether the service and its endpoints appear in the service
    /// catalog.
    #[cfg_attr(feature = "builder", builder(default))]
    pub enabled: Option<bool>,

    /// The service name.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: Option<String>,

    /// Extra attributes for the service (replaces the existing extra).
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Service update request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ServiceUpdateRequest {
    /// Service object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub service: ServiceUpdate,
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_service_create_deserialize_omitted_enabled_defaults_true() {
        // Mirrors DomainCreate: real clients omit `enabled` on create and
        // expect it to default to true rather than 422.
        let sot: super::ServiceCreate = serde_json::from_str(r#"{"type": "identity"}"#).unwrap();
        assert!(sot.enabled);
    }
}
