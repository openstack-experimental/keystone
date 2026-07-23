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

/// The endpoint data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Endpoint {
    /// Endpoint ID.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,
    /// The interface type, which describes the visibility of the endpoint
    /// (`public`, `internal`, or `admin`).
    #[cfg_attr(feature = "validate", validate(length(max = 8)))]
    pub interface: String,
    /// The ID of the region that contains the service endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub region_id: Option<String>,
    /// Deprecated alias for `region_id`, mirrored for clients still reading
    /// the pre-v3.2 attribute name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// The UUID of the service to which the endpoint belongs.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub service_id: String,
    /// The endpoint URL.
    pub url: String,
    /// Indicates whether the endpoint appears in the service catalog.
    pub enabled: bool,

    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct EndpointResponse {
    /// Endpoint object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub endpoint: Endpoint,
}

/// Endpoints.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct EndpointList {
    /// Collection of endpoint objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub endpoints: Vec<Endpoint>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct EndpointListParameters {
    /// Filters the response by an interface.
    #[cfg_attr(feature = "validate", validate(length(max = 8)))]
    pub interface: Option<String>,
    /// Filters the response by a service ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub service_id: Option<String>,
    /// Filters the response by a region ID.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub region_id: Option<String>,
}

/// Endpoint create request body.
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
pub struct EndpointCreate {
    /// The interface type, which describes the visibility of the endpoint
    /// (`public`, `internal`, or `admin`).
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 8)))]
    pub interface: String,

    /// The ID of the region that contains the service endpoint.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub region_id: Option<String>,

    /// The UUID of the service to which the endpoint belongs.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub service_id: String,

    /// The endpoint URL.
    pub url: String,

    /// Defines whether the endpoint appears in the service catalog.
    #[cfg_attr(feature = "builder", builder(default))]
    pub enabled: bool,

    /// Extra attributes for the endpoint.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// New endpoint creation request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct EndpointCreateRequest {
    /// Endpoint object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub endpoint: EndpointCreate,
}

/// Update endpoint data.
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
pub struct EndpointUpdate {
    /// The interface type, which describes the visibility of the endpoint
    /// (`public`, `internal`, or `admin`).
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 8)))]
    pub interface: Option<String>,

    /// The ID of the region that contains the service endpoint.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub region_id: Option<String>,

    /// The UUID of the service to which the endpoint belongs.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub service_id: Option<String>,

    /// The endpoint URL.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Defines whether the endpoint appears in the service catalog.
    #[cfg_attr(feature = "builder", builder(default))]
    pub enabled: Option<bool>,

    /// Extra attributes for the endpoint (replaces the existing extra).
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Endpoint update request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct EndpointUpdateRequest {
    /// Endpoint object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub endpoint: EndpointUpdate,
}
