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

use derive_builder::Builder;
use serde_json::Value;
use validator::Validate;

use crate::error::BuilderError;

#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Endpoint {
    /// The ID of the endpoint.
    #[validate(length(min = 1, max = 64))]
    pub id: String,
    /// The interface type, which describes the visibility of the endpoint.
    /// Value is:
    ///   - public. Visible by end users on a publicly available network
    ///     interface.
    ///
    ///   - internal. Visible by end users on an unmetered internal network
    ///     interface.
    ///
    ///   - admin. Visible by administrative users on a secure network
    ///     interface.
    #[builder(default)]
    #[validate(length(max = 8))]
    pub interface: String,
    /// The ID of the region that contains the service endpoint.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub region_id: Option<String>,
    /// The UUID of the service to which the endpoint belongs.
    #[validate(length(max = 64))]
    pub service_id: String,
    /// The endpoint URL.
    pub url: String,
    /// Indicates whether the endpoint appears in the service catalog: - false.
    /// The endpoint does not appear in the service catalog. - true. The
    /// endpoint appears in the service catalog.
    pub enabled: bool,
    /// Additional endpoint properties.
    #[builder(default)]
    pub extra: Option<Value>,
}

/// Parameters for creating a new endpoint.
#[derive(Clone, Debug, Default, PartialEq, Validate)]
pub struct EndpointCreate {
    /// Whether the endpoint appears in the service catalog.
    pub enabled: bool,

    /// Additional endpoint properties.
    pub extra: HashMap<String, Value>,

    /// The ID of the endpoint. A UUID is generated when omitted.
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,

    /// The interface type (`public`, `internal`, or `admin`).
    #[validate(length(max = 8))]
    pub interface: String,

    /// The ID of the region that contains the endpoint.
    #[validate(length(max = 255))]
    pub region_id: Option<String>,

    /// The UUID of the service to which the endpoint belongs.
    #[validate(length(max = 64))]
    pub service_id: String,

    /// The endpoint URL.
    pub url: String,
}

#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct EndpointListParameters {
    /// Filters the response by an interface.
    #[validate(length(max = 8))]
    pub interface: Option<String>,
    /// Filters the response by a service ID.
    #[validate(length(max = 64))]
    pub service_id: Option<String>,
    /// Filters the response by a region ID.
    #[validate(length(max = 255))]
    pub region_id: Option<String>,
}

/// Fields that can be changed when updating an endpoint.
///
/// Each field is `None` when the caller did not provide it (leave unchanged)
/// and `Some(..)` to set a new value.
#[derive(Clone, Debug, Default, PartialEq, Validate)]
pub struct EndpointUpdate {
    /// New enabled flag.
    pub enabled: Option<bool>,

    /// New additional endpoint properties (replaces the existing `extra`).
    pub extra: Option<HashMap<String, Value>>,

    /// New interface type.
    #[validate(length(max = 8))]
    pub interface: Option<String>,

    /// New region ID.
    #[validate(length(max = 255))]
    pub region_id: Option<String>,

    /// New service ID.
    #[validate(length(max = 64))]
    pub service_id: Option<String>,

    /// New endpoint URL.
    pub url: Option<String>,
}
