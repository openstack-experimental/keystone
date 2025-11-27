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

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(strip_option, into))]
pub struct Endpoint {
    /// The ID of the endpoint.
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
    pub interface: String,
    /// The ID of the region that contains the service endpoint.
    #[builder(default)]
    pub region_id: Option<String>,
    /// The UUID of the service to which the endpoint belongs.
    pub service_id: String,
    /// The endpoint URL.
    pub url: String,
    /// Indicates whether the endpoint appears in the service catalog: - false.
    /// The endpoint does not appear in the service catalog. - true. The
    /// endpoint appears in the service catalog.
    pub enabled: bool,
    /// Additional endpoint properties
    #[builder(default)]
    pub extra: Option<Value>,
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(strip_option, into))]
pub struct EndpointListParameters {
    /// Filters the response by an interface.
    pub interface: Option<String>,
    /// Filters the response by a service ID.
    pub service_id: Option<String>,
    /// Filters the response by a region ID.
    pub region_id: Option<String>,
}
