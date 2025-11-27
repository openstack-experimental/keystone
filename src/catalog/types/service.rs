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
pub struct Service {
    /// Additional service properties
    #[builder(default)]
    pub extra: Option<Value>,
    /// The ID of the service.
    pub id: String,
    /// The service type.
    #[builder(default)]
    pub r#type: Option<String>,
    /// The service name.
    #[builder(default)]
    pub name: Option<String>,
    /// Defines whether the service and its endpoints appear in the service
    /// catalog: - false. The service and its endpoints do not appear in the
    /// service catalog. - true. The service and its endpoints appear in the
    /// service catalog.
    pub enabled: bool,
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(strip_option, into))]
pub struct ServiceListParameters {
    /// Filters the response by a service name.
    pub name: Option<String>,
    /// Filters the response by a service type. A valid value is compute, ec2,
    /// identity, image, network, or volume.
    pub r#type: Option<String>,
}
