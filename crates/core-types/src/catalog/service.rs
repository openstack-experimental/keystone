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
pub struct Service {
    /// Defines whether the service and its endpoints appear in the service
    /// catalog: - false. The service and its endpoints do not appear in the
    /// service catalog. - true. The service and its endpoints appear in the
    /// service catalog.
    pub enabled: bool,

    /// Additional service properties.
    #[builder(default)]
    pub extra: Option<Value>,

    /// The ID of the service.
    #[validate(length(min = 1, max = 64))]
    pub id: String,

    /// The service type.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub r#type: Option<String>,
}

impl Service {
    /// Returns the service name, if set.
    ///
    /// The name is not a dedicated database column; it is stored as the `name`
    /// key inside the `extra` JSON blob, so it is read back out from there
    /// rather than being a field on the model itself.
    pub fn name(&self) -> Option<String> {
        self.extra
            .as_ref()
            .and_then(|extra| extra.get("name"))
            .and_then(|name| name.as_str())
            .map(ToString::to_string)
    }
}

/// Parameters for creating a new service.
#[derive(Clone, Debug, Default, PartialEq, Validate)]
pub struct ServiceCreate {
    /// Whether the service and its endpoints appear in the service catalog.
    pub enabled: bool,

    /// Additional service properties.
    pub extra: HashMap<String, Value>,

    /// The ID of the service. A UUID is generated when omitted.
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,

    /// The service type.
    #[validate(length(max = 255))]
    pub r#type: Option<String>,
}

#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct ServiceListParameters {
    /// Filters the response by a service name.
    pub name: Option<String>,

    /// Filters the response by a service type. A valid value is compute, ec2,
    /// identity, image, network, or volume.
    #[validate(length(max = 255))]
    pub r#type: Option<String>,
}

/// Fields that can be changed when updating a service.
///
/// Each field is `None` when the caller did not provide it (leave unchanged)
/// and `Some(..)` to set a new value.
#[derive(Clone, Debug, Default, PartialEq, Validate)]
pub struct ServiceUpdate {
    /// New enabled flag.
    pub enabled: Option<bool>,

    /// New additional service properties (replaces the existing `extra`).
    pub extra: Option<HashMap<String, Value>>,

    /// New service type.
    #[validate(length(max = 255))]
    pub r#type: Option<String>,
}
