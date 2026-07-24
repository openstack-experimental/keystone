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

use openstack_keystone_core_types::catalog as provider_types;

use crate::v3::service as api_types;

impl From<provider_types::Service> for api_types::Service {
    fn from(value: provider_types::Service) -> Self {
        let name = value.name();
        let mut extra = value.extra;
        extra.remove("name");
        Self {
            id: value.id,
            r#type: value.r#type,
            enabled: value.enabled,
            name,
            extra,
        }
    }
}

impl From<api_types::ServiceListParameters> for provider_types::ServiceListParameters {
    fn from(value: api_types::ServiceListParameters) -> Self {
        Self {
            name: value.name,
            r#type: value.r#type,
            pagination: Default::default(),
        }
    }
}

impl From<api_types::ServiceCreateRequest> for provider_types::ServiceCreate {
    fn from(value: api_types::ServiceCreateRequest) -> Self {
        let mut extra = value.service.extra;
        if let Some(name) = value.service.name {
            extra.insert("name".to_string(), serde_json::Value::String(name));
        }
        Self {
            enabled: value.service.enabled,
            extra,
            id: None,
            r#type: value.service.r#type,
        }
    }
}

impl From<api_types::ServiceUpdateRequest> for provider_types::ServiceUpdate {
    fn from(value: api_types::ServiceUpdateRequest) -> Self {
        let mut extra = value.service.extra;
        if let Some(name) = value.service.name {
            extra.insert("name".to_string(), serde_json::Value::String(name));
        }
        Self {
            enabled: value.service.enabled,
            extra,
            r#type: value.service.r#type,
        }
    }
}
