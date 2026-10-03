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
//! Registered limit API types conversions.

use openstack_keystone_core_types::limit as provider_types;

use crate::v3::registered_limit as api_types;

impl From<provider_types::RegisteredLimit> for api_types::RegisteredLimit {
    fn from(value: provider_types::RegisteredLimit) -> Self {
        Self {
            id: value.id,
            service_id: value.service_id,
            region_id: value.region_id,
            resource_name: value.resource_name,
            default_limit: value.default_limit,
            description: value.description,
        }
    }
}

impl From<api_types::RegisteredLimitListParameters>
    for provider_types::RegisteredLimitListParameters
{
    fn from(value: api_types::RegisteredLimitListParameters) -> Self {
        Self {
            pagination: Default::default(),
            region_id: value.region_id,
            resource_name: value.resource_name,
            service_id: value.service_id,
        }
    }
}

impl From<api_types::RegisteredLimitCreate> for provider_types::RegisteredLimitCreate {
    fn from(value: api_types::RegisteredLimitCreate) -> Self {
        Self {
            default_limit: value.default_limit,
            description: value.description,
            id: None,
            region_id: value.region_id,
            resource_name: value.resource_name,
            service_id: value.service_id,
        }
    }
}

impl From<api_types::RegisteredLimitCreateRequest> for Vec<provider_types::RegisteredLimitCreate> {
    fn from(value: api_types::RegisteredLimitCreateRequest) -> Self {
        value
            .registered_limits
            .into_iter()
            .map(Into::into)
            .collect()
    }
}

impl From<api_types::RegisteredLimitUpdateRequest> for provider_types::RegisteredLimitUpdate {
    fn from(value: api_types::RegisteredLimitUpdateRequest) -> Self {
        Self {
            default_limit: value.registered_limit.default_limit,
            description: value.registered_limit.description,
            region_id: value.registered_limit.region_id,
            resource_name: value.registered_limit.resource_name,
            service_id: value.registered_limit.service_id,
        }
    }
}
