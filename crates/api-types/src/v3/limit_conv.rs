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
//! Limit API types conversions.

use openstack_keystone_core_types::limit as provider_types;

use crate::v3::limit as api_types;

impl From<provider_types::Limit> for api_types::Limit {
    fn from(value: provider_types::Limit) -> Self {
        Self {
            id: value.id,
            service_id: value.service_id,
            region_id: value.region_id,
            resource_name: value.resource_name,
            resource_limit: value.resource_limit,
            project_id: value.project_id,
            domain_id: value.domain_id,
            description: value.description,
        }
    }
}

impl From<provider_types::LimitModel> for api_types::LimitModel {
    fn from(value: provider_types::LimitModel) -> Self {
        Self {
            name: value.name,
            description: value.description,
        }
    }
}

impl From<api_types::LimitListParameters> for provider_types::LimitListParameters {
    fn from(value: api_types::LimitListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            pagination: Default::default(),
            project_id: value.project_id,
            project_ids: None,
            region_id: value.region_id,
            resource_name: value.resource_name,
            service_id: value.service_id,
        }
    }
}

impl From<api_types::LimitCreate> for provider_types::LimitCreate {
    fn from(value: api_types::LimitCreate) -> Self {
        Self {
            description: value.description,
            domain_id: value.domain_id,
            id: None,
            project_id: value.project_id,
            region_id: value.region_id,
            resource_limit: value.resource_limit,
            resource_name: value.resource_name,
            service_id: value.service_id,
        }
    }
}

impl From<api_types::LimitCreateRequest> for Vec<provider_types::LimitCreate> {
    fn from(value: api_types::LimitCreateRequest) -> Self {
        value.limits.into_iter().map(Into::into).collect()
    }
}

impl From<api_types::LimitUpdateRequest> for provider_types::LimitUpdate {
    fn from(value: api_types::LimitUpdateRequest) -> Self {
        Self {
            description: value.limit.description,
            resource_limit: value.limit.resource_limit,
        }
    }
}
