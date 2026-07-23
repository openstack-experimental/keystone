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

use crate::v3::region as api_types;

impl From<provider_types::Region> for api_types::Region {
    fn from(value: provider_types::Region) -> Self {
        Self {
            id: value.id,
            description: value.description,
            parent_region_id: value.parent_region_id,
            extra: value.extra,
        }
    }
}

impl From<api_types::RegionListParameters> for provider_types::RegionListParameters {
    fn from(value: api_types::RegionListParameters) -> Self {
        Self {
            parent_region_id: value.parent_region_id,
        }
    }
}

impl From<api_types::RegionCreateRequest> for provider_types::RegionCreate {
    fn from(value: api_types::RegionCreateRequest) -> Self {
        Self {
            id: value.region.id,
            description: value.region.description,
            parent_region_id: value.region.parent_region_id,
            extra: value.region.extra,
        }
    }
}

impl From<api_types::RegionUpdateRequest> for provider_types::RegionUpdate {
    fn from(value: api_types::RegionUpdateRequest) -> Self {
        Self {
            description: value.region.description,
            parent_region_id: value.region.parent_region_id,
            extra: value.region.extra,
        }
    }
}
