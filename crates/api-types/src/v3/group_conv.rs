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

use openstack_keystone_core_types::identity as provider_types;

use crate::v3::group as api_types;

impl From<provider_types::Group> for api_types::Group {
    fn from(value: provider_types::Group) -> Self {
        Self {
            id: value.id,
            domain_id: value.domain_id,
            name: value.name,
            description: value.description,
            extra: value.extra,
        }
    }
}

impl From<api_types::GroupCreateRequest> for provider_types::GroupCreate {
    fn from(value: api_types::GroupCreateRequest) -> Self {
        let group = value.group;
        Self {
            id: None,
            name: group.name,
            domain_id: group.domain_id,
            extra: group.extra,
            description: group.description,
        }
    }
}

impl From<api_types::GroupListParameters> for provider_types::GroupListParameters {
    fn from(value: api_types::GroupListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            name: value.name,
        }
    }
}
