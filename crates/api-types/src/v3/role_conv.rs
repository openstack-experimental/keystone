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

use openstack_keystone_core_types::role as provider_types;

use crate::v3::role as api_types;

impl From<provider_types::Role> for api_types::Role {
    fn from(value: provider_types::Role) -> Self {
        Self {
            id: value.id,
            domain_id: value.domain_id,
            name: value.name,
            description: value.description,
            extra: value.extra,
        }
    }
}

impl From<provider_types::RoleRef> for api_types::RoleRef {
    fn from(value: provider_types::RoleRef) -> Self {
        Self {
            id: value.id,
            domain_id: value.domain_id,
            name: value.name.unwrap_or_default(),
        }
    }
}

impl From<api_types::RoleListParameters> for provider_types::RoleListParameters {
    fn from(value: api_types::RoleListParameters) -> Self {
        Self {
            domain_id: Some(value.domain_id),
            name: value.name,
        }
    }
}

impl From<api_types::RoleCreateRequest> for provider_types::RoleCreate {
    fn from(value: api_types::RoleCreateRequest) -> Self {
        Self {
            description: value.role.description,
            domain_id: value.role.domain_id,
            extra: value.role.extra,
            id: None,
            name: value.role.name,
        }
    }
}
