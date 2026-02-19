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
//! Project API types.

pub use openstack_keystone_api_types::v3::project::*;

use crate::resource::types as provider_types;

impl From<provider_types::Project> for ProjectShort {
    fn from(value: provider_types::Project) -> Self {
        Self {
            domain_id: value.domain_id,
            enabled: value.enabled,
            id: value.id,
            name: value.name,
        }
    }
}

impl From<&provider_types::Project> for ProjectShort {
    fn from(value: &provider_types::Project) -> Self {
        Self {
            domain_id: value.domain_id.clone(),
            enabled: value.enabled,
            id: value.id.clone(),
            name: value.name.clone(),
        }
    }
}

impl From<provider_types::Project> for Project {
    fn from(value: provider_types::Project) -> Self {
        Self {
            description: value.description,
            domain_id: value.domain_id,
            enabled: value.enabled,
            extra: value.extra,
            id: value.id,
            is_domain: value.is_domain,
            name: value.name,
            parent_id: value.parent_id,
        }
    }
}

impl From<ProjectCreate> for provider_types::ProjectCreate {
    fn from(value: ProjectCreate) -> Self {
        Self {
            description: value.description,
            domain_id: value.domain_id,
            enabled: value.enabled,
            extra: value.extra,
            id: None,
            is_domain: value.is_domain,
            name: value.name,
            parent_id: value.parent_id,
        }
    }
}
