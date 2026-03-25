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
//! Keystone API types.
use crate::scope as api_types;
//
//use openstack_keystone_core_types::scope as provider_types;

impl From<openstack_keystone_core_types::resource::Domain> for api_types::Domain {
    fn from(value: openstack_keystone_core_types::resource::Domain) -> Self {
        Self {
            id: Some(value.id),
            name: Some(value.name),
        }
    }
}

impl From<&openstack_keystone_core_types::resource::Domain> for api_types::Domain {
    fn from(value: &openstack_keystone_core_types::resource::Domain) -> Self {
        Self {
            id: Some(value.id.clone()),
            name: Some(value.name.clone()),
        }
    }
}

impl From<api_types::Domain> for openstack_keystone_core_types::scope::Domain {
    fn from(value: api_types::Domain) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}

impl From<openstack_keystone_core_types::scope::Domain> for api_types::Domain {
    fn from(value: openstack_keystone_core_types::scope::Domain) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}

impl From<api_types::ScopeProject> for openstack_keystone_core_types::scope::Project {
    fn from(value: api_types::ScopeProject) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain: value.domain.map(Into::into),
        }
    }
}

impl From<openstack_keystone_core_types::scope::Project> for api_types::ScopeProject {
    fn from(value: openstack_keystone_core_types::scope::Project) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain: value.domain.map(Into::into),
        }
    }
}

impl From<&openstack_keystone_core_types::scope::Project> for api_types::ScopeProject {
    fn from(value: &openstack_keystone_core_types::scope::Project) -> Self {
        Self::from(value.clone())
    }
}

impl From<api_types::System> for openstack_keystone_core_types::scope::System {
    fn from(value: api_types::System) -> Self {
        Self { all: value.all }
    }
}

impl From<api_types::Scope> for openstack_keystone_core_types::scope::Scope {
    fn from(value: api_types::Scope) -> Self {
        match value {
            api_types::Scope::Project(scope) => Self::Project(scope.into()),
            api_types::Scope::Domain(scope) => Self::Domain(scope.into()),
            api_types::Scope::System(scope) => Self::System(scope.into()),
        }
    }
}
