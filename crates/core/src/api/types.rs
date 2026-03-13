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
pub use openstack_keystone_api_types::Link;
pub use openstack_keystone_api_types::catalog::*;
pub use openstack_keystone_api_types::scope::*;
pub use openstack_keystone_api_types::version::*;

use crate::catalog::types::Endpoint as ProviderEndpoint;
use crate::common::types as provider_types;
use crate::resource::types as resource_provider_types;

//impl From<(Service, Vec<ProviderEndpoint>)> for CatalogService {
//    fn from(value: (Service, Vec<ProviderEndpoint>)) -> Self {
//        Self {
//            id: value.0.id.clone(),
//            name: value.0.name.clone(),
//            r#type: value.0.r#type,
//            endpoints: value.1.into_iter().map(Into::into).collect(),
//        }
//    }
//}

impl From<ProviderEndpoint> for Endpoint {
    fn from(value: ProviderEndpoint) -> Self {
        Self {
            id: value.id.clone(),
            interface: value.interface.clone(),
            url: value.url.clone(),
            region: value.region_id.clone(),
            region_id: value.region_id.clone(),
        }
    }
}

//impl From<Vec<(Service, Vec<ProviderEndpoint>)>> for Catalog {
//    fn from(value: Vec<(Service, Vec<ProviderEndpoint>)>) -> Self {
//        Self(
//            value
//                .into_iter()
//                .map(|(srv, eps)| (srv, eps).into())
//                .collect(),
//        )
//    }
//}

impl From<resource_provider_types::Domain> for Domain {
    fn from(value: resource_provider_types::Domain) -> Self {
        Self {
            id: Some(value.id),
            name: Some(value.name),
        }
    }
}

impl From<&resource_provider_types::Domain> for Domain {
    fn from(value: &resource_provider_types::Domain) -> Self {
        Self {
            id: Some(value.id.clone()),
            name: Some(value.name.clone()),
        }
    }
}

impl From<Domain> for provider_types::Domain {
    fn from(value: Domain) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}

impl From<provider_types::Domain> for Domain {
    fn from(value: provider_types::Domain) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}

impl From<ScopeProject> for provider_types::Project {
    fn from(value: ScopeProject) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain: value.domain.map(Into::into),
        }
    }
}

impl From<provider_types::Project> for ScopeProject {
    fn from(value: provider_types::Project) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain: value.domain.map(Into::into),
        }
    }
}

impl From<&provider_types::Project> for ScopeProject {
    fn from(value: &provider_types::Project) -> Self {
        Self::from(value.clone())
    }
}

impl From<System> for provider_types::System {
    fn from(value: System) -> Self {
        Self { all: value.all }
    }
}

impl From<Scope> for provider_types::Scope {
    fn from(value: Scope) -> Self {
        match value {
            Scope::Project(scope) => Self::Project(scope.into()),
            Scope::Domain(scope) => Self::Domain(scope.into()),
            Scope::System(scope) => Self::System(scope.into()),
        }
    }
}
