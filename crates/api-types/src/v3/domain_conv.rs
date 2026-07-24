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
//! Domain API types conversions.

use std::collections::HashSet;

use openstack_keystone_core_types::resource as provider_types;

use crate::v3::domain as api_types;

impl From<provider_types::Domain> for api_types::DomainShort {
    fn from(value: provider_types::Domain) -> Self {
        Self {
            enabled: value.enabled,
            id: value.id,
            name: value.name,
        }
    }
}

impl From<&provider_types::Domain> for api_types::DomainShort {
    fn from(value: &provider_types::Domain) -> Self {
        Self {
            enabled: value.enabled,
            id: value.id.clone(),
            name: value.name.clone(),
        }
    }
}

impl From<provider_types::Domain> for api_types::Domain {
    fn from(value: provider_types::Domain) -> Self {
        Self {
            description: value.description,
            enabled: value.enabled,
            extra: value.extra,
            id: value.id,
            name: value.name,
        }
    }
}

impl From<api_types::DomainCreate> for provider_types::DomainCreate {
    fn from(value: api_types::DomainCreate) -> Self {
        Self {
            description: value.description,
            enabled: value.enabled,
            extra: value.extra,
            id: value.id,
            name: value.name,
        }
    }
}

impl From<api_types::DomainUpdateRequest> for provider_types::DomainUpdate {
    fn from(value: api_types::DomainUpdateRequest) -> Self {
        let domain = value.domain;
        Self {
            description: domain.description.map(Some),
            enabled: domain.enabled,
            extra: domain.extra,
            name: domain.name,
        }
    }
}

impl From<api_types::DomainListParameters> for provider_types::DomainListParameters {
    fn from(value: api_types::DomainListParameters) -> Self {
        Self {
            ids: value.ids.map(|s| HashSet::from([s])),
            name: value.name,
            pagination: Default::default(),
        }
    }
}
