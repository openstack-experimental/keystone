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
//! SCIM realm conversion implementations.

use openstack_keystone_core_types::scim as core;

use crate::v4::scim_realm as api;

impl From<api::ScimRealmCreateRequest> for core::ScimRealmResourceCreate {
    fn from(value: api::ScimRealmCreateRequest) -> Self {
        Self {
            domain_id: value.scim_realm.domain_id,
            provider_id: value.scim_realm.provider_id,
            idp_id: value.scim_realm.idp_id,
            display_name: value.scim_realm.display_name,
        }
    }
}

impl From<api::ScimRealmUpdateRequest> for core::ScimRealmResourceUpdate {
    fn from(value: api::ScimRealmUpdateRequest) -> Self {
        value.scim_realm.into()
    }
}

impl From<api::ScimRealmUpdate> for core::ScimRealmResourceUpdate {
    fn from(value: api::ScimRealmUpdate) -> Self {
        Self {
            idp_id: value.idp_id,
            display_name: value.display_name,
            enabled: value.enabled,
        }
    }
}

impl From<core::ScimRealmResource> for api::ScimRealm {
    fn from(value: core::ScimRealmResource) -> Self {
        Self {
            domain_id: value.domain_id,
            provider_id: value.provider_id,
            idp_id: value.idp_id,
            display_name: value.display_name,
            enabled: value.enabled,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

impl From<api::ScimRealmListParameters> for core::ScimRealmResourceListParameters {
    fn from(value: api::ScimRealmListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            enabled: value.enabled,
            pagination: Default::default(),
        }
    }
}
