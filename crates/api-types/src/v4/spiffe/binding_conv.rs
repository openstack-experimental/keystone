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
//! SPIFFE binding conversion implementations.

use openstack_keystone_core_types::spiffe as provider_types;

use crate::v4::spiffe::binding as api_types;

impl From<api_types::SpiffeAuthorization> for provider_types::SpiffeAuthorization {
    fn from(value: api_types::SpiffeAuthorization) -> Self {
        match value {
            api_types::SpiffeAuthorization::Domain {
                domain_id,
                role_ids,
            } => Self::Domain {
                domain_id,
                role_ids,
            },
            api_types::SpiffeAuthorization::Project {
                project_id,
                role_ids,
            } => Self::Project {
                project_id,
                role_ids,
            },
            api_types::SpiffeAuthorization::System {
                system_id,
                role_ids,
            } => Self::System {
                system_id,
                role_ids,
            },
        }
    }
}

impl From<provider_types::SpiffeAuthorization> for api_types::SpiffeAuthorization {
    fn from(value: provider_types::SpiffeAuthorization) -> Self {
        match value {
            provider_types::SpiffeAuthorization::Domain {
                domain_id,
                role_ids,
            } => Self::Domain {
                domain_id,
                role_ids,
            },
            provider_types::SpiffeAuthorization::Project {
                project_id,
                role_ids,
            } => Self::Project {
                project_id,
                role_ids,
            },
            provider_types::SpiffeAuthorization::System {
                system_id,
                role_ids,
            } => Self::System {
                system_id,
                role_ids,
            },
        }
    }
}

impl From<provider_types::SpiffeBinding> for api_types::SpiffeBinding {
    fn from(value: provider_types::SpiffeBinding) -> Self {
        Self {
            domain_id: value.domain_id,
            is_system: value.is_system,
            svid: value.svid,
            user_id: value.user_id,
            authorizations: value
                .authorizations
                .map(|auths| auths.into_iter().map(Into::into).collect()),
        }
    }
}

impl From<api_types::SpiffeBindingListParameters> for provider_types::SpiffeBindingListParameters {
    fn from(value: api_types::SpiffeBindingListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            user_id: value.user_id,
        }
    }
}

impl From<api_types::SpiffeBindingCreateRequest> for provider_types::SpiffeBindingCreate {
    fn from(value: api_types::SpiffeBindingCreateRequest) -> Self {
        Self {
            domain_id: value.binding.domain_id,
            is_system: value.binding.is_system,
            svid: value.binding.svid,
            user_id: value.binding.user_id,
            authorizations: value
                .binding
                .authorizations
                .map(|auths| auths.into_iter().map(Into::into).collect()),
        }
    }
}

impl From<api_types::SpiffeBindingUpdateRequest> for provider_types::SpiffeBindingUpdate {
    fn from(value: api_types::SpiffeBindingUpdateRequest) -> Self {
        Self {
            authorizations: value
                .binding
                .authorizations
                .map(|auths| auths.into_iter().map(Into::into).collect()),
        }
    }
}
