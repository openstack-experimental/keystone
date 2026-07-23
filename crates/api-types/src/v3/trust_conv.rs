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

use openstack_keystone_core_types::role::RoleRef as ProviderRoleRef;
use openstack_keystone_core_types::trust as provider_types;

use crate::v3::trust as api_types;

impl From<ProviderRoleRef> for api_types::TrustRoleRef {
    fn from(value: ProviderRoleRef) -> Self {
        Self {
            domain_id: value.domain_id,
            id: Some(value.id),
            name: value.name,
        }
    }
}

/// Converts a resolved `TrustRoleRef` (i.e. `id` filled in, either
/// originally or by the create handler's name lookup) into the provider
/// `RoleRef`.
impl From<api_types::TrustRoleRef> for ProviderRoleRef {
    fn from(value: api_types::TrustRoleRef) -> Self {
        Self {
            domain_id: value.domain_id,
            id: value.id.unwrap_or_default(),
            name: value.name,
        }
    }
}

impl From<provider_types::Trust> for api_types::Trust {
    fn from(value: provider_types::Trust) -> Self {
        Self {
            id: value.id,
            trustor_user_id: value.trustor_user_id,
            trustee_user_id: value.trustee_user_id,
            project_id: value.project_id,
            impersonation: value.impersonation,
            expires_at: value.expires_at,
            remaining_uses: value.remaining_uses,
            redelegated_trust_id: value.redelegated_trust_id,
            redelegation_count: value.redelegation_count,
            roles: value
                .roles
                .unwrap_or_default()
                .into_iter()
                .map(Into::into)
                .collect(),
            extra: value.extra,
        }
    }
}

impl From<api_types::TrustListParameters> for provider_types::TrustListParameters {
    fn from(value: api_types::TrustListParameters) -> Self {
        Self {
            include_deleted: value.include_deleted,
            ..Default::default()
        }
    }
}

impl From<api_types::TrustCreateRequest> for provider_types::TrustCreate {
    fn from(value: api_types::TrustCreateRequest) -> Self {
        let trust = value.trust;
        Self {
            id: trust.id,
            trustor_user_id: trust.trustor_user_id,
            trustee_user_id: trust.trustee_user_id,
            project_id: trust.project_id,
            impersonation: trust.impersonation,
            expires_at: trust.expires_at,
            remaining_uses: trust.remaining_uses,
            redelegated_trust_id: trust.redelegated_trust_id,
            redelegation_count: trust.redelegation_count,
            roles: trust.roles.into_iter().map(Into::into).collect(),
            extra: trust.extra,
        }
    }
}
