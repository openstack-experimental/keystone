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
//! Token restriction types.

use openstack_keystone_core_types::token as provider_types;

use crate::v4::token_restriction as api_types;

impl From<api_types::TokenRestrictionListParameters>
    for provider_types::TokenRestrictionListParameters
{
    fn from(value: api_types::TokenRestrictionListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            user_id: value.user_id,
            project_id: value.project_id,
        }
    }
}

impl From<provider_types::TokenRestriction> for api_types::TokenRestriction {
    fn from(value: provider_types::TokenRestriction) -> Self {
        Self {
            allow_rescope: value.allow_rescope,
            allow_renew: value.allow_renew,
            id: value.id,
            domain_id: value.domain_id,
            project_id: value.project_id,
            user_id: value.user_id,
            roles: value
                .roles
                .map(|roles| roles.into_iter().map(Into::into).collect())
                .unwrap_or_default(),
        }
    }
}

impl From<api_types::TokenRestrictionCreateRequest> for provider_types::TokenRestrictionCreate {
    fn from(value: api_types::TokenRestrictionCreateRequest) -> Self {
        Self {
            allow_rescope: value.restriction.allow_rescope,
            allow_renew: value.restriction.allow_renew,
            id: String::new(),
            domain_id: value.restriction.domain_id,
            project_id: value.restriction.project_id,
            user_id: value.restriction.user_id,
            role_ids: value
                .restriction
                .roles
                .into_iter()
                .map(|role| role.id)
                .collect(),
        }
    }
}

impl From<api_types::TokenRestrictionUpdateRequest> for provider_types::TokenRestrictionUpdate {
    fn from(value: api_types::TokenRestrictionUpdateRequest) -> Self {
        Self {
            allow_rescope: value.restriction.allow_rescope,
            allow_renew: value.restriction.allow_renew,
            project_id: value.restriction.project_id,
            user_id: value.restriction.user_id,
            role_ids: value
                .restriction
                .roles
                .map(|roles| roles.into_iter().map(|role| role.id).collect()),
        }
    }
}
