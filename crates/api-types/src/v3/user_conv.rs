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

use crate::v3::user as api_types;

impl From<provider_types::UserOptions> for api_types::UserOptions {
    fn from(value: provider_types::UserOptions) -> Self {
        Self {
            ignore_change_password_upon_first_use: value.ignore_change_password_upon_first_use,
            ignore_password_expiry: value.ignore_password_expiry,
            ignore_lockout_failure_attempts: value.ignore_lockout_failure_attempts,
            lock_password: value.lock_password,
            ignore_user_inactivity: value.ignore_user_inactivity,
            multi_factor_auth_rules: value.multi_factor_auth_rules,
            multi_factor_auth_enabled: value.multi_factor_auth_enabled,
        }
    }
}

impl From<api_types::UserOptions> for provider_types::UserOptions {
    fn from(value: api_types::UserOptions) -> Self {
        Self {
            ignore_change_password_upon_first_use: value.ignore_change_password_upon_first_use,
            ignore_password_expiry: value.ignore_password_expiry,
            ignore_lockout_failure_attempts: value.ignore_lockout_failure_attempts,
            lock_password: value.lock_password,
            ignore_user_inactivity: value.ignore_user_inactivity,
            multi_factor_auth_rules: value.multi_factor_auth_rules,
            multi_factor_auth_enabled: value.multi_factor_auth_enabled,
            is_service_account: None,
        }
    }
}

impl From<provider_types::UserResponse> for api_types::User {
    fn from(value: provider_types::UserResponse) -> Self {
        let opts: api_types::UserOptions = value.options.clone().into();
        // We only want to see user options if there is at least 1 option set
        let opts = if opts.ignore_change_password_upon_first_use.is_some()
            || opts.ignore_password_expiry.is_some()
            || opts.ignore_lockout_failure_attempts.is_some()
            || opts.lock_password.is_some()
            || opts.ignore_user_inactivity.is_some()
            || opts.multi_factor_auth_rules.is_some()
            || opts.multi_factor_auth_enabled.is_some()
        {
            Some(opts)
        } else {
            None
        };
        Self {
            default_project_id: value.default_project_id,
            domain_id: value.domain_id,
            enabled: value.enabled,
            extra: value.extra,
            federated: value
                .federated
                .map(|val| val.into_iter().map(Into::into).collect()),
            id: value.id,
            name: value.name,
            options: opts,
            password_expires_at: value.password_expires_at,
        }
    }
}

impl From<api_types::UserCreateRequest> for provider_types::UserCreate {
    fn from(value: api_types::UserCreateRequest) -> Self {
        let user = value.user;
        Self {
            default_project_id: user.default_project_id,
            domain_id: user.domain_id,
            enabled: Some(user.enabled),
            extra: user.extra,
            id: None,
            federated: None,
            name: user.name,
            options: user.options.map(Into::into),
            password: user.password,
        }
    }
}

impl From<provider_types::Federation> for api_types::Federation {
    fn from(value: provider_types::Federation) -> Self {
        Self {
            idp_id: value.idp_id,
            protocols: value.protocols.into_iter().map(Into::into).collect(),
        }
    }
}
impl From<provider_types::FederationProtocol> for api_types::FederationProtocol {
    fn from(value: provider_types::FederationProtocol) -> Self {
        Self {
            protocol_id: value.protocol_id,
            unique_id: value.unique_id,
        }
    }
}

impl From<api_types::UserListParameters> for provider_types::UserListParameters {
    fn from(value: api_types::UserListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            name: value.name,
            unique_id: value.unique_id,
            ..Default::default() //    limit: value.limit,
        }
    }
}
