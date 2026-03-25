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
use openstack_keystone_core_types::k8s_auth as provider_types;

use crate::k8s_auth as api_types;

impl From<provider_types::K8sAuthRole> for api_types::K8sAuthRole {
    fn from(value: provider_types::K8sAuthRole) -> Self {
        Self {
            auth_instance_id: value.auth_instance_id,
            bound_audience: value.bound_audience,
            bound_service_account_names: value.bound_service_account_names,
            bound_service_account_namespaces: value.bound_service_account_namespaces,
            domain_id: value.domain_id,
            enabled: value.enabled,
            id: value.id,
            name: value.name,
            token_restriction_id: value.token_restriction_id,
        }
    }
}

impl From<api_types::K8sAuthRoleCreateRequest> for provider_types::K8sAuthRoleCreateBuilder {
    fn from(value: api_types::K8sAuthRoleCreateRequest) -> Self {
        let role = value.role;
        let mut builder = Self::default();
        builder.enabled(role.enabled);
        builder.name(role.name);
        builder.token_restriction_id(role.token_restriction_id);
        builder.bound_service_account_namespaces(role.bound_service_account_namespaces);
        builder.bound_service_account_names(role.bound_service_account_names);
        if let Some(val) = &role.bound_audience {
            builder.bound_audience(val);
        }
        builder
    }
}

impl From<api_types::K8sAuthRoleUpdateRequest> for provider_types::K8sAuthRoleUpdate {
    fn from(value: api_types::K8sAuthRoleUpdateRequest) -> Self {
        Self {
            bound_audience: value.role.bound_audience,
            bound_service_account_names: value.role.bound_service_account_names,
            bound_service_account_namespaces: value.role.bound_service_account_namespaces,
            enabled: value.role.enabled,
            name: value.role.name,
            token_restriction_id: value.role.token_restriction_id,
        }
    }
}

impl From<api_types::K8sAuthRoleListParameters> for provider_types::K8sAuthRoleListParameters {
    fn from(value: api_types::K8sAuthRoleListParameters) -> Self {
        Self {
            auth_instance_id: value.auth_instance_id,
            domain_id: value.domain_id,
            name: value.name,
        }
    }
}
