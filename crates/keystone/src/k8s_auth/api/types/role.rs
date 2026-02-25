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
//! Federated identity provider types.
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use openstack_keystone_api_types::k8s_auth::role;

pub use role::K8sAuthRole;
pub use role::K8sAuthRoleCreate;
pub use role::K8sAuthRoleCreateRequest;
pub use role::K8sAuthRoleList;
pub use role::K8sAuthRoleListParameters;
pub use role::K8sAuthRoleListParametersNested;
pub use role::K8sAuthRolePathParams;
pub use role::K8sAuthRoleResponse;
pub use role::K8sAuthRoleUpdate;
pub use role::K8sAuthRoleUpdateRequest;

use crate::k8s_auth::types;

use crate::api::common::ResourceIdentifier;

impl From<types::K8sAuthRole> for K8sAuthRole {
    fn from(value: types::K8sAuthRole) -> Self {
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

impl From<(K8sAuthRoleCreateRequest, String, String)> for types::K8sAuthRoleCreate {
    fn from(value: (K8sAuthRoleCreateRequest, String, String)) -> Self {
        Self {
            auth_instance_id: value.1,
            bound_audience: value.0.role.bound_audience,
            bound_service_account_names: value.0.role.bound_service_account_names,
            bound_service_account_namespaces: value.0.role.bound_service_account_namespaces,
            domain_id: value.2,
            enabled: value.0.role.enabled,
            id: None,
            name: value.0.role.name,
            token_restriction_id: value.0.role.token_restriction_id,
        }
    }
}

impl From<K8sAuthRoleUpdateRequest> for types::K8sAuthRoleUpdate {
    fn from(value: K8sAuthRoleUpdateRequest) -> Self {
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

impl IntoResponse for types::K8sAuthRole {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            Json(K8sAuthRoleResponse {
                role: K8sAuthRole::from(self),
            }),
        )
            .into_response()
    }
}

//impl From<K8sAuthRoleListParameters> for types::K8sAuthRoleListParameters {
//    fn from(value: K8sAuthRoleListParameters) -> Self {
//        Self {
//            auth_configuration_id: value.auth_configuration_id,
//            domain_id: value.domain_id,
//            name: value.name,
//        }
//    }
//}

impl ResourceIdentifier for K8sAuthRole {
    fn get_id(&self) -> String {
        self.id.clone()
    }
}
