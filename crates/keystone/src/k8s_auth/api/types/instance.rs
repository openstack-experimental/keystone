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
//! # Kubernetes auth instance types
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use openstack_keystone_api_types::k8s_auth::instance;

pub use instance::K8sAuthInstance;
pub use instance::K8sAuthInstanceCreate;
pub use instance::K8sAuthInstanceCreateRequest;
pub use instance::K8sAuthInstanceList;
pub use instance::K8sAuthInstanceListParameters;
pub use instance::K8sAuthInstanceResponse;
pub use instance::K8sAuthInstanceUpdate;
pub use instance::K8sAuthInstanceUpdateRequest;

use crate::k8s_auth::types;

use crate::api::common::ResourceIdentifier;

impl From<types::K8sAuthInstance> for K8sAuthInstance {
    fn from(value: types::K8sAuthInstance) -> Self {
        Self {
            ca_cert: value.ca_cert,
            disable_local_ca_jwt: value.disable_local_ca_jwt,
            domain_id: value.domain_id,
            enabled: value.enabled,
            host: value.host,
            id: value.id,
            name: value.name,
        }
    }
}

impl From<K8sAuthInstanceCreateRequest> for types::K8sAuthInstanceCreate {
    fn from(value: K8sAuthInstanceCreateRequest) -> Self {
        Self {
            ca_cert: value.instance.ca_cert,
            disable_local_ca_jwt: value.instance.disable_local_ca_jwt,
            domain_id: value.instance.domain_id,
            enabled: value.instance.enabled,
            host: value.instance.host,
            id: None,
            name: value.instance.name,
        }
    }
}

impl From<K8sAuthInstanceUpdateRequest> for types::K8sAuthInstanceUpdate {
    fn from(value: K8sAuthInstanceUpdateRequest) -> Self {
        Self {
            ca_cert: value.instance.ca_cert,
            disable_local_ca_jwt: value.instance.disable_local_ca_jwt,
            enabled: value.instance.enabled,
            host: value.instance.host,
            name: value.instance.name,
        }
    }
}

impl IntoResponse for types::K8sAuthInstance {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            Json(K8sAuthInstanceResponse {
                instance: K8sAuthInstance::from(self),
            }),
        )
            .into_response()
    }
}

impl From<K8sAuthInstanceListParameters> for types::K8sAuthInstanceListParameters {
    fn from(value: K8sAuthInstanceListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            name: value.name,
        }
    }
}

impl ResourceIdentifier for K8sAuthInstance {
    fn get_id(&self) -> String {
        self.id.clone()
    }
}
