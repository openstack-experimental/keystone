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
use openstack_keystone_core_types::k8s_auth as provider_types;

use crate::k8s_auth as api_types;

impl From<provider_types::K8sAuthInstance> for api_types::K8sAuthInstance {
    fn from(value: provider_types::K8sAuthInstance) -> Self {
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

impl From<api_types::K8sAuthInstanceCreateRequest> for provider_types::K8sAuthInstanceCreate {
    fn from(value: api_types::K8sAuthInstanceCreateRequest) -> Self {
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

impl From<api_types::K8sAuthInstanceUpdateRequest> for provider_types::K8sAuthInstanceUpdate {
    fn from(value: api_types::K8sAuthInstanceUpdateRequest) -> Self {
        Self {
            ca_cert: value.instance.ca_cert,
            disable_local_ca_jwt: value.instance.disable_local_ca_jwt,
            enabled: value.instance.enabled,
            host: value.instance.host,
            name: value.instance.name,
        }
    }
}

impl From<api_types::K8sAuthInstanceListParameters>
    for provider_types::K8sAuthInstanceListParameters
{
    fn from(value: api_types::K8sAuthInstanceListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            name: value.name,
        }
    }
}
