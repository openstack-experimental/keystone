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
//! K8s auth provider types.

use secrecy::{ExposeSecret, SecretString};

use openstack_keystone_core_types::k8s_auth as provider_types;

use crate::k8s_auth as api_types;

impl api_types::K8sAuthRequest {
    pub fn to_provider_with_instance_id(
        self,
        instance_id: String,
    ) -> provider_types::K8sAuthRequest {
        provider_types::K8sAuthRequest {
            auth_instance_id: instance_id,
            jwt: SecretString::from(self.jwt.expose_secret()),
            role_name: self.role_name,
        }
    }
}
