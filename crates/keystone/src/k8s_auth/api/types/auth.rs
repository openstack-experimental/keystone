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

use openstack_keystone_api_types::k8s_auth::auth;

pub use auth::K8sAuthRequest;
use secrecy::{ExposeSecret, SecretString};

use crate::k8s_auth::types;

impl From<(K8sAuthRequest, String)> for types::K8sAuthRequest {
    fn from(value: (K8sAuthRequest, String)) -> Self {
        Self {
            auth_instance_id: value.1,
            jwt: SecretString::from(value.0.jwt.expose_secret()),
            role_name: value.0.role_name,
        }
    }
}
