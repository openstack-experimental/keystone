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

use openstack_keystone_api_types::k8s_auth::instance;

pub use instance::K8sAuthInstance;
pub use instance::K8sAuthInstanceCreate;
pub use instance::K8sAuthInstanceCreateRequest;
pub use instance::K8sAuthInstanceList;
pub use instance::K8sAuthInstanceListParameters;
pub use instance::K8sAuthInstanceResponse;
pub use instance::K8sAuthInstanceUpdate;
pub use instance::K8sAuthInstanceUpdateRequest;

use crate::api::common::ResourceIdentifier;

impl ResourceIdentifier for K8sAuthInstance {
    fn get_id(&self) -> String {
        self.id.clone()
    }
}
