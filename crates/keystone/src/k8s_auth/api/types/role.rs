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

use crate::api::common::ResourceIdentifier;

impl ResourceIdentifier for K8sAuthRole {
    fn get_id(&self) -> String {
        self.id.clone()
    }
}
