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

use std::pin::Pin;
use std::sync::Arc;

use eyre::Result;

use openstack_keystone::k8s_auth::{K8sAuthApi, types::*};
use openstack_keystone::keystone::Service;
use openstack_keystone::keystone::ServiceState;

mod create;
mod delete;
mod get;
mod list;
mod update;

use crate::common::*;
use crate::impl_deleter;

impl_deleter!(
    Service,
    K8sAuthRole,
    get_k8s_auth_provider,
    delete_auth_role
);

pub async fn create_k8s_auth_role(
    state: &ServiceState,
    data: K8sAuthRoleCreate,
) -> Result<AsyncResourceGuard<K8sAuthRole, ServiceState>> {
    let res = state
        .provider
        .get_k8s_auth_provider()
        .create_auth_role(state, data)
        .await
        .unwrap();
    Ok(AsyncResourceGuard::new(res, state.clone()))
}
