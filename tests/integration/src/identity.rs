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

use openstack_keystone::identity::IdentityApi;
use openstack_keystone::keystone::Service;
use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core_types::identity::*;

use crate::common::*;
use crate::impl_deleter;

mod service_account;
mod user;
mod user_group;

impl_deleter!(Service, UserResponse, get_identity_provider, delete_user);
impl_deleter!(Service, Group, get_identity_provider, delete_group);

pub async fn create_user(
    state: &ServiceState,
    data: UserCreate,
) -> Result<AsyncResourceGuard<UserResponse, ServiceState>> {
    let res = state
        .provider
        .get_identity_provider()
        .create_user(state, data)
        .await
        .unwrap();
    Ok(AsyncResourceGuard::new(res, state.clone()))
}

pub async fn create_group(
    state: &Arc<Service>,
    data: GroupCreate,
) -> Result<AsyncResourceGuard<Group, ServiceState>> {
    let res = state
        .provider
        .get_identity_provider()
        .create_group(state, data)
        .await?;
    Ok(AsyncResourceGuard::new(res, state.clone()))
}
