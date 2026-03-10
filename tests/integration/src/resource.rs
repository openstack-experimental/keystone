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

use openstack_keystone::keystone::Service;
use openstack_keystone::keystone::ServiceState;
use openstack_keystone::resource::{ResourceApi, types::*};

use crate::common::*;
use crate::impl_deleter;

impl_deleter!(Service, Project, get_resource_provider, delete_project);
impl_deleter!(Service, Domain, get_resource_provider, delete_domain);

pub async fn create_project(
    state: &ServiceState,
    data: ProjectCreate,
) -> Result<AsyncResourceGuard<Project, ServiceState>> {
    let res = state
        .provider
        .get_resource_provider()
        .create_project(state, data)
        .await
        .unwrap();
    Ok(AsyncResourceGuard::new(res, state.clone()))
}

pub async fn create_domain(
    state: &ServiceState,
    data: DomainCreate,
) -> Result<AsyncResourceGuard<Domain, ServiceState>> {
    let res = state
        .provider
        .get_resource_provider()
        .create_domain(state, data)
        .await
        .unwrap();
    Ok(AsyncResourceGuard::new(res, state.clone()))
}
