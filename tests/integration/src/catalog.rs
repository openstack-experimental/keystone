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

mod endpoint;
mod region;
mod service;

use std::pin::Pin;
use std::sync::Arc;

use eyre::Result;

use openstack_keystone::keystone::Service;
use openstack_keystone::keystone::ServiceState;
// The catalog domain type is also called `Service`, which clashes with the
// Keystone `Service` state struct imported above, so it is aliased here.
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::Service as CatalogService;
use openstack_keystone_core_types::catalog::*;

use crate::common::*;
use crate::impl_deleter;

impl_deleter!(Service, Endpoint, get_catalog_provider, delete_endpoint);
impl_deleter!(Service, Region, get_catalog_provider, delete_region);
impl_deleter!(
    Service,
    CatalogService,
    get_catalog_provider,
    delete_service
);

/// Create an endpoint through the catalog provider, returning a guard that
/// deletes it again when dropped.
pub async fn create_endpoint(
    state: &ServiceState,
    data: EndpointCreate,
) -> Result<AsyncResourceGuard<Endpoint, ServiceState>> {
    let res = state
        .provider
        .get_catalog_provider()
        .create_endpoint(&ExecutionContext::internal(&state), data)
        .await
        .unwrap();
    Ok(AsyncResourceGuard::new(res, state.clone()))
}

/// Create a region through the catalog provider, returning a guard that deletes
/// it again when dropped.
pub async fn create_region(
    state: &ServiceState,
    data: RegionCreate,
) -> Result<AsyncResourceGuard<Region, ServiceState>> {
    let res = state
        .provider
        .get_catalog_provider()
        .create_region(&ExecutionContext::internal(&state), data)
        .await
        .unwrap();
    Ok(AsyncResourceGuard::new(res, state.clone()))
}

/// Create a service through the catalog provider, returning a guard that
/// deletes it again when dropped.
pub async fn create_service(
    state: &ServiceState,
    data: ServiceCreate,
) -> Result<AsyncResourceGuard<CatalogService, ServiceState>> {
    let res = state
        .provider
        .get_catalog_provider()
        .create_service(&ExecutionContext::internal(&state), data)
        .await
        .unwrap();
    Ok(AsyncResourceGuard::new(res, state.clone()))
}
