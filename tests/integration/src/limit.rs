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

mod limits;
mod model;
mod registered_limit;

use eyre::Result;

use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::{
    Region, RegionCreate, Service as CatalogService, ServiceCreate,
};
use openstack_keystone_core_types::limit::*;

use crate::catalog::{create_region, create_service};
use crate::common::AsyncResourceGuard;

/// Create a catalog service (deleted when the guard is dropped).
pub async fn setup_service(
    state: &ServiceState,
) -> Result<AsyncResourceGuard<CatalogService, ServiceState>> {
    create_service(
        state,
        ServiceCreate {
            enabled: true,
            r#type: Some("compute".into()),
            ..Default::default()
        },
    )
    .await
}

/// Create a catalog region (deleted when the guard is dropped).
pub async fn setup_region(
    state: &ServiceState,
) -> Result<AsyncResourceGuard<Region, ServiceState>> {
    create_region(state, RegionCreate::default()).await
}

/// Build the registered limit request.
pub fn registered(
    service_id: &str,
    region_id: Option<&str>,
    name: &str,
    default_limit: i32,
) -> RegisteredLimitCreate {
    RegisteredLimitCreate {
        default_limit,
        description: None,
        id: None,
        region_id: region_id.map(Into::into),
        resource_name: name.into(),
        service_id: service_id.into(),
    }
}

/// Build the project limit request.
pub fn project_limit(
    service_id: &str,
    region_id: Option<&str>,
    name: &str,
    project_id: &str,
    value: i32,
) -> LimitCreate {
    LimitCreate {
        project_id: Some(project_id.into()),
        region_id: region_id.map(Into::into),
        resource_limit: value,
        resource_name: name.into(),
        service_id: service_id.into(),
        ..Default::default()
    }
}

/// Build the domain limit request.
pub fn domain_limit(
    service_id: &str,
    region_id: Option<&str>,
    name: &str,
    domain_id: &str,
    value: i32,
) -> LimitCreate {
    LimitCreate {
        domain_id: Some(domain_id.into()),
        region_id: region_id.map(Into::into),
        resource_limit: value,
        resource_name: name.into(),
        service_id: service_id.into(),
        ..Default::default()
    }
}

/// Execution context used by the tests.
pub fn exec(state: &ServiceState) -> ExecutionContext<'_> {
    ExecutionContext::internal(state)
}
