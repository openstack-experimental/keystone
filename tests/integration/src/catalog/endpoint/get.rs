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
//! Test fetching a single endpoint.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::{EndpointCreate, ServiceCreate};

use crate::catalog::{create_endpoint, create_service};
use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_get() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let service = create_service(
        &state,
        ServiceCreate {
            enabled: true,
            extra: HashMap::new(),
            id: None,
            r#type: Some("image".to_string()),
        },
    )
    .await?;

    let endpoint = create_endpoint(
        &state,
        EndpointCreate {
            enabled: true,
            extra: HashMap::new(),
            id: Some("endpoint-get".to_string()),
            interface: "internal".to_string(),
            region_id: None,
            service_id: service.id.clone(),
            url: "http://localhost:9292".to_string(),
        },
    )
    .await?;

    let fetched = state
        .provider
        .get_catalog_provider()
        .get_endpoint(&ExecutionContext::internal(&state), &endpoint.id)
        .await?;

    assert!(fetched.is_some());
    let fetched = fetched.unwrap();
    assert_eq!(fetched.id, "endpoint-get");
    assert_eq!(fetched.interface, "internal");
    assert_eq!(fetched.service_id, service.id);
    assert_eq!(fetched.url, "http://localhost:9292");
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_not_found() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let fetched = state
        .provider
        .get_catalog_provider()
        .get_endpoint(&ExecutionContext::internal(&state), "does-not-exist")
        .await?;
    assert!(fetched.is_none());
    Ok(())
}
