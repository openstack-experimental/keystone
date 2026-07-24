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
//! Test listing endpoints.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::{
    EndpointCreate, EndpointListParameters, ServiceCreate,
};

use crate::catalog::{create_endpoint, create_service};
use crate::common::get_state;

fn endpoint(id: &str, interface: &str, service_id: &str) -> EndpointCreate {
    EndpointCreate {
        enabled: true,
        extra: HashMap::new(),
        id: Some(id.to_string()),
        interface: interface.to_string(),
        region_id: None,
        service_id: service_id.to_string(),
        url: "http://localhost".to_string(),
    }
}

#[traced_test]
#[tokio::test]
async fn test_list() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let service = create_service(
        &state,
        ServiceCreate {
            enabled: true,
            extra: HashMap::new(),
            id: None,
            r#type: Some("compute".to_string()),
        },
    )
    .await?;

    let _e1 = create_endpoint(&state, endpoint("list-e1", "public", &service.id)).await?;
    let _e2 = create_endpoint(&state, endpoint("list-e2", "internal", &service.id)).await?;

    let endpoints = state
        .provider
        .get_catalog_provider()
        .list_endpoints(
            &ExecutionContext::internal(&state),
            &EndpointListParameters::default(),
        )
        .await?;

    let ids: Vec<&str> = endpoints.iter().map(|e| e.id.as_str()).collect();
    assert!(ids.contains(&"list-e1"));
    assert!(ids.contains(&"list-e2"));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_filter_by_interface() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let service = create_service(
        &state,
        ServiceCreate {
            enabled: true,
            extra: HashMap::new(),
            id: None,
            r#type: Some("compute".to_string()),
        },
    )
    .await?;

    let _p1 = create_endpoint(&state, endpoint("pub-1", "public", &service.id)).await?;
    let _i1 = create_endpoint(&state, endpoint("int-1", "internal", &service.id)).await?;

    let endpoints = state
        .provider
        .get_catalog_provider()
        .list_endpoints(
            &ExecutionContext::internal(&state),
            &EndpointListParameters {
                interface: Some("public".to_string()),
                service_id: Some(service.id.clone()),
                region_id: None,
                pagination: Default::default(),
            },
        )
        .await?;

    let ids: Vec<&str> = endpoints.iter().map(|e| e.id.as_str()).collect();
    assert!(ids.contains(&"pub-1"));
    assert!(!ids.contains(&"int-1"));
    Ok(())
}
