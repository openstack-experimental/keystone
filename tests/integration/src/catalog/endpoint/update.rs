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
//! Test updating an endpoint.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::{EndpointCreate, EndpointUpdate, ServiceCreate};

use crate::catalog::{create_endpoint, create_service};
use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_update() -> Result<()> {
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

    let endpoint = create_endpoint(
        &state,
        EndpointCreate {
            enabled: true,
            extra: HashMap::new(),
            id: Some("upd-ep".to_string()),
            interface: "public".to_string(),
            region_id: None,
            service_id: service.id.clone(),
            url: "http://localhost:8774".to_string(),
        },
    )
    .await?;

    let updated = state
        .provider
        .get_catalog_provider()
        .update_endpoint(
            &ExecutionContext::internal(&state),
            &endpoint.id,
            EndpointUpdate {
                enabled: Some(false),
                url: Some("http://localhost:9999".to_string()),
                ..Default::default()
            },
        )
        .await?;
    assert!(!updated.enabled);
    assert_eq!(updated.url, "http://localhost:9999");

    // Confirm the change was persisted.
    let fetched = state
        .provider
        .get_catalog_provider()
        .get_endpoint(&ExecutionContext::internal(&state), &endpoint.id)
        .await?
        .unwrap();
    assert!(!fetched.enabled);
    assert_eq!(fetched.url, "http://localhost:9999");
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_not_found() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let result = state
        .provider
        .get_catalog_provider()
        .update_endpoint(
            &ExecutionContext::internal(&state),
            "missing",
            EndpointUpdate {
                enabled: Some(true),
                ..Default::default()
            },
        )
        .await;
    assert!(
        result.is_err(),
        "expected a not-found error when updating an endpoint that does not exist"
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_interface_too_long() -> Result<()> {
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

    let endpoint = create_endpoint(
        &state,
        EndpointCreate {
            enabled: true,
            extra: HashMap::new(),
            id: Some("upd-long".to_string()),
            interface: "public".to_string(),
            region_id: None,
            service_id: service.id.clone(),
            url: "http://localhost".to_string(),
        },
    )
    .await?;

    let too_long = "x".repeat(256);
    let result = state
        .provider
        .get_catalog_provider()
        .update_endpoint(
            &ExecutionContext::internal(&state),
            &endpoint.id,
            EndpointUpdate {
                interface: Some(too_long),
                ..Default::default()
            },
        )
        .await;
    assert!(
        result.is_err(),
        "expected a validation error for a too-long interface"
    );
    Ok(())
}
