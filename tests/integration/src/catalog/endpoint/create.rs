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
//! Test endpoint creation.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::{EndpointCreate, ServiceCreate};

use crate::catalog::{create_endpoint, create_service};
use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_create() -> Result<()> {
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
            id: None,
            interface: "public".to_string(),
            region_id: None,
            service_id: service.id.clone(),
            url: "http://localhost:8774".to_string(),
        },
    )
    .await?;

    // An ID is generated when none is provided.
    assert!(!endpoint.id.is_empty());
    assert_eq!(endpoint.interface, "public");
    assert_eq!(endpoint.service_id, service.id);
    assert_eq!(endpoint.url, "http://localhost:8774");
    assert!(endpoint.enabled);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_id_too_long() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    // The endpoint id is limited to 64 characters by the validator.
    let too_long = "x".repeat(65);
    let result = state
        .provider
        .get_catalog_provider()
        .create_endpoint(
            &ExecutionContext::internal(&state),
            EndpointCreate {
                enabled: true,
                extra: HashMap::new(),
                id: Some(too_long),
                interface: "public".to_string(),
                region_id: None,
                service_id: "some-service".to_string(),
                url: "http://localhost".to_string(),
            },
        )
        .await;

    assert!(
        result.is_err(),
        "expected a validation error for an id longer than 64 characters"
    );
    Ok(())
}
