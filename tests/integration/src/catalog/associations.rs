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
//! Test the OS-EP-FILTER project association operations.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::{EndpointCreate, EndpointGroupCreate, ServiceCreate};

use crate::catalog::{create_endpoint, create_endpoint_group, create_service};
use crate::common::get_state;
use crate::{create_domain, create_project};

#[traced_test]
#[tokio::test]
async fn test_project_endpoint_association() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
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

    let catalog = state.provider.get_catalog_provider();
    let ctx = ExecutionContext::internal(&state);

    // Not associated initially.
    assert!(
        !catalog
            .check_endpoint_in_project(&ctx, &project.id, &endpoint.id)
            .await?
    );

    // Associate, then check + list reflect it.
    catalog
        .add_endpoint_to_project(&ctx, &project.id, &endpoint.id)
        .await?;
    assert!(
        catalog
            .check_endpoint_in_project(&ctx, &project.id, &endpoint.id)
            .await?
    );
    let endpoints = catalog.list_project_endpoints(&ctx, &project.id).await?;
    assert!(endpoints.iter().any(|e| e.id == endpoint.id));

    // Adding again is idempotent.
    catalog
        .add_endpoint_to_project(&ctx, &project.id, &endpoint.id)
        .await?;

    // Remove, then it is gone.
    catalog
        .remove_endpoint_from_project(&ctx, &project.id, &endpoint.id)
        .await?;
    assert!(
        !catalog
            .check_endpoint_in_project(&ctx, &project.id, &endpoint.id)
            .await?
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_project_endpoint_group_association() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let group = create_endpoint_group(
        &state,
        EndpointGroupCreate {
            id: None,
            name: Uuid::new_v4().to_string(),
            description: None,
            filters: HashMap::new(),
        },
    )
    .await?;

    let catalog = state.provider.get_catalog_provider();
    let ctx = ExecutionContext::internal(&state);

    // Not associated initially.
    assert!(
        !catalog
            .check_endpoint_group_in_project(&ctx, &project.id, &group.id)
            .await?
    );

    // Associate, then check + list reflect it.
    catalog
        .add_endpoint_group_to_project(&ctx, &project.id, &group.id)
        .await?;
    assert!(
        catalog
            .check_endpoint_group_in_project(&ctx, &project.id, &group.id)
            .await?
    );
    let groups = catalog
        .list_project_endpoint_groups(&ctx, &project.id)
        .await?;
    assert!(groups.iter().any(|g| g.id == group.id));

    // Remove, then it is gone.
    catalog
        .remove_endpoint_group_from_project(&ctx, &project.id, &group.id)
        .await?;
    assert!(
        !catalog
            .check_endpoint_group_in_project(&ctx, &project.id, &group.id)
            .await?
    );
    Ok(())
}
