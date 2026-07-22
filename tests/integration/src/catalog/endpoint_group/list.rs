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
//! Test endpoint group listing.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::{EndpointGroupCreate, EndpointGroupListParameters};

use crate::catalog::create_endpoint_group;
use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_list() -> Result<()> {
    let (state, _tmp) = get_state().await?;
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

    let groups = state
        .provider
        .get_catalog_provider()
        .list_endpoint_groups(
            &ExecutionContext::internal(&state),
            &EndpointGroupListParameters::default(),
        )
        .await?;
    assert!(
        groups.iter().any(|g| g.id == group.id),
        "created group is listed"
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_by_name() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let name = Uuid::new_v4().to_string();
    let group = create_endpoint_group(
        &state,
        EndpointGroupCreate {
            id: None,
            name: name.clone(),
            description: None,
            filters: HashMap::new(),
        },
    )
    .await?;

    let groups = state
        .provider
        .get_catalog_provider()
        .list_endpoint_groups(
            &ExecutionContext::internal(&state),
            &EndpointGroupListParameters {
                name: Some(name.clone()),
            },
        )
        .await?;
    assert!(
        groups.iter().all(|g| g.name == name),
        "only groups with the requested name are returned"
    );
    assert!(groups.iter().any(|g| g.id == group.id));
    Ok(())
}
