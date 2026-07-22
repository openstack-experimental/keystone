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
//! Test endpoint group update.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::{EndpointGroupCreate, EndpointGroupUpdate};

use crate::catalog::create_endpoint_group;
use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_update() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let group = create_endpoint_group(
        &state,
        EndpointGroupCreate {
            id: None,
            name: Uuid::new_v4().to_string(),
            description: Some("old".to_string()),
            filters: HashMap::new(),
        },
    )
    .await?;

    let new_name = Uuid::new_v4().to_string();
    let updated = state
        .provider
        .get_catalog_provider()
        .update_endpoint_group(
            &ExecutionContext::internal(&state),
            &group.id,
            EndpointGroupUpdate {
                name: Some(new_name.clone()),
                description: Some("new".to_string()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.name, new_name);
    assert_eq!(updated.description.as_deref(), Some("new"));

    // Confirm the change persisted.
    let fetched = state
        .provider
        .get_catalog_provider()
        .get_endpoint_group(&ExecutionContext::internal(&state), &group.id)
        .await?
        .expect("endpoint group found");
    assert_eq!(fetched.name, new_name);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_not_found() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let result = state
        .provider
        .get_catalog_provider()
        .update_endpoint_group(
            &ExecutionContext::internal(&state),
            &Uuid::new_v4().to_string(),
            EndpointGroupUpdate {
                name: Some("x".to_string()),
                ..Default::default()
            },
        )
        .await;
    assert!(result.is_err(), "updating a missing endpoint group errors");
    Ok(())
}
