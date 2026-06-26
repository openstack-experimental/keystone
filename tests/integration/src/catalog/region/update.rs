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
//! Test updating a region.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::{RegionCreate, RegionUpdate};

use crate::catalog::create_region;
use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_update() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let region = create_region(
        &state,
        RegionCreate {
            id: Some("upd".to_string()),
            description: Some("old".to_string()),
            parent_region_id: None,
            extra: HashMap::new(),
        },
    )
    .await?;

    let updated = state
        .provider
        .get_catalog_provider()
        .update_region(
            &ExecutionContext::internal(&state),
            &region.id,
            RegionUpdate {
                description: Some("new".to_string()),
                parent_region_id: None,
                extra: HashMap::new(),
            },
        )
        .await?;
    assert_eq!(updated.description.as_deref(), Some("new"));

    // Confirm the change was persisted.
    let fetched = state
        .provider
        .get_catalog_provider()
        .get_region(&ExecutionContext::internal(&state), &region.id)
        .await?
        .unwrap();
    assert_eq!(fetched.description.as_deref(), Some("new"));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_not_found() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let result = state
        .provider
        .get_catalog_provider()
        .update_region(
            &ExecutionContext::internal(&state),
            "missing",
            RegionUpdate {
                description: Some("x".to_string()),
                parent_region_id: None,
                extra: HashMap::new(),
            },
        )
        .await;
    assert!(
        result.is_err(),
        "expected a not-found error when updating a region that does not exist"
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_description_too_long() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let region = create_region(
        &state,
        RegionCreate {
            id: Some("upd-long".to_string()),
            description: None,
            parent_region_id: None,
            extra: HashMap::new(),
        },
    )
    .await?;

    let too_long = "x".repeat(256);
    let result = state
        .provider
        .get_catalog_provider()
        .update_region(
            &ExecutionContext::internal(&state),
            &region.id,
            RegionUpdate {
                description: Some(too_long),
                parent_region_id: None,
                extra: HashMap::new(),
            },
        )
        .await;
    assert!(
        result.is_err(),
        "expected a validation error for a too-long description"
    );
    Ok(())
}
