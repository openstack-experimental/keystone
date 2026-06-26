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
//! Test region creation.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::RegionCreate;

use crate::catalog::create_region;
use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_create() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let region = create_region(
        &state,
        RegionCreate {
            id: None,
            description: Some("Region One".to_string()),
            parent_region_id: None,
            extra: HashMap::new(),
        },
    )
    .await?;

    // An ID is generated when none is provided.
    assert!(!region.id.is_empty());
    assert_eq!(region.description.as_deref(), Some("Region One"));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_with_parent() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let parent = create_region(
        &state,
        RegionCreate {
            id: Some("parent-region".to_string()),
            description: None,
            parent_region_id: None,
            extra: HashMap::new(),
        },
    )
    .await?;
    let child = create_region(
        &state,
        RegionCreate {
            id: None,
            description: None,
            parent_region_id: Some(parent.id.clone()),
            extra: HashMap::new(),
        },
    )
    .await?;

    assert_eq!(child.parent_region_id.as_deref(), Some("parent-region"));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_description_too_long() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    // The Region description is limited to 255 characters by the validator, and
    // the provider must reject it before touching the database.
    let too_long = "x".repeat(256);
    let result = state
        .provider
        .get_catalog_provider()
        .create_region(
            &ExecutionContext::internal(&state),
            RegionCreate {
                id: None,
                description: Some(too_long),
                parent_region_id: None,
                extra: HashMap::new(),
            },
        )
        .await;

    assert!(
        result.is_err(),
        "expected a validation error for a description longer than 255 characters"
    );
    Ok(())
}
