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
//! Test listing regions.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::{RegionCreate, RegionListParameters};

use crate::catalog::create_region;
use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_list() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let _r1 = create_region(
        &state,
        RegionCreate {
            id: Some("list-r1".to_string()),
            description: None,
            parent_region_id: None,
            extra: HashMap::new(),
        },
    )
    .await?;
    let _r2 = create_region(
        &state,
        RegionCreate {
            id: Some("list-r2".to_string()),
            description: None,
            parent_region_id: None,
            extra: HashMap::new(),
        },
    )
    .await?;

    let regions = state
        .provider
        .get_catalog_provider()
        .list_regions(
            &ExecutionContext::internal(&state),
            &RegionListParameters::default(),
        )
        .await?;

    let ids: Vec<&str> = regions.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"list-r1"));
    assert!(ids.contains(&"list-r2"));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_filter_by_parent() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let _parent = create_region(
        &state,
        RegionCreate {
            id: Some("parent".to_string()),
            description: None,
            parent_region_id: None,
            extra: HashMap::new(),
        },
    )
    .await?;
    let _child1 = create_region(
        &state,
        RegionCreate {
            id: Some("child1".to_string()),
            description: None,
            parent_region_id: Some("parent".to_string()),
            extra: HashMap::new(),
        },
    )
    .await?;
    let _child2 = create_region(
        &state,
        RegionCreate {
            id: Some("child2".to_string()),
            description: None,
            parent_region_id: Some("parent".to_string()),
            extra: HashMap::new(),
        },
    )
    .await?;
    let _unrelated = create_region(
        &state,
        RegionCreate {
            id: Some("unrelated".to_string()),
            description: None,
            parent_region_id: None,
            extra: HashMap::new(),
        },
    )
    .await?;

    let regions = state
        .provider
        .get_catalog_provider()
        .list_regions(
            &ExecutionContext::internal(&state),
            &RegionListParameters {
                parent_region_id: Some("parent".to_string()),
            },
        )
        .await?;

    let ids: Vec<&str> = regions.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(regions.len(), 2, "expected only the two children");
    assert!(ids.contains(&"child1"));
    assert!(ids.contains(&"child2"));
    Ok(())
}
