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
//! Test fetching a single region.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::RegionCreate;

use crate::catalog::create_region;
use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_get() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let region = create_region(
        &state,
        RegionCreate {
            id: Some("region-get".to_string()),
            description: Some("a region".to_string()),
            parent_region_id: None,
            extra: HashMap::new(),
        },
    )
    .await?;

    let fetched = state
        .provider
        .get_catalog_provider()
        .get_region(&ExecutionContext::internal(&state), &region.id)
        .await?;

    assert!(fetched.is_some());
    let fetched = fetched.unwrap();
    assert_eq!(fetched.id, "region-get");
    assert_eq!(fetched.description.as_deref(), Some("a region"));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_not_found() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let fetched = state
        .provider
        .get_catalog_provider()
        .get_region(&ExecutionContext::internal(&state), "does-not-exist")
        .await?;
    assert!(fetched.is_none());
    Ok(())
}
