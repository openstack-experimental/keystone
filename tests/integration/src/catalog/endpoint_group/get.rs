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
//! Test endpoint group get.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::EndpointGroupCreate;

use crate::catalog::create_endpoint_group;
use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_get() -> Result<()> {
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

    let fetched = state
        .provider
        .get_catalog_provider()
        .get_endpoint_group(&ExecutionContext::internal(&state), &group.id)
        .await?
        .expect("endpoint group found");
    assert_eq!(fetched.id, group.id);
    assert_eq!(fetched.name, group.name);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_missing() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let result = state
        .provider
        .get_catalog_provider()
        .get_endpoint_group(
            &ExecutionContext::internal(&state),
            &Uuid::new_v4().to_string(),
        )
        .await?;
    assert!(result.is_none(), "a missing endpoint group returns None");
    Ok(())
}
