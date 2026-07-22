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
//! Test endpoint group deletion.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::EndpointGroupCreate;

use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_delete() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    // Create directly (not via the guard) so we own the deletion.
    let group = state
        .provider
        .get_catalog_provider()
        .create_endpoint_group(
            &ExecutionContext::internal(&state),
            EndpointGroupCreate {
                id: None,
                name: Uuid::new_v4().to_string(),
                description: None,
                filters: HashMap::new(),
            },
        )
        .await?;

    state
        .provider
        .get_catalog_provider()
        .delete_endpoint_group(&ExecutionContext::internal(&state), &group.id)
        .await?;

    let fetched = state
        .provider
        .get_catalog_provider()
        .get_endpoint_group(&ExecutionContext::internal(&state), &group.id)
        .await?;
    assert!(fetched.is_none(), "endpoint group is gone after delete");
    Ok(())
}
