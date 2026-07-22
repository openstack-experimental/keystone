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
//! Test endpoint group creation.

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
async fn test_create() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let group = create_endpoint_group(
        &state,
        EndpointGroupCreate {
            id: None,
            name: Uuid::new_v4().to_string(),
            description: Some("a group".to_string()),
            filters: HashMap::from([(
                "interface".to_string(),
                serde_json::Value::String("public".to_string()),
            )]),
        },
    )
    .await?;

    // An ID is generated when none is provided.
    assert!(!group.id.is_empty());
    assert_eq!(group.description.as_deref(), Some("a group"));
    assert_eq!(
        group.filters.get("interface").and_then(|v| v.as_str()),
        Some("public")
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_invalid_empty_name() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let result = state
        .provider
        .get_catalog_provider()
        .create_endpoint_group(
            &ExecutionContext::internal(&state),
            EndpointGroupCreate {
                id: None,
                name: String::new(),
                description: None,
                filters: HashMap::new(),
            },
        )
        .await;

    assert!(
        result.is_err(),
        "creating an endpoint group with an empty name is rejected"
    );
    Ok(())
}
