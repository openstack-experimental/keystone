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
//! Test service creation.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::ServiceCreate;

use crate::catalog::create_service;
use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_create() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    // The service `name` is supplied as a key inside `extra`.
    let mut extra = HashMap::new();
    extra.insert(
        "name".to_string(),
        serde_json::Value::String("nova".to_string()),
    );
    let service = create_service(
        &state,
        ServiceCreate {
            enabled: true,
            extra,
            id: None,
            r#type: Some("compute".to_string()),
        },
    )
    .await?;

    // An ID is generated when none is provided.
    assert!(!service.id.is_empty());
    // `name` round-trips out of the `extra` blob via the accessor.
    assert_eq!(service.name().as_deref(), Some("nova"));
    assert_eq!(service.r#type.as_deref(), Some("compute"));
    assert!(service.enabled);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_id_too_long() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    // The service id is limited to 64 characters by the validator.
    let too_long = "x".repeat(65);
    let result = state
        .provider
        .get_catalog_provider()
        .create_service(
            &ExecutionContext::internal(&state),
            ServiceCreate {
                enabled: true,
                extra: HashMap::new(),
                id: Some(too_long),
                r#type: None,
            },
        )
        .await;

    assert!(
        result.is_err(),
        "expected a validation error for an id longer than 64 characters"
    );
    Ok(())
}
