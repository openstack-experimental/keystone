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
//! Test updating a service.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::{ServiceCreate, ServiceUpdate};

use crate::catalog::create_service;
use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_update() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let service = create_service(
        &state,
        ServiceCreate {
            enabled: true,
            extra: HashMap::new(),
            id: Some("upd-svc".to_string()),
            r#type: Some("compute".to_string()),
        },
    )
    .await?;

    let updated = state
        .provider
        .get_catalog_provider()
        .update_service(
            &ExecutionContext::internal(&state),
            &service.id,
            ServiceUpdate {
                enabled: Some(false),
                r#type: Some("image".to_string()),
                ..Default::default()
            },
        )
        .await?;
    assert!(!updated.enabled);
    assert_eq!(updated.r#type.as_deref(), Some("image"));

    // Confirm the change was persisted.
    let fetched = state
        .provider
        .get_catalog_provider()
        .get_service(&ExecutionContext::internal(&state), &service.id)
        .await?
        .unwrap();
    assert!(!fetched.enabled);
    assert_eq!(fetched.r#type.as_deref(), Some("image"));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_not_found() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let result = state
        .provider
        .get_catalog_provider()
        .update_service(
            &ExecutionContext::internal(&state),
            "missing",
            ServiceUpdate {
                enabled: Some(true),
                ..Default::default()
            },
        )
        .await;
    assert!(
        result.is_err(),
        "expected a not-found error when updating a service that does not exist"
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_type_too_long() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let service = create_service(
        &state,
        ServiceCreate {
            enabled: true,
            extra: HashMap::new(),
            id: Some("upd-long".to_string()),
            r#type: Some("compute".to_string()),
        },
    )
    .await?;

    let too_long = "x".repeat(256);
    let result = state
        .provider
        .get_catalog_provider()
        .update_service(
            &ExecutionContext::internal(&state),
            &service.id,
            ServiceUpdate {
                r#type: Some(too_long),
                ..Default::default()
            },
        )
        .await;
    assert!(
        result.is_err(),
        "expected a validation error for a too-long service type"
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_extra_overwrites() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    // Seed two extra properties.
    let mut extra = HashMap::new();
    extra.insert(
        "keep".to_string(),
        serde_json::Value::String("yes".to_string()),
    );
    extra.insert(
        "drop".to_string(),
        serde_json::Value::String("later".to_string()),
    );
    let service = create_service(
        &state,
        ServiceCreate {
            enabled: true,
            extra,
            id: Some("svc-extra".to_string()),
            r#type: Some("compute".to_string()),
        },
    )
    .await?;

    // Update replaces `extra` wholesale with the supplied map; any previously
    // stored keys are dropped (matching Python Keystone, which does not merge).
    let mut update_extra = HashMap::new();
    update_extra.insert(
        "add".to_string(),
        serde_json::Value::String("new".to_string()),
    );
    let updated = state
        .provider
        .get_catalog_provider()
        .update_service(
            &ExecutionContext::internal(&state),
            &service.id,
            ServiceUpdate {
                extra: update_extra,
                ..Default::default()
            },
        )
        .await?;

    let extra = updated.extra;
    // Only the supplied key remains; previously stored keys are overwritten.
    assert_eq!(extra.get("add").and_then(|v| v.as_str()), Some("new"));
    assert!(
        extra.get("keep").is_none(),
        "update overwrites `extra` wholesale"
    );
    assert!(
        extra.get("drop").is_none(),
        "update overwrites `extra` wholesale"
    );
    Ok(())
}
