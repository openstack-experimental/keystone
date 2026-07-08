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
//! Test SCIM realm update / enable-disable (ADR 0024 §2.B) against the
//! real `scim-driver-raft` backend.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::scim::{ScimRealmProviderError, ScimRealmResourceUpdate};

use super::{create_realm, sample_realm_create};

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_update_disable_then_enable_round_trips() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let created = create_realm(&state, sample_realm_create(&domain.id, "provider-1")).await?;
    assert!(created.enabled);

    let disabled = state
        .provider
        .get_scim_realm_provider()
        .update_realm(
            &ExecutionContext::internal(&state),
            &domain.id,
            "provider-1",
            ScimRealmResourceUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;
    assert!(!disabled.enabled);

    let re_enabled = state
        .provider
        .get_scim_realm_provider()
        .update_realm(
            &ExecutionContext::internal(&state),
            &domain.id,
            "provider-1",
            ScimRealmResourceUpdate {
                enabled: Some(true),
                ..Default::default()
            },
        )
        .await?;
    assert!(re_enabled.enabled);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_display_name_leaves_enabled_unchanged() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    create_realm(&state, sample_realm_create(&domain.id, "provider-1")).await?;

    let updated = state
        .provider
        .get_scim_realm_provider()
        .update_realm(
            &ExecutionContext::internal(&state),
            &domain.id,
            "provider-1",
            ScimRealmResourceUpdate {
                display_name: Some("Renamed realm".to_string()),
                ..Default::default()
            },
        )
        .await?;

    assert_eq!(updated.display_name, "Renamed realm");
    assert!(
        updated.enabled,
        "enabled must be untouched by a display_name-only update"
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_update_unregistered_coordinate_not_found() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let err = state
        .provider
        .get_scim_realm_provider()
        .update_realm(
            &ExecutionContext::internal(&state),
            &domain.id,
            "never-registered",
            ScimRealmResourceUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .expect_err("updating an unregistered realm must fail");

    assert!(matches!(err, ScimRealmProviderError::NotFound(_)));
    Ok(())
}
