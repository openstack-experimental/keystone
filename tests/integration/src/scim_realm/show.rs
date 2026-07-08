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
//! Test SCIM realm lookup (ADR 0024 §2.A) against the real
//! `scim-driver-raft` backend. `get_realm` is also the exact call the
//! Realm Activation Gate (§2.B) makes on every SCIM resource request --
//! see `scim_realm::gate` for that end-to-end path.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;

use super::{create_realm, sample_realm_create};

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_show_returns_registered_realm() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let created = create_realm(&state, sample_realm_create(&domain.id, "provider-1")).await?;

    let fetched = state
        .provider
        .get_scim_realm_provider()
        .get_realm(
            &ExecutionContext::internal(&state),
            &domain.id,
            "provider-1",
        )
        .await?
        .expect("realm must be found");

    assert_eq!(fetched, created);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_show_returns_none_for_unregistered_coordinate() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let fetched = state
        .provider
        .get_scim_realm_provider()
        .get_realm(
            &ExecutionContext::internal(&state),
            &domain.id,
            "never-registered",
        )
        .await?;

    assert!(fetched.is_none());
    Ok(())
}
