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
//! Test domain delete.

use eyre::Result;
use tracing_test::traced_test;

use crate::common::get_state;
use crate::create_domain;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::resource::{DomainUpdateBuilder, ProjectOptionsBuilder};

#[traced_test]
#[tokio::test]
async fn test_delete() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    state
        .provider
        .get_resource_provider()
        .delete_domain(&ExecutionContext::internal(&state), &domain.id)
        .await?;
    assert!(
        state
            .provider
            .get_resource_provider()
            .get_domain(&ExecutionContext::internal(&state), &domain.id)
            .await?
            .is_none()
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_delete_blocked_when_immutable() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    state
        .provider
        .get_resource_provider()
        .update_domain(
            &ExecutionContext::internal(&state),
            &domain.id,
            DomainUpdateBuilder::default()
                .options(ProjectOptionsBuilder::default().immutable(true).build()?)
                .build()?,
        )
        .await?;

    let result = state
        .provider
        .get_resource_provider()
        .delete_domain(&ExecutionContext::internal(&state), &domain.id)
        .await;
    assert!(result.is_err(), "delete of an immutable domain is rejected");

    state
        .provider
        .get_resource_provider()
        .update_domain(
            &ExecutionContext::internal(&state),
            &domain.id,
            DomainUpdateBuilder::default()
                .options(ProjectOptionsBuilder::default().immutable(false).build()?)
                .build()?,
        )
        .await?;

    state
        .provider
        .get_resource_provider()
        .delete_domain(&ExecutionContext::internal(&state), &domain.id)
        .await?;
    assert!(
        state
            .provider
            .get_resource_provider()
            .get_domain(&ExecutionContext::internal(&state), &domain.id)
            .await?
            .is_none()
    );
    Ok(())
}
