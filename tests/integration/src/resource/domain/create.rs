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
//! Test domain creation.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::resource::DomainCreateBuilder;

use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_create() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let name = uuid::Uuid::new_v4().to_string();
    let domain = crate::resource::create_domain(
        &state,
        openstack_keystone_core_types::resource::DomainCreateBuilder::default()
            .name(&name)
            .build()?,
    )
    .await?;

    assert_eq!(name, domain.name);
    assert!(domain.enabled);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_invalid_name_too_long() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    let result = state
        .provider
        .get_resource_provider()
        .create_domain(
            &ExecutionContext::internal(&state),
            DomainCreateBuilder::default()
                .name("x".repeat(256))
                .build()?,
        )
        .await;
    assert!(
        result.is_err(),
        "creating a domain with an over-length name is rejected"
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_create_invalid_empty_name() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    let result = state
        .provider
        .get_resource_provider()
        .create_domain(
            &ExecutionContext::internal(&state),
            DomainCreateBuilder::default().name("").build()?,
        )
        .await;
    assert!(
        result.is_err(),
        "creating a domain with an empty name is rejected"
    );
    Ok(())
}
