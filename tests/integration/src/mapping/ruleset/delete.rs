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
//! Test mapping ruleset deletion.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::mapping::MappingApi;

use super::create_ruleset;
use super::sample_ruleset_create;

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_delete() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let ruleset = create_ruleset(&state, sample_ruleset_create(Some(domain.id.clone()))).await?;

    state
        .provider
        .get_mapping_provider()
        .delete_ruleset(&state, &ruleset.mapping_id)
        .await?;

    let res = state
        .provider
        .get_mapping_provider()
        .get_ruleset(&state, &ruleset.mapping_id)
        .await?;

    assert!(res.is_none());
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_delete_missing() -> Result<()> {
    let (state, _) = get_state().await?;
    state
        .provider
        .get_mapping_provider()
        .delete_ruleset(&state, &uuid::Uuid::new_v4().simple().to_string())
        .await?;
    Ok(())
}
