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
//! Test mapping ruleset retrieval.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::mapping::MappingApi;

use super::create_ruleset;
use super::sample_ruleset_create;

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_get() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let sot = sample_ruleset_create(Some(domain.id.clone()));
    let ruleset = create_ruleset(&state, sot.clone()).await?;

    let res = state
        .provider
        .get_mapping_provider()
        .get_ruleset(&state, &ruleset.mapping_id)
        .await?
        .expect("ruleset should be present");

    assert_eq!(sot.mapping_id.unwrap(), res.mapping_id);
    assert_eq!(sot.domain_id, res.domain_id);
    assert_eq!(sot.source, res.source);
    assert_eq!(sot.domain_resolution_mode, res.domain_resolution_mode);
    assert_eq!(sot.enabled, res.enabled);
    assert_eq!(sot.rules, res.rules);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_global() -> Result<()> {
    let (state, _) = get_state().await?;
    let sot = sample_ruleset_create(None::<String>);
    let ruleset = create_ruleset(&state, sot.clone()).await?;

    let res = state
        .provider
        .get_mapping_provider()
        .get_ruleset(&state, &ruleset.mapping_id)
        .await?
        .expect("ruleset should be present");

    assert_eq!(sot.mapping_id.unwrap(), res.mapping_id);
    assert!(res.domain_id.is_none());
    assert_eq!(sot.source, res.source);
    assert_eq!(sot.enabled, res.enabled);

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_missing() -> Result<()> {
    let (state, _) = get_state().await?;
    let res = state
        .provider
        .get_mapping_provider()
        .get_ruleset(&state, &uuid::Uuid::new_v4().simple().to_string())
        .await?;

    assert!(res.is_none());
    Ok(())
}
