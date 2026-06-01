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
//! Test domain list.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone::resource::ResourceApi;
use openstack_keystone_core_types::resource::*;

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_list() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain2 = create_domain!(state)?;

    let res = state
        .provider
        .get_resource_provider()
        .list_domains(&state, &DomainListParameters::default())
        .await?;
    // Check that created domains are in the list
    assert!(res.iter().any(|d| d.id == domain.id));
    assert!(res.iter().any(|d| d.id == domain2.id));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_by_id() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain2 = create_domain!(state)?;

    let res = state
        .provider
        .get_resource_provider()
        .list_domains(
            &state,
            &DomainListParameters {
                ids: Some(std::collections::HashSet::from_iter(vec![
                    domain.id.clone(),
                ])),
                ..Default::default()
            },
        )
        .await?;
    assert!(res.iter().any(|d| d.id == domain.id));
    assert!(!res.iter().any(|d| d.id == domain2.id));
    Ok(())
}
