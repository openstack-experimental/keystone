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
//! Test list groups functionality.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone::identity::IdentityApi;
use openstack_keystone_core_types::identity::GroupListParameters;

use crate::common::get_state;
use crate::{create_domain, create_group};

#[tokio::test]
#[traced_test]
async fn test_list() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let group_a = create_group!(state, domain.id.clone())?;
    let group_b = create_group!(state, domain.id.clone())?;

    let groups = state
        .provider
        .get_identity_provider()
        .list_groups(&state, &GroupListParameters::default())
        .await?;

    assert!(
        groups.iter().any(|g| g.id == group_a.id),
        "first group is listed"
    );
    assert!(
        groups.iter().any(|g| g.id == group_b.id),
        "second group is listed"
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_list_by_domain() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let group = create_group!(state, domain.id.clone())?;

    let groups = state
        .provider
        .get_identity_provider()
        .list_groups(
            &state,
            &GroupListParameters {
                domain_id: Some(domain.id.clone()),
                name: None,
            },
        )
        .await?;

    assert!(
        groups.iter().any(|g| g.id == group.id),
        "group is listed for its domain"
    );
    assert!(
        groups.iter().all(|g| g.domain_id == domain.id),
        "only groups from the requested domain are returned"
    );
    Ok(())
}
