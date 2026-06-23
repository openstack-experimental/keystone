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
//! Test bulk user group membership operations.

use std::collections::HashSet;

use eyre::Report;
use tracing_test::traced_test;

use openstack_keystone::identity::IdentityApi;

use super::*;
use crate::common::get_state;
use crate::{create_domain, create_group, create_user};

#[tokio::test]
#[traced_test]
async fn test_add_users_to_groups() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;
    let group_a = create_group!(state, domain.id.clone())?;
    let group_b = create_group!(state, domain.id.clone())?;

    state
        .provider
        .get_identity_provider()
        .add_users_to_groups(
            &state,
            vec![
                (user.id.as_str(), group_a.id.as_str()),
                (user.id.as_str(), group_b.id.as_str()),
            ],
        )
        .await?;

    let groups = list_user_groups(&state, &user.id).await?;
    assert_eq!(groups.len(), 2, "both memberships were added");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_remove_user_from_groups() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;
    let group_a = create_group!(state, domain.id.clone())?;
    let group_b = create_group!(state, domain.id.clone())?;

    state
        .provider
        .get_identity_provider()
        .add_user_to_group(&state, &user.id, &group_a.id)
        .await?;
    state
        .provider
        .get_identity_provider()
        .add_user_to_group(&state, &user.id, &group_b.id)
        .await?;

    let to_remove: HashSet<&str> = HashSet::from([group_a.id.as_str(), group_b.id.as_str()]);
    state
        .provider
        .get_identity_provider()
        .remove_user_from_groups(&state, &user.id, to_remove)
        .await?;

    let groups = list_user_groups(&state, &user.id).await?;
    assert!(groups.is_empty(), "all memberships were removed");
    Ok(())
}
