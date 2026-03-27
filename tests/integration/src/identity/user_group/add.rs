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
//! Test add user group membership functionality.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone::identity::IdentityApi;

use super::*;

use crate::common::get_state;
use crate::{create_domain, create_group, create_user};

#[tokio::test]
#[traced_test]
async fn test_expiring_groups() -> Result<()> {
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
        .add_user_to_group_expiring(&state, &user.id, &group_b.id, "idp_id")
        .await?;

    let groups = list_user_groups(&state, &user.id).await?;
    assert_eq!(2, groups.len());
    assert!(groups.iter().find(|x| x.id == group_a.id).is_some());
    assert!(groups.iter().find(|x| x.id == group_b.id).is_some());
    Ok(())
}
