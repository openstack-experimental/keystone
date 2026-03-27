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
//! Test role assignments.

use eyre::Result;
use std::collections::BTreeSet;
use uuid::Uuid;

use openstack_keystone::keystone::ServiceState;
use openstack_keystone::role::RoleApi;
use openstack_keystone_core_types::role::*;

use crate::common::get_state;
use crate::create_role;

async fn list_roles(state: &ServiceState, params: &RoleListParameters) -> Result<BTreeSet<String>> {
    Ok(state
        .provider
        .get_role_provider()
        .list_roles(state, params)
        .await?
        .into_iter()
        .map(|role| role.id)
        .collect())
}

#[tokio::test]
async fn test_list() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let role_names: [String; 4] = core::array::from_fn(|_| Uuid::new_v4().simple().to_string());
    let mut res = Vec::new();
    for rname in &role_names {
        res.push(create_role!(state, rname.clone())?);
    }

    assert_eq!(
        list_roles(&state, &RoleListParameters::default()).await?,
        BTreeSet::from_iter(res.into_iter().map(|r| r.id.clone()))
    );
    Ok(())
}
