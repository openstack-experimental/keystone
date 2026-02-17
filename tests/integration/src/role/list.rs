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

use openstack_keystone::keystone::ServiceState;
use openstack_keystone::role::{RoleApi, types::*};

use super::get_state;
use crate::common::create_role;

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

async fn init_data(state: &ServiceState) -> Result<()> {
    for role in ["role_a", "role_b", "role_c", "role_d"] {
        create_role(state, role).await?;
    }
    Ok(())
}

#[tokio::test]
async fn test_list() -> Result<()> {
    let state = get_state().await?;
    init_data(&state).await?;

    assert_eq!(
        list_roles(&state, &RoleListParameters::default()).await?,
        BTreeSet::from([
            "role_a".into(),
            "role_b".into(),
            "role_c".into(),
            "role_d".into()
        ]),
    );
    Ok(())
}
