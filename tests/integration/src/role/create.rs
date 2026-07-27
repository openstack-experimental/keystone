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
use uuid::Uuid;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::role::{
    RoleCreateBuilder, RoleOptionsBuilder, RoleUpdateBuilder,
};

use crate::common::get_state;
use crate::create_role;

#[tokio::test]
async fn test_create() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let name = Uuid::new_v4().to_string();
    let role = create_role!(state, name.clone())?;

    assert_eq!(name, role.name);

    Ok(())
}

#[tokio::test]
async fn test_create_with_immutable_option() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let name = Uuid::new_v4().to_string();

    let role = state
        .provider
        .get_role_provider()
        .create_role(
            &ExecutionContext::internal(&state),
            RoleCreateBuilder::default()
                .name(name)
                .options(RoleOptionsBuilder::default().immutable(true).build()?)
                .build()?,
        )
        .await?;

    assert_eq!(role.options.immutable, Some(true));

    let fetched = state
        .provider
        .get_role_provider()
        .get_role(&ExecutionContext::internal(&state), &role.id)
        .await?
        .expect("role should be there");
    assert_eq!(fetched.options.immutable, Some(true));

    // Clear immutable so the guard-driven cleanup does not fail.
    state
        .provider
        .get_role_provider()
        .update_role(
            &ExecutionContext::internal(&state),
            &role.id,
            RoleUpdateBuilder::default()
                .options(RoleOptionsBuilder::default().immutable(false).build()?)
                .build()?,
        )
        .await?;

    Ok(())
}
