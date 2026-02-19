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

use openstack_keystone::role::{RoleApi, types::*};

use super::get_state;

#[tokio::test]
async fn test_create() -> Result<()> {
    let state = get_state().await?;
    let name = Uuid::new_v4().to_string();

    let role = state
        .provider
        .get_role_provider()
        .create_role(
            &state,
            RoleCreate {
                name: name.clone(),
                ..Default::default()
            },
        )
        .await?;

    assert_eq!(name, role.name);

    Ok(())
}
