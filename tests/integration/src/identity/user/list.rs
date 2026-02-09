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
use uuid::Uuid;

use openstack_keystone::identity::{IdentityApi, types::*};

use super::*;

#[tokio::test]
#[traced_test]
async fn test_list() -> Result<()> {
    let state = get_state().await?;
    let cnt = 20;

    for _ in 0..cnt {
        state
            .provider
            .get_identity_provider()
            .create_user(
                &state,
                UserCreateBuilder::default()
                    .name(Uuid::new_v4().to_string())
                    .domain_id("domain_a")
                    .enabled(true)
                    .build()?,
            )
            .await?;
    }

    let users: Vec<UserResponse> = state
        .provider
        .get_identity_provider()
        .list_users(&state, &UserListParameters::default())
        .await?
        .into_iter()
        .collect();
    assert!(users.len() >= cnt, "{} >= {}", users.len(), cnt);
    Ok(())
}
