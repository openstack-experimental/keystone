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
//! Test delete user functionality.

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone::identity::IdentityApi;
use openstack_keystone_core_types::identity::UserCreateBuilder;

use crate::common::get_state;
use crate::create_domain;

#[tokio::test]
#[traced_test]
async fn test_delete() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    let user = state
        .provider
        .get_identity_provider()
        .create_user(
            &state,
            UserCreateBuilder::default()
                .name(Uuid::new_v4().to_string())
                .domain_id(domain.id.clone())
                .enabled(true)
                .build()?,
        )
        .await?;

    state
        .provider
        .get_identity_provider()
        .delete_user(&state, &user.id)
        .await?;

    let fetched = state
        .provider
        .get_identity_provider()
        .get_user(&state, &user.id)
        .await?;
    assert!(fetched.is_none(), "user is gone after delete");
    Ok(())
}
