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
async fn test_get() -> Result<()> {
    let state = get_state().await?;
    let uid = Uuid::new_v4().simple().to_string();

    let sa = state
        .provider
        .get_identity_provider()
        .create_service_account(
            &state,
            ServiceAccountCreate {
                domain_id: "domain_a".into(),
                enabled: Some(true),
                id: Some(uid.clone()),
                name: "sa_foo".into(),
            },
        )
        .await?;

    let _user = state
        .provider
        .get_identity_provider()
        .get_user(&state, &sa.id)
        .await?
        .expect("user found");

    let _sa = state
        .provider
        .get_identity_provider()
        .get_service_account(&state, &sa.id)
        .await?
        .expect("sa found");
    Ok(())
}
