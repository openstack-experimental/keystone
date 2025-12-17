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
async fn test_create_local_with_password() -> Result<()> {
    let state = get_state().await?;
    let uid = Uuid::new_v4().simple().to_string();

    let user = state
        .provider
        .get_identity_provider()
        .create_user(
            &state,
            UserCreateBuilder::default()
                .id(&uid)
                .name("name")
                .domain_id("domain_a")
                .enabled(true)
                .password("foobar")
                .build()?,
        )
        .await?;
    assert!(user.default_project_id.is_none());
    assert_eq!(user.domain_id, "domain_a");
    assert!(user.enabled);
    assert!(user.extra.is_none());
    assert!(user.federated.is_none());
    assert_eq!(user.id, uid);
    assert_eq!(user.name, "name");
    assert_eq!(user.options, UserOptions::default());
    assert!(user.password_expires_at.is_none());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_local_with_no_password() -> Result<()> {
    let state = get_state().await?;
    let uid = Uuid::new_v4().simple().to_string();

    let user = state
        .provider
        .get_identity_provider()
        .create_user(
            &state,
            UserCreateBuilder::default()
                .id(&uid)
                .name("name")
                .domain_id("domain_a")
                .enabled(true)
                .build()?,
        )
        .await?;
    assert!(user.default_project_id.is_none());
    assert_eq!(user.domain_id, "domain_a");
    assert!(user.enabled);
    assert!(user.extra.is_none());
    assert!(user.federated.is_none());
    assert_eq!(user.id, uid);
    assert_eq!(user.name, "name");
    assert_eq!(user.options, UserOptions::default());
    assert!(user.password_expires_at.is_none());
    Ok(())
}
