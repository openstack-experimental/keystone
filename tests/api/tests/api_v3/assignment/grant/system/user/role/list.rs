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

use eyre::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v3::role_assignment::Role;
use openstack_keystone_api_types::v3::user::UserCreateBuilder;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use super::*;
use test_api::guard::*;
use test_api::identity::user::*;
use test_api::role::list_roles;

#[tokio::test]
#[traced_test]
async fn test_list_system_roles_for_user() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let _auth_token = test_client
        .get_auth_info()
        .expect("must be authenticated")
        .token;

    let user = create_user(
        &test_client,
        UserCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .domain_id("default")
            .enabled(true)
            .build()?,
    )
    .await?;

    // List should be empty initially
    let listed_roles: Vec<Role> = list_system_roles(&test_client, &user.id).await?;
    assert!(listed_roles.is_empty());

    let roles: HashMap<String, String> = list_roles(&test_client)
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let reader_role = roles.get("reader").expect("reader role must exist");
    let member_role = roles.get("member").expect("member role must exist");

    // Grant two roles
    add_system_grant(&test_client, &user.id, &reader_role).await?;
    add_system_grant(&test_client, &user.id, &member_role).await?;

    // List should now return two roles
    let listed_roles: Vec<Role> = list_system_roles(&test_client, &user.id).await?;
    assert_eq!(listed_roles.len(), 2);

    let listed_role_ids: Vec<String> = listed_roles.iter().map(|r| r.id.clone()).collect();
    assert!(listed_role_ids.contains(&member_role.to_string()));
    assert!(listed_role_ids.contains(&reader_role.to_string()));

    user.delete().await?;
    Ok(())
}
