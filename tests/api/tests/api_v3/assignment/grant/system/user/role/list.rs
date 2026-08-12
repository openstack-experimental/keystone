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

use eyre::{OptionExt, Result};
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

    let user = create_user(
        &test_client,
        UserCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .domain_id("default")
            .enabled(true)
            .build()?,
    )
    .await?;

    let result: Result<(bool, Vec<Role>, String, String)> = async {
        let initially_empty = list_system_roles(&test_client, &user.id).await?.is_empty();
        let roles = list_roles(&test_client).await?;
        let reader_role = roles
            .iter()
            .find(|role| role.name == "reader")
            .map(|role| role.id.clone())
            .ok_or_eyre("the bootstrap reader role must exist")?;
        let member_role = roles
            .iter()
            .find(|role| role.name == "member")
            .map(|role| role.id.clone())
            .ok_or_eyre("the bootstrap member role must exist")?;

        add_system_grant(&test_client, &user.id, &reader_role).await?;
        add_system_grant(&test_client, &user.id, &member_role).await?;
        let listed_roles = list_system_roles(&test_client, &user.id).await?;
        Ok((initially_empty, listed_roles, reader_role, member_role))
    }
    .await;
    user.delete().await?;

    let (initially_empty, listed_roles, reader_role, member_role) = result?;
    let listed_role_ids: Vec<&str> = listed_roles.iter().map(|role| role.id.as_str()).collect();
    assert!(initially_empty, "a new user must have no system grants");
    assert_eq!(listed_roles.len(), 2);
    assert!(listed_role_ids.contains(&member_role.as_str()));
    assert!(listed_role_ids.contains(&reader_role.as_str()));
    Ok(())
}
