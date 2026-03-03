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

use openstack_keystone_api_types::v3::project::ProjectCreateBuilder;
use openstack_keystone_api_types::v3::user::UserCreateBuilder;
use openstack_sdk_core::{AsyncOpenStack, config::CloudConfig};

use super::*;
use crate::guard::*;
use crate::identity::user::*;
use crate::resource::project::*;
use crate::role::list_roles;

#[tokio::test]
#[traced_test]
async fn test_grant_project_role_to_user() -> Result<()> {
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

    let project = create_project(
        &test_client,
        ProjectCreateBuilder::default()
            .domain_id("default")
            .parent_id("default")
            .name(Uuid::new_v4().simple().to_string())
            .is_domain(false)
            .enabled(true)
            .build()?,
    )
    .await?;

    let roles: HashMap<String, String> = list_roles(&test_client)
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let member_role = roles.get("member").expect("member role must exist");
    add_project_grant(&test_client, &project.id, &user.id, &member_role).await?;
    assert!(check_grant(&test_client, &project.id, &user.id, &member_role).await?);

    user.delete().await?;
    project.delete().await?;
    Ok(())
}
