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

use std::sync::Arc;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_api_types::v3::user::UserCreateBuilder;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::auth::project::*;
use test_api::common::get_session_by_user_password;
use test_api::guard::ResourceGuard;
use test_api::identity::user::create_user;
use uuid::Uuid;

#[tokio::test]
async fn test_list_user_projects() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let projects = list_auth_projects(&test_client).await?;
    assert!(!projects.is_empty());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_auth_projects_empty_for_user_without_roles() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let name = format!("usr_{}", Uuid::new_v4().simple());
    let password = "TestPassword123!";

    let guard = create_user(
        &tc,
        UserCreateBuilder::default()
            .name(&name)
            .domain_id("default")
            .enabled(true)
            .password(password)
            .build()?,
    )
    .await?;

    let user_client =
        get_session_by_user_password(&guard.name, &guard.domain_id, &password).await?;

    let projects = list_auth_projects(&user_client).await?;
    assert!(projects.is_empty());

    guard.delete().await?;
    Ok(())
}
