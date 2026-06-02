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
use uuid::Uuid;

use openstack_keystone_api_types::v3::user::*;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use super::create_user;
use crate::common::auth_user_by_password;
use crate::guard::ResourceGuard;

#[tokio::test]
#[traced_test]
async fn test_create_with_password() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let name = format!("usr_{}", Uuid::new_v4().simple());
    let password = "initial_pass";

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

    assert_eq!(guard.name, name);
    assert!(guard.enabled);

    // Authenticate with the created password
    auth_user_by_password(&guard.name, &guard.domain_id, password).await?;

    guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_with_no_password() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let name = format!("usr_{}", Uuid::new_v4().simple());

    let guard = create_user(
        &tc,
        UserCreateBuilder::default()
            .name(&name)
            .domain_id("default")
            .enabled(true)
            .build()?,
    )
    .await?;

    assert_eq!(guard.name, name);
    assert!(guard.enabled);

    guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_with_default_project_id() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let name = format!("usr_{}", Uuid::new_v4().simple());
    let project_id = "test-project-id";

    let guard = create_user(
        &tc,
        UserCreateBuilder::default()
            .name(&name)
            .domain_id("default")
            .enabled(true)
            .password("initial")
            .default_project_id(project_id)
            .build()?,
    )
    .await?;

    assert_eq!(guard.default_project_id, Some(project_id.to_string()));

    guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_disabled_user() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let name = format!("usr_{}", Uuid::new_v4().simple());
    let password = "initial_pass";

    let guard = create_user(
        &tc,
        UserCreateBuilder::default()
            .name(&name)
            .domain_id("default")
            .enabled(false)
            .password(password)
            .build()?,
    )
    .await?;

    assert!(!guard.enabled, "user should be disabled as requested");

    // Auth should fail for disabled user
    let user_client = auth_user_by_password(&guard.name, &guard.domain_id, password).await;
    assert!(
        user_client.is_err(),
        "disabled user should not be able to authenticate"
    );

    guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_and_verify_fields() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let name = format!("usr_{}", Uuid::new_v4().simple());

    let guard = create_user(
        &tc,
        UserCreateBuilder::default()
            .name(&name)
            .domain_id("default")
            .enabled(true)
            .password("initial")
            .build()?,
    )
    .await?;

    assert_eq!(guard.name, name);
    assert_eq!(guard.domain_id, "default");
    assert!(guard.enabled);
    assert!(guard.default_project_id.is_none());
    assert!(guard.extra.is_empty());

    guard.delete().await?;
    Ok(())
}
