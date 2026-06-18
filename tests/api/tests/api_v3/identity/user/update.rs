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

use test_api::common::auth_user_by_password;
use test_api::guard::ResourceGuard;
use test_api::identity::user::{create_user, update_user};

#[tokio::test]
#[traced_test]
async fn test_update_name() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let name = format!("usr_{}", Uuid::new_v4().simple());
    let new_name = format!("{name}_updated");

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

    let updated = update_user(
        &tc,
        &guard.id,
        UserUpdateBuilder::default()
            .name(new_name.clone())
            .build()?,
    )
    .await?;

    assert_eq!(updated.name, new_name);
    assert_eq!(updated.id, guard.id);

    guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_password() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let name = format!("usr_{}", Uuid::new_v4().simple());
    let old_password = "old_pass";
    let new_password = "new_pass";

    let guard = create_user(
        &tc,
        UserCreateBuilder::default()
            .name(&name)
            .domain_id("default")
            .enabled(true)
            .password(old_password)
            .build()?,
    )
    .await?;

    // Old password works
    auth_user_by_password(&guard.name, &guard.domain_id, old_password).await?;

    // Update password
    update_user(
        &tc,
        &guard.id,
        UserUpdateBuilder::default()
            .password(new_password)
            .build()?,
    )
    .await?;

    // Old password is rejected
    let user_client2 = auth_user_by_password(&guard.name, &guard.domain_id, old_password).await;

    assert!(
        user_client2.is_err(),
        "old password should be rejected after update",
    );

    // New password works
    auth_user_by_password(&guard.name, &guard.domain_id, new_password).await?;

    guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_enabled() -> Result<()> {
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

    let updated = update_user(
        &tc,
        &guard.id,
        UserUpdateBuilder::default().enabled(false).build()?,
    )
    .await?;

    assert!(!updated.enabled, "user should be disabled after update");
    assert_eq!(updated.id, guard.id);

    guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_name_and_password() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let name = format!("usr_{}", Uuid::new_v4().simple());
    let new_name = format!("{name}_updated");
    let old_password = "old_pass";
    let new_password = "new_pass";

    let guard = create_user(
        &tc,
        UserCreateBuilder::default()
            .name(&name)
            .domain_id("default")
            .enabled(true)
            .password(old_password)
            .build()?,
    )
    .await?;

    let updated = update_user(
        &tc,
        &guard.id,
        UserUpdateBuilder::default()
            .name(new_name.clone())
            .password(new_password)
            .build()?,
    )
    .await?;

    assert_eq!(updated.name, new_name);
    assert_eq!(updated.id, guard.id);

    // Verify new password works with new name
    auth_user_by_password(&updated.name, &guard.domain_id, new_password).await?;

    guard.delete().await?;
    Ok(())
}
