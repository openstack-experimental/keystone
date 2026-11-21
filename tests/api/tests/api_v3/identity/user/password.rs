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
//! Self-service password change and the `lock_password` user option.

use std::sync::Arc;

use eyre::Result;
use http::Method;
use reqwest::StatusCode;
use serde_json::json;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v3::user::*;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::common::{auth_user_by_password, raw_request};
use test_api::guard::ResourceGuard;
use test_api::identity::user::{create_user, update_user};

fn options(lock_password: bool) -> UserOptions {
    UserOptions {
        lock_password: Some(lock_password),
        ..Default::default()
    }
}

/// A user without `lock_password` can change their own password.
#[tokio::test]
#[traced_test]
async fn test_self_service_change_password() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let guard = create_user(
        &tc,
        UserCreateBuilder::default()
            .name(format!("usr_{}", Uuid::new_v4().simple()))
            .domain_id("default")
            .enabled(true)
            .password("old_pass")
            .build()?,
    )
    .await?;

    let rsp = raw_request(
        Method::POST,
        &format!("v3/users/{}/password", guard.id),
        None,
        Some(json!({"user": {"original_password": "old_pass", "password": "new_pass"}})),
    )
    .await?;
    assert_eq!(StatusCode::NO_CONTENT, rsp.status());
    auth_user_by_password(&guard.name, &guard.domain_id, "new_pass").await?;

    guard.delete().await?;
    Ok(())
}

/// `lock_password` blocks the self-service change (403) and keeps the
/// password intact, while the administrative reset still works.
#[tokio::test]
#[traced_test]
async fn test_lock_password_blocks_self_service_not_admin_reset() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let guard = create_user(
        &tc,
        UserCreateBuilder::default()
            .name(format!("usr_{}", Uuid::new_v4().simple()))
            .domain_id("default")
            .enabled(true)
            .password("old_pass")
            .options(options(true))
            .build()?,
    )
    .await?;
    let path = format!("v3/users/{}/password", guard.id);

    let rsp = raw_request(
        Method::POST,
        &path,
        None,
        Some(json!({"user": {"original_password": "old_pass", "password": "new_pass"}})),
    )
    .await?;
    assert_eq!(StatusCode::FORBIDDEN, rsp.status());
    // The password is unchanged.
    auth_user_by_password(&guard.name, &guard.domain_id, "old_pass").await?;
    assert!(
        auth_user_by_password(&guard.name, &guard.domain_id, "new_pass")
            .await
            .is_err()
    );

    // Admin reset is unaffected by the lock.
    update_user(
        &tc,
        &guard.id,
        UserUpdateBuilder::default()
            .password("admin_pass")
            .build()?,
    )
    .await?;
    auth_user_by_password(&guard.name, &guard.domain_id, "admin_pass").await?;

    // Clearing the lock restores the self-service change.
    update_user(
        &tc,
        &guard.id,
        UserUpdateBuilder::default()
            .options(options(false))
            .build()?,
    )
    .await?;
    let rsp = raw_request(
        Method::POST,
        &path,
        None,
        Some(json!({"user": {"original_password": "admin_pass", "password": "new_pass"}})),
    )
    .await?;
    assert_eq!(StatusCode::NO_CONTENT, rsp.status());

    guard.delete().await?;
    Ok(())
}
