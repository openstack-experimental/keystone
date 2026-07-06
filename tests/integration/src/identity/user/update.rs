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
//! Test user update with password and security_compliance interaction.

use chrono::Utc;
use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::auth::AuthenticationError;
use openstack_keystone_core_types::identity::*;

use crate::common::get_state;
use crate::{create_domain, create_user};

use super::helpers::{assert_expires_at_approx, setup_test_config};

#[tokio::test]
#[traced_test]
async fn test_update_password_basic() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();

    let prov = state.provider.get_identity_provider();

    prov.create_user(
        &ExecutionContext::internal(&state),
        UserCreateBuilder::default()
            .id(&uid)
            .name("testuser")
            .domain_id(domain.id.clone())
            .enabled(true)
            .password("old_pass")
            .build()?,
    )
    .await?;

    // Old password works
    let auth = prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("old_pass")
                .build()?,
        )
        .await;
    assert!(auth.is_ok(), "old password should work initially");

    // Update password
    prov.update_user(
        &ExecutionContext::internal(&state),
        &uid,
        UserUpdateBuilder::default().password("new_pass").build()?,
    )
    .await?;

    // Old password is rejected
    match prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("old_pass")
                .build()?,
        )
        .await
    {
        Err(openstack_keystone_core::identity::IdentityProviderError::Authentication {
            source: AuthenticationError::UserNameOrPasswordWrong,
        }) => {}
        other => {
            panic!("old password should be rejected: {other:?}");
        }
    }

    // New password works
    let auth = prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("new_pass")
                .build()?,
        )
        .await;
    assert!(auth.is_ok(), "new password should work");

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_name() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;

    let new_name = Uuid::new_v4().simple().to_string();
    let updated = state
        .provider
        .get_identity_provider()
        .update_user(
            &ExecutionContext::internal(&state),
            &user.id,
            UserUpdateBuilder::default()
                .name(new_name.clone())
                .build()?,
        )
        .await?;
    assert_eq!(updated.name, new_name, "name was updated");

    // Confirm the change was persisted.
    let fetched = state
        .provider
        .get_identity_provider()
        .get_user(&ExecutionContext::internal(&state), &user.id)
        .await?
        .expect("user found");
    assert_eq!(fetched.name, new_name, "updated name persisted");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_password_with_expiry() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();
    setup_test_config(&ExecutionContext::internal(&state), Some(90), None).await;

    let prov = state.provider.get_identity_provider();

    prov.create_user(
        &ExecutionContext::internal(&state),
        UserCreateBuilder::default()
            .id(&uid)
            .name("testuser")
            .domain_id(domain.id.clone())
            .enabled(true)
            .password("initial")
            .build()?,
    )
    .await?;

    // Check expires_at after create
    let now_create = Utc::now();
    let user = prov
        .get_user(&ExecutionContext::internal(&state), &uid)
        .await?
        .expect("user found");
    assert!(
        user.password_expires_at.is_some(),
        "expires_at should be set after create"
    );
    assert_expires_at_approx(user.password_expires_at.as_ref(), now_create, 90);

    // Update password
    prov.update_user(
        &ExecutionContext::internal(&state),
        &uid,
        UserUpdateBuilder::default().password("new_pass").build()?,
    )
    .await?;

    // Check expires_at after update — should be ~90 days from update time
    let now_update = Utc::now();
    let user = prov
        .get_user(&ExecutionContext::internal(&state), &uid)
        .await?
        .expect("user found");
    assert!(
        user.password_expires_at.is_some(),
        "expires_at should still be set after update"
    );
    assert_expires_at_approx(user.password_expires_at.as_ref(), now_update, 90);

    // New password works
    let auth = prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("new_pass")
                .build()?,
        )
        .await;
    assert!(auth.is_ok(), "new password should work");

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_password_no_expiry_configured() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();

    let prov = state.provider.get_identity_provider();

    // Create user with password (default config: no expiry)
    prov.create_user(
        &ExecutionContext::internal(&state),
        UserCreateBuilder::default()
            .id(&uid)
            .name("testuser")
            .domain_id(domain.id.clone())
            .enabled(true)
            .password("initial")
            .build()?,
    )
    .await?;

    let user = prov
        .get_user(&ExecutionContext::internal(&state), &uid)
        .await?
        .expect("user found");
    assert!(
        user.password_expires_at.is_none(),
        "expires_at should be None without config"
    );

    // Update password
    prov.update_user(
        &ExecutionContext::internal(&state),
        &uid,
        UserUpdateBuilder::default().password("new_pass").build()?,
    )
    .await?;

    // Still no expiry
    let user = prov
        .get_user(&ExecutionContext::internal(&state), &uid)
        .await?
        .expect("user found");
    assert!(
        user.password_expires_at.is_none(),
        "expires_at should still be None after update"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_password_with_history() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();
    setup_test_config(&ExecutionContext::internal(&state), None, Some(1)).await;

    let prov = state.provider.get_identity_provider();

    // Create with pass1
    prov.create_user(
        &ExecutionContext::internal(&state),
        UserCreateBuilder::default()
            .id(&uid)
            .name("testuser")
            .domain_id(domain.id.clone())
            .enabled(true)
            .password("pass1")
            .build()?,
    )
    .await?;

    // pass1 works
    let auth = prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("pass1")
                .build()?,
        )
        .await;
    assert!(auth.is_ok(), "pass1 should work initially");

    // Update to pass2
    prov.update_user(
        &ExecutionContext::internal(&state),
        &uid,
        UserUpdateBuilder::default().password("pass2").build()?,
    )
    .await?;

    // pass1 rejected
    match prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("pass1")
                .build()?,
        )
        .await
    {
        Err(openstack_keystone_core::identity::IdentityProviderError::Authentication {
            source: AuthenticationError::UserNameOrPasswordWrong,
        }) => {}
        other => {
            panic!("pass1 should be rejected after update: {other:?}");
        }
    }

    // pass2 accepted
    let auth = prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("pass2")
                .build()?,
        )
        .await;
    assert!(auth.is_ok(), "pass2 should work");

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_name_and_password_combined() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();

    let prov = state.provider.get_identity_provider();

    // Create user
    prov.create_user(
        &ExecutionContext::internal(&state),
        UserCreateBuilder::default()
            .id(&uid)
            .name("old_name")
            .domain_id(domain.id.clone())
            .enabled(true)
            .password("old_pass")
            .build()?,
    )
    .await?;

    // Update both name and password
    let updated = prov
        .update_user(
            &ExecutionContext::internal(&state),
            &uid,
            UserUpdateBuilder::default()
                .name("new_name")
                .password("new_pass")
                .build()?,
        )
        .await?;
    assert_eq!(updated.name, "new_name");

    // Old password rejected
    match prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("old_pass")
                .build()?,
        )
        .await
    {
        Err(openstack_keystone_core::identity::IdentityProviderError::Authentication {
            source: AuthenticationError::UserNameOrPasswordWrong,
        }) => {}
        other => {
            panic!("old password should be rejected: {other:?}");
        }
    }

    // New password works
    let auth = prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("new_pass")
                .build()?,
        )
        .await;
    assert!(auth.is_ok(), "new password should work");

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_password_with_expiry_and_history() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();
    setup_test_config(&ExecutionContext::internal(&state), Some(90), Some(1)).await;

    let prov = state.provider.get_identity_provider();

    // Create with pass1
    prov.create_user(
        &ExecutionContext::internal(&state),
        UserCreateBuilder::default()
            .id(&uid)
            .name("testuser")
            .domain_id(domain.id.clone())
            .enabled(true)
            .password("pass1")
            .build()?,
    )
    .await?;

    // Update to pass2
    prov.update_user(
        &ExecutionContext::internal(&state),
        &uid,
        UserUpdateBuilder::default().password("pass2").build()?,
    )
    .await?;

    // pass1 rejected
    match prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("pass1")
                .build()?,
        )
        .await
    {
        Err(openstack_keystone_core::identity::IdentityProviderError::Authentication {
            source: AuthenticationError::UserNameOrPasswordWrong,
        }) => {}
        other => {
            panic!("pass1 should be rejected: {other:?}");
        }
    }

    // pass2 accepted
    let auth = prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("pass2")
                .build()?,
        )
        .await;
    assert!(auth.is_ok(), "pass2 should work");

    // expires_at ≈ 90d from update
    let now = Utc::now();
    let user = prov
        .get_user(&ExecutionContext::internal(&state), &uid)
        .await?
        .expect("user found");
    assert_expires_at_approx(user.password_expires_at.as_ref(), now, 90);

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_password_expiry_config_change() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();

    let prov = state.provider.get_identity_provider();

    // Create with default config (no expiry)
    prov.create_user(
        &ExecutionContext::internal(&state),
        UserCreateBuilder::default()
            .id(&uid)
            .name("testuser")
            .domain_id(domain.id.clone())
            .enabled(true)
            .password("initial")
            .build()?,
    )
    .await?;

    let user = prov
        .get_user(&ExecutionContext::internal(&state), &uid)
        .await?
        .expect("user found");
    assert!(
        user.password_expires_at.is_none(),
        "expires_at should be None without config"
    );

    // Enable expiry, then update password
    setup_test_config(&ExecutionContext::internal(&state), Some(90), None).await;

    prov.update_user(
        &ExecutionContext::internal(&state),
        &uid,
        UserUpdateBuilder::default().password("new_pass").build()?,
    )
    .await?;

    // Now expires_at should be set
    let now = Utc::now();
    let user = prov
        .get_user(&ExecutionContext::internal(&state), &uid)
        .await?
        .expect("user found");
    assert!(
        user.password_expires_at.is_some(),
        "expires_at should be set after config change + update"
    );
    assert_expires_at_approx(user.password_expires_at.as_ref(), now, 90);

    // New password works
    let auth = prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("new_pass")
                .build()?,
        )
        .await;
    assert!(auth.is_ok(), "new password should work");

    Ok(())
}
