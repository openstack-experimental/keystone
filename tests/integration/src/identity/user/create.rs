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

use chrono::Utc;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::auth::AuthenticationError;
use openstack_keystone_core_types::identity::*;

use crate::common::get_state;
use crate::create_domain;

use super::helpers::{assert_expires_at_approx, setup_test_config};

#[tokio::test]
#[traced_test]
async fn test_create_local_with_password() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();

    let user = state
        .provider
        .get_identity_provider()
        .create_user(
            &ExecutionContext::internal(&state),
            UserCreateBuilder::default()
                .id(&uid)
                .name("name")
                .domain_id(domain.id.clone())
                .enabled(true)
                .password("foobar")
                .build()?,
        )
        .await?;
    assert!(user.default_project_id.is_none());
    assert_eq!(user.domain_id, domain.id);
    assert!(user.enabled);
    assert!(user.extra.is_empty());
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
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();

    let user = state
        .provider
        .get_identity_provider()
        .create_user(
            &ExecutionContext::internal(&state),
            UserCreateBuilder::default()
                .id(&uid)
                .name("name")
                .domain_id(domain.id.clone())
                .enabled(true)
                .build()?,
        )
        .await?;
    assert!(user.default_project_id.is_none());
    assert_eq!(user.domain_id, domain.id);
    assert!(user.enabled);
    assert!(user.extra.is_empty());
    assert!(user.federated.is_none());
    assert_eq!(user.id, uid);
    assert_eq!(user.name, "name");
    assert_eq!(user.options, UserOptions::default());
    assert!(user.password_expires_at.is_none());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_with_password_and_expiry_days() -> eyre::Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();
    setup_test_config(&state, Some(90), None).await;

    let prov = state.provider.get_identity_provider();
    let user = prov
        .create_user(
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

    // Check expires_at is set during creation
    let now = Utc::now();
    assert!(
        user.password_expires_at.is_some(),
        "expires_at should be set during creation with expiry config"
    );
    assert_expires_at_approx(user.password_expires_at.as_ref(), now, 90);

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_with_password_and_authenticate() -> Result<()> {
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
            .password("initial")
            .build()?,
    )
    .await?;

    // Authenticate with the created password
    let auth = prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("initial")
                .build()?,
        )
        .await;
    assert!(
        auth.is_ok(),
        "user should be able to authenticate with password set during creation"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_with_password_and_unique_count() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();
    setup_test_config(&state, None, Some(5)).await;

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

    // Authenticate with the created password (should still work)
    let auth = prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("initial")
                .build()?,
        )
        .await;
    assert!(
        auth.is_ok(),
        "user should authenticate with unique_last_password_count config set"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_disabled_user_with_password() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();

    let prov = state.provider.get_identity_provider();
    let user = prov
        .create_user(
            &ExecutionContext::internal(&state),
            UserCreateBuilder::default()
                .id(&uid)
                .name("disabled_user")
                .domain_id(domain.id.clone())
                .enabled(false)
                .password("initial")
                .build()?,
        )
        .await?;

    assert!(!user.enabled, "user should be disabled as requested");

    // Try to authenticate - should fail
    match prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("initial")
                .build()?,
        )
        .await
    {
        Err(openstack_keystone_core::identity::IdentityProviderError::Authentication {
            source: AuthenticationError::UserDisabled(_),
        }) => {}
        other => {
            panic!("disabled user should not authenticate: {other:?}");
        }
    }

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_with_password_and_default_project_id() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();
    let project_id = "test-project-id";

    let prov = state.provider.get_identity_provider();
    let user = prov
        .create_user(
            &ExecutionContext::internal(&state),
            UserCreateBuilder::default()
                .id(&uid)
                .name("testuser")
                .domain_id(domain.id.clone())
                .enabled(true)
                .password("initial")
                .default_project_id(project_id)
                .build()?,
        )
        .await?;

    assert_eq!(
        user.default_project_id,
        Some(project_id.to_string()),
        "default_project_id should be set during creation"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_with_password_and_get_user() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();
    setup_test_config(&state, Some(30), None).await;

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

    // Fetch user and verify password_expires_at is populated
    let user = prov
        .get_user(&ExecutionContext::internal(&state), &uid)
        .await?
        .expect("user should be found");
    assert!(
        user.password_expires_at.is_some(),
        "password_expires_at should be set during creation with expiry config"
    );
    assert_eq!(user.name, "testuser");

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_with_expiry_and_authenticate() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();
    setup_test_config(&state, Some(90), None).await;

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

    // Authenticate should work (password is fresh, not expired)
    let auth = prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("initial")
                .build()?,
        )
        .await;
    assert!(
        auth.is_ok(),
        "fresh password should work even with expiry_days configured"
    );

    // Verify password_expires_at is set in response
    let user = prov
        .get_user(&ExecutionContext::internal(&state), &uid)
        .await?
        .expect("user should be found");
    assert!(user.password_expires_at.is_some());

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_with_expiry_and_unique_count() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();
    setup_test_config(&state, Some(90), Some(1)).await;

    let prov = state.provider.get_identity_provider();
    let user = prov
        .create_user(
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

    // Both expiry should work
    let now = Utc::now();
    assert!(user.password_expires_at.is_some());
    assert_expires_at_approx(user.password_expires_at.as_ref(), now, 90);

    // Authenticate should work
    let auth = prov
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("initial")
                .build()?,
        )
        .await;
    assert!(
        auth.is_ok(),
        "should authenticate with both expiry and unique_count config"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_invalid_name_too_long() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    let result = state
        .provider
        .get_identity_provider()
        .create_user(
            &state,
            UserCreateBuilder::default()
                .name("x".repeat(256))
                .domain_id(domain.id.clone())
                .enabled(true)
                .build()?,
        )
        .await;
    assert!(
        result.is_err(),
        "creating a user with an over-length name is rejected"
    );
    Ok(())
}
