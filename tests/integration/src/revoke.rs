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

use chrono::Utc;
use eyre::Report;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone::auth::*;
use openstack_keystone::revoke::RevokeApi;
use openstack_keystone::token::TokenApi;
use openstack_keystone_core_types::identity::*;
use openstack_keystone_core_types::resource::*;
use openstack_keystone_core_types::revoke::*;
use openstack_keystone_core_types::role::RoleCreateBuilder;

use crate::assignment::grant_role_to_user_on_project;
use crate::common::get_state;
use crate::identity::create_user;
use crate::resource::{create_domain, create_project};
use crate::role::create_role;

#[tokio::test]
#[traced_test]
async fn test_token_revoked() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;

    let domain = create_domain(
        &state,
        DomainCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .enabled(true)
            .build()?,
    )
    .await?;
    let project = create_project(
        &state,
        ProjectCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .domain_id(domain.id.clone())
            .enabled(true)
            .build()?,
    )
    .await?;
    let user = create_user(
        &state,
        UserCreateBuilder::default()
            .name("user_a")
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;
    let role = create_role(&state, RoleCreateBuilder::default().name("role_b").build()?).await?;
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role.id).await?;

    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            domain_id: Some(user.domain_id.clone()),
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user.id.clone())
                    .user(user.clone())
                    .build()?,
            ),
        })
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(auth).unwrap();
    let token = state.provider.get_token_provider().issue_token(
        &ctx,
        &AuthzInfo::Project(
            ProjectBuilder::default()
                .id(project.id.clone())
                .name(project.name.clone())
                .domain_id(project.domain_id.clone())
                .enabled(true)
                .build()?,
        ),
    )?;

    // Token gets proper issued_at only during the serialization
    let encoded_token = state.provider.get_token_provider().encode_token(&token)?;

    let token = state
        .provider
        .get_token_provider()
        .validate_token(&state, &encoded_token, None, None)
        .await?;

    assert!(
        !state
            .provider
            .get_revoke_provider()
            .is_token_revoked(&state, &token)
            .await?
    );

    state
        .provider
        .get_revoke_provider()
        .revoke_token(&state, &token)
        .await?;

    assert!(
        state
            .provider
            .get_revoke_provider()
            .is_token_revoked(&state, &token)
            .await?
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
/// Revocation event (role) with matching data renders token invalid.
async fn test_revoked_event_role() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;

    let domain = create_domain(
        &state,
        DomainCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .enabled(true)
            .build()?,
    )
    .await?;
    let project = create_project(
        &state,
        ProjectCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .domain_id(domain.id.clone())
            .enabled(true)
            .build()?,
    )
    .await?;
    let user = create_user(
        &state,
        UserCreateBuilder::default()
            .name("user_a")
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;
    let role = create_role(&state, RoleCreateBuilder::default().name("role_b").build()?).await?;
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role.id).await?;

    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            domain_id: Some(user.domain_id.clone()),
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user.id.clone())
                    .user(user.clone())
                    .build()?,
            ),
        })
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(auth).unwrap();
    let token = state.provider.get_token_provider().issue_token(
        &ctx,
        &AuthzInfo::Project(
            ProjectBuilder::default()
                .id(project.id.clone())
                .name(project.name.clone())
                .domain_id(project.domain_id.clone())
                .enabled(true)
                .build()?,
        ),
    )?;

    // Token gets proper issued_at only during the serialization
    let encoded_token = state.provider.get_token_provider().encode_token(&token)?;

    let token = state
        .provider
        .get_token_provider()
        .validate_token(&state, &encoded_token, None, None)
        .await?;

    assert!(
        !state
            .provider
            .get_revoke_provider()
            .is_token_revoked(&state, &token)
            .await?
    );

    state
        .provider
        .get_revoke_provider()
        .create_revocation_event(
            &state,
            RevocationEventCreateBuilder::default()
                .role_id(role.id.clone())
                .revoked_at(Utc::now())
                .issued_before(Utc::now())
                .build()?,
        )
        .await?;

    assert!(
        state
            .provider
            .get_revoke_provider()
            .is_token_revoked(&state, &token)
            .await?
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
/// Revocation event (user) with matching data renders token invalid.
async fn test_revoked_event_user() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;

    let domain = create_domain(
        &state,
        DomainCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .enabled(true)
            .build()?,
    )
    .await?;
    let project = create_project(
        &state,
        ProjectCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .domain_id(domain.id.clone())
            .enabled(true)
            .build()?,
    )
    .await?;
    let user = create_user(
        &state,
        UserCreateBuilder::default()
            .name("user_a")
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;
    let role = create_role(&state, RoleCreateBuilder::default().name("role_b").build()?).await?;
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role.id).await?;

    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            domain_id: Some(user.domain_id.clone()),
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user.id.clone())
                    .user(user.clone())
                    .build()?,
            ),
        })
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(auth).unwrap();
    let token = state.provider.get_token_provider().issue_token(
        &ctx,
        &AuthzInfo::Project(
            ProjectBuilder::default()
                .id(project.id.clone())
                .name(project.name.clone())
                .domain_id(project.domain_id.clone())
                .enabled(true)
                .build()?,
        ),
    )?;

    // Token gets proper issued_at only during the serialization
    let encoded_token = state.provider.get_token_provider().encode_token(&token)?;

    let token = state
        .provider
        .get_token_provider()
        .validate_token(&state, &encoded_token, None, None)
        .await?;

    assert!(
        !state
            .provider
            .get_revoke_provider()
            .is_token_revoked(&state, &token)
            .await?
    );

    state
        .provider
        .get_revoke_provider()
        .create_revocation_event(
            &state,
            RevocationEventCreateBuilder::default()
                .user_id(user.id.clone())
                .revoked_at(Utc::now())
                .issued_before(Utc::now())
                .build()?,
        )
        .await?;

    assert!(
        state
            .provider
            .get_revoke_provider()
            .is_token_revoked(&state, &token)
            .await?
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
/// Revocation event (project) with matching data renders token invalid.
async fn test_revoked_event_project() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;

    let domain = create_domain(
        &state,
        DomainCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .enabled(true)
            .build()?,
    )
    .await?;
    let project = create_project(
        &state,
        ProjectCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .domain_id(domain.id.clone())
            .enabled(true)
            .build()?,
    )
    .await?;
    let user = create_user(
        &state,
        UserCreateBuilder::default()
            .name("user_a")
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;
    let role = create_role(&state, RoleCreateBuilder::default().name("role_b").build()?).await?;
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role.id).await?;

    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            domain_id: Some(user.domain_id.clone()),
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user.id.clone())
                    .user(user.clone())
                    .build()?,
            ),
        })
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(auth).unwrap();
    let token = state.provider.get_token_provider().issue_token(
        &ctx,
        &AuthzInfo::Project(
            ProjectBuilder::default()
                .id(project.id.clone())
                .name(project.name.clone())
                .domain_id(project.domain_id.clone())
                .enabled(true)
                .build()?,
        ),
    )?;

    // Token gets proper issued_at only during the serialization
    let encoded_token = state.provider.get_token_provider().encode_token(&token)?;

    let token = state
        .provider
        .get_token_provider()
        .validate_token(&state, &encoded_token, None, None)
        .await?;

    assert!(
        !state
            .provider
            .get_revoke_provider()
            .is_token_revoked(&state, &token)
            .await?
    );

    state
        .provider
        .get_revoke_provider()
        .create_revocation_event(
            &state,
            RevocationEventCreateBuilder::default()
                .project_id(project.id.clone())
                .revoked_at(Utc::now())
                .issued_before(Utc::now())
                .build()?,
        )
        .await?;

    assert!(
        state
            .provider
            .get_revoke_provider()
            .is_token_revoked(&state, &token)
            .await?
    );
    Ok(())
}
