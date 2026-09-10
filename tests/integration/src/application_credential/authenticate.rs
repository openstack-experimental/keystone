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
//! Integration tests for authentication by application credential.

use std::ops::Deref;

use eyre::Report;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone::application_credential::ApplicationCredentialProviderError;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::application_credential::*;
use openstack_keystone_core_types::auth::*;
use openstack_keystone_core_types::role::*;

use crate::common::get_state;
use crate::{create_domain, create_project, create_role, create_user};

/// Helper to build an auth request by credential ID.
fn auth_request_by_id(cred_id: &str, secret: &str) -> ApplicationCredentialAuthRequest {
    ApplicationCredentialAuthRequest {
        secret: secret.into(),
        credential: ApplicationCredentialAuthData::Id(ApplicationCredentialAuthById {
            id: cred_id.to_string(),
            user: None,
        }),
    }
}

#[tokio::test]
#[traced_test]
async fn test_authenticate_by_app_cred_success() -> Result<(), Report> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let role = create_role!(state)?;

    let secret = "test_app_cred_secret".to_string();
    let cred = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &ExecutionContext::internal(&state),
            ApplicationCredentialCreate {
                name: Uuid::new_v4().to_string(),
                project_id: project.id.clone(),
                roles: vec![RoleRef::from(role.clone())],
                secret: Some(secret.clone().into()),
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    let result = state
        .provider
        .get_application_credential_provider()
        .authenticate_by_application_credential(
            &ExecutionContext::internal(&state),
            &auth_request_by_id(&cred.id, &secret),
        )
        .await?;

    assert!(
        matches!(
            result.context,
            AuthenticationContext::ApplicationCredential { .. }
        ),
        "context must be ApplicationCredential"
    );

    if let AuthenticationContext::ApplicationCredential {
        application_credential,
        token,
    } = &result.context
    {
        assert_eq!(application_credential.id, cred.id);
        assert_eq!(application_credential.project_id, project.id);
        assert!(token.is_none());
    }

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authenticate_by_app_cred_wrong_secret() -> Result<(), Report> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;

    let cred = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &ExecutionContext::internal(&state),
            ApplicationCredentialCreate {
                name: Uuid::new_v4().to_string(),
                project_id: project.id.clone(),
                roles: vec![],
                secret: Some("correct_secret".into()),
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    let result = state
        .provider
        .get_application_credential_provider()
        .authenticate_by_application_credential(
            &ExecutionContext::internal(&state),
            &auth_request_by_id(&cred.id, "wrong_secret"),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(ApplicationCredentialProviderError::AuthenticationFailed)
        ),
        "wrong secret must fail"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authenticate_by_app_cred_not_found() -> Result<(), Report> {
    let (state, _) = get_state().await?;

    let result = state
        .provider
        .get_application_credential_provider()
        .authenticate_by_application_credential(
            &ExecutionContext::internal(&state),
            &auth_request_by_id("nonexistent_id", "any_secret"),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(ApplicationCredentialProviderError::AuthenticationFailed)
        ),
        "nonexistent credential must fail"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authenticate_by_app_cred_expired() -> Result<(), Report> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;

    let secret = "expired_cred_secret".to_string();
    let cred = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &ExecutionContext::internal(&state),
            ApplicationCredentialCreate {
                name: Uuid::new_v4().to_string(),
                project_id: project.id.clone(),
                roles: vec![],
                secret: Some(secret.clone().into()),
                user_id: user.id.clone(),
                expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
                ..Default::default()
            },
        )
        .await?;

    let result = state
        .provider
        .get_application_credential_provider()
        .authenticate_by_application_credential(
            &ExecutionContext::internal(&state),
            &auth_request_by_id(&cred.id, &secret),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(ApplicationCredentialProviderError::ApplicationCredentialExpired)
        ),
        "expired credential must fail"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authenticate_by_app_cred_disabled_user_rejected_by_central_validation()
-> Result<(), Report> {
    // The provider does NOT check user.enabled — that is handled centrally
    // by UserIdentityInfo::validate() during token issuance
    // (ValidatedSecurityContext::new_for_scope).
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let role = create_role!(state)?;

    state
        .provider
        .get_assignment_provider()
        .create_grant(
            &ExecutionContext::internal(&state),
            openstack_keystone_core_types::assignment::AssignmentCreate::user_project(
                &user.id,
                &project.id,
                &role.id,
                false,
            ),
        )
        .await?;

    let secret = "disabled_user_secret".to_string();
    let cred = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &ExecutionContext::internal(&state),
            ApplicationCredentialCreate {
                name: Uuid::new_v4().to_string(),
                project_id: project.id.clone(),
                roles: vec![RoleRef::from(role.deref().clone())],
                secret: Some(secret.clone().into()),
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    state
        .provider
        .get_identity_provider()
        .update_user(
            &ExecutionContext::internal(&state),
            &user.id,
            openstack_keystone_core_types::identity::UserUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;

    // Provider returns Ok — user.enabled is NOT checked here
    let auth_result = state
        .provider
        .get_application_credential_provider()
        .authenticate_by_application_credential(
            &ExecutionContext::internal(&state),
            &auth_request_by_id(&cred.id, &secret),
        )
        .await;

    assert!(
        auth_result.is_ok(),
        "provider must return Ok — user.enabled is checked centrally"
    );

    // Token issuance fails via UserIdentityInfo::validate()
    let ctx = SecurityContext::try_from(auth_result.unwrap())?;
    let authz_info = openstack_keystone_core::api::common::get_authz_info(
        &state,
        Some(&openstack_keystone_core_types::scope::Scope::Project(
            openstack_keystone_core_types::scope::ProjectBuilder::default()
                .id(Some(project.id.clone()))
                .build()?,
        )),
    )
    .await?;

    let result = state
        .provider
        .get_token_provider()
        .issue_token_context(&state, &ctx, &authz_info)
        .await;

    assert!(
        result.is_err(),
        "token issuance must fail for a disabled user"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authenticate_by_app_cred_disabled_project_rejected_by_scope_validation()
-> Result<(), Report> {
    // The provider does NOT check project.enabled — that is handled by
    // ScopeInfo::validate() via get_authz_info.
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let role = create_role!(state)?;

    state
        .provider
        .get_assignment_provider()
        .create_grant(
            &ExecutionContext::internal(&state),
            openstack_keystone_core_types::assignment::AssignmentCreate::user_project(
                &user.id,
                &project.id,
                &role.id,
                false,
            ),
        )
        .await?;

    let secret = "disabled_project_secret".to_string();
    let _cred = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &ExecutionContext::internal(&state),
            ApplicationCredentialCreate {
                name: Uuid::new_v4().to_string(),
                project_id: project.id.clone(),
                roles: vec![RoleRef::from(role.deref().clone())],
                secret: Some(secret.clone().into()),
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    // Disable the project
    state
        .provider
        .get_resource_provider()
        .update_project(
            &ExecutionContext::internal(&state),
            &project.id,
            openstack_keystone_core_types::resource::ProjectUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;

    // Scope resolution rejects the disabled project
    let result = openstack_keystone_core::api::common::get_authz_info(
        &state,
        Some(&openstack_keystone_core_types::scope::Scope::Project(
            openstack_keystone_core_types::scope::ProjectBuilder::default()
                .id(Some(project.id.clone()))
                .build()?,
        )),
    )
    .await;

    assert!(
        result.is_err(),
        "scope resolution must fail for a disabled project"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authenticate_by_app_cred_disabled_domain_rejected_by_scope_validation()
-> Result<(), Report> {
    // The provider does NOT check domain.enabled — that is handled by
    // ScopeInfo::validate() via get_authz_info.
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let role = create_role!(state)?;

    state
        .provider
        .get_assignment_provider()
        .create_grant(
            &ExecutionContext::internal(&state),
            openstack_keystone_core_types::assignment::AssignmentCreate::user_project(
                &user.id,
                &project.id,
                &role.id,
                false,
            ),
        )
        .await?;

    let secret = "disabled_domain_secret".to_string();
    let _cred = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &ExecutionContext::internal(&state),
            ApplicationCredentialCreate {
                name: Uuid::new_v4().to_string(),
                project_id: project.id.clone(),
                roles: vec![RoleRef::from(role.deref().clone())],
                secret: Some(secret.clone().into()),
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    // Disable the domain
    state
        .provider
        .get_resource_provider()
        .update_domain(
            &ExecutionContext::internal(&state),
            &domain.id,
            openstack_keystone_core_types::resource::DomainUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;

    // Scope resolution rejects the disabled domain
    let result = openstack_keystone_core::api::common::get_authz_info(
        &state,
        Some(&openstack_keystone_core_types::scope::Scope::Project(
            openstack_keystone_core_types::scope::ProjectBuilder::default()
                .id(Some(project.id.clone()))
                .build()?,
        )),
    )
    .await;

    assert!(
        result.is_err(),
        "scope resolution must fail for a disabled domain"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authenticate_by_app_cred_scope_to_different_project_rejected() -> Result<(), Report> {
    // validate_scope_boundaries rejects scoping to a different project.
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let other_project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let role = create_role!(state)?;

    let secret = "scope_test_secret".to_string();
    let cred = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &ExecutionContext::internal(&state),
            ApplicationCredentialCreate {
                name: Uuid::new_v4().to_string(),
                project_id: project.id.clone(),
                roles: vec![RoleRef::from(role.deref().clone())],
                secret: Some(secret.clone().into()),
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    let auth_result = state
        .provider
        .get_application_credential_provider()
        .authenticate_by_application_credential(
            &ExecutionContext::internal(&state),
            &auth_request_by_id(&cred.id, &secret),
        )
        .await?;

    let ctx = SecurityContext::try_from(auth_result)?;

    // Scoping to a different project must be rejected
    let wrong_scope = ScopeInfo::Project {
        project: openstack_keystone_core_types::resource::ProjectBuilder::default()
            .id(&other_project.id)
            .name("other")
            .domain_id(&domain.id)
            .enabled(true)
            .build()?,
        project_domain: openstack_keystone_core_types::resource::DomainBuilder::default()
            .id(&domain.id)
            .name("test")
            .enabled(true)
            .build()?,
    };

    assert!(
        ctx.validate_scope_boundaries(&wrong_scope).is_err(),
        "app cred must not be scoped to a different project"
    );

    // Domain scope must be rejected
    let domain_scope = ScopeInfo::Domain(
        openstack_keystone_core_types::resource::DomainBuilder::default()
            .id(&domain.id)
            .name("test")
            .enabled(true)
            .build()?,
    );
    assert!(
        ctx.validate_scope_boundaries(&domain_scope).is_err(),
        "app cred must not be scoped to a domain"
    );

    // System scope must be rejected
    let system_scope = ScopeInfo::System("all".into());
    assert!(
        ctx.validate_scope_boundaries(&system_scope).is_err(),
        "app cred must not be scoped to system"
    );

    Ok(())
}
