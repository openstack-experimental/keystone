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

//! Validation of the tokens issued after the password authentication.

use eyre::Report;
use secrecy::SecretString;
use tracing_test::traced_test;

use openstack_keystone::auth::*;
use openstack_keystone::token::{FernetToken, TokenProviderError};
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::identity::UserUpdate;
use openstack_keystone_core_types::resource::{DomainRefBuilder, ProjectRefBuilder};

use super::{grant_role_to_user_on_project, revoke_role_from_user_on_project};

use crate::common::get_state;
use crate::{create_domain, create_project, create_role, create_user};

/// Issue a project scoped token for the user authenticated by password.
async fn issue_token(
    state: &std::sync::Arc<openstack_keystone_core::keystone::Service>,
    user: &openstack_keystone_core_types::identity::UserResponse,
    project: &openstack_keystone_core_types::resource::Project,
    domain: &openstack_keystone_core_types::resource::Domain,
) -> Result<String, Report> {
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user.id.clone())
                    .user(user.clone())
                    .build()?,
            ),
        })
        .build()?;
    let ctx = SecurityContext::try_from(auth)?;

    let vsc = state
        .provider
        .get_token_provider()
        .issue_token_context(
            &ExecutionContext::internal(state),
            &ctx,
            &ScopeInfo::Project {
                project: ProjectRefBuilder::default()
                    .id(project.id.clone())
                    .name(project.name.clone())
                    .domain_id(domain.id.clone())
                    .enabled(true)
                    .build()?,
                project_domain: DomainRefBuilder::default()
                    .id(domain.id.clone())
                    .name(domain.name.clone())
                    .enabled(true)
                    .build()?,
            },
        )
        .await?;

    Ok(state
        .provider
        .get_token_provider()
        .encode_token(vsc.inner().token().ok_or_else(|| eyre::eyre!("no token"))?)?)
}

#[tokio::test]
#[traced_test]
async fn test_valid() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let role = create_role!(state)?;
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role.id).await?;

    let encoded_token = issue_token(&state, &user, &project, &domain).await?;

    let vsc = state
        .provider
        .get_token_provider()
        .validate_to_context(
            &ExecutionContext::internal(&state),
            &encoded_token,
            None,
            None,
        )
        .await?;

    match vsc.inner().token() {
        Some(FernetToken::ProjectScope(data)) => {
            assert_eq!(data.user_id, user.id);
            assert_eq!(data.project_id, project.id);
        }
        other => panic!("The unpacked token is not a project scope token: {other:?}"),
    }
    let roles = vsc
        .inner()
        .authorization()
        .ok_or_else(|| eyre::eyre!("authz present"))?
        .effective_roles()
        .ok_or_else(|| eyre::eyre!("roles present"))?;
    assert!(
        roles.iter().any(|r| r.id == role.id),
        "token should contain the granted role"
    );
    // The complete user is resolved for the token rendering.
    match &vsc.inner().principal().identity {
        IdentityInfo::User(info) => assert!(info.user.is_some()),
        other => panic!("unexpected identity: {other:?}"),
    }

    Ok(())
}

/// The request authentication resolves only the minimal user data.
#[tokio::test]
#[traced_test]
async fn test_valid_request_token() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let role = create_role!(state)?;
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role.id).await?;

    let encoded_token = issue_token(&state, &user, &project, &domain).await?;

    let vsc = state
        .provider
        .get_token_provider()
        .authorize_request_token(
            &ExecutionContext::internal(&state),
            &SecretString::from(encoded_token.clone()),
        )
        .await?;

    match &vsc.inner().principal().identity {
        IdentityInfo::User(info) => {
            assert_eq!(info.user_id, user.id);
            assert!(info.user.is_none(), "complete user must not be loaded");
            let core = info
                .user_core
                .as_ref()
                .ok_or_else(|| eyre::eyre!("user_core present"))?;
            assert_eq!(core.id, user.id);
            assert_eq!(core.domain_id, domain.id);
            assert!(core.enabled);
        }
        other => panic!("unexpected identity: {other:?}"),
    }
    let roles = vsc
        .inner()
        .authorization()
        .ok_or_else(|| eyre::eyre!("authz present"))?
        .effective_roles()
        .ok_or_else(|| eyre::eyre!("roles present"))?;
    assert!(roles.iter().any(|r| r.id == role.id));

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_user_disabled() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let role = create_role!(state)?;
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role.id).await?;

    let encoded_token = issue_token(&state, &user, &project, &domain).await?;

    state
        .provider
        .get_identity_provider()
        .update_user(
            &ExecutionContext::internal(&state),
            &user.id,
            UserUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;

    let full = state
        .provider
        .get_token_provider()
        .validate_to_context(
            &ExecutionContext::internal(&state),
            &encoded_token,
            None,
            None,
        )
        .await;
    assert!(
        matches!(
            full,
            Err(TokenProviderError::Authentication(
                AuthenticationError::UserDisabled(_)
            ))
        ),
        "validation should fail for the disabled user: {full:?}"
    );

    let minimal = state
        .provider
        .get_token_provider()
        .authorize_request_token(
            &ExecutionContext::internal(&state),
            &SecretString::from(encoded_token.clone()),
        )
        .await;
    assert!(
        matches!(
            minimal,
            Err(TokenProviderError::Authentication(
                AuthenticationError::UserDisabled(_)
            ))
        ),
        "request authentication should fail for the disabled user: {minimal:?}"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_all_roles_revoked() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let role = create_role!(state)?;
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role.id).await?;

    let encoded_token = issue_token(&state, &user, &project, &domain).await?;
    revoke_role_from_user_on_project(&state, &user.id, &project.id, &role.id).await?;

    for result in [
        state
            .provider
            .get_token_provider()
            .validate_to_context(
                &ExecutionContext::internal(&state),
                &encoded_token,
                None,
                None,
            )
            .await,
        state
            .provider
            .get_token_provider()
            .authorize_request_token(
                &ExecutionContext::internal(&state),
                &SecretString::from(encoded_token.clone()),
            )
            .await,
    ] {
        assert!(
            matches!(
                result,
                Err(TokenProviderError::Authentication(
                    AuthenticationError::ActorHasNoRolesOnTarget
                ))
            ),
            "should fail since the user has no active role assignment: {result:?}"
        );
    }
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_token_revoked() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let role = create_role!(state)?;
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role.id).await?;

    let encoded_token = issue_token(&state, &user, &project, &domain).await?;

    let vsc = state
        .provider
        .get_token_provider()
        .validate_to_context(
            &ExecutionContext::internal(&state),
            &encoded_token,
            None,
            None,
        )
        .await?;

    state
        .provider
        .get_revoke_provider()
        .revoke_token(
            &ExecutionContext::internal(&state),
            vsc.inner().token().ok_or_else(|| eyre::eyre!("no token"))?,
        )
        .await?;

    assert!(
        state
            .provider
            .get_revoke_provider()
            .is_token_revoked(&ExecutionContext::internal(&state), &vsc)
            .await?
    );
    let minimal = state
        .provider
        .get_token_provider()
        .authorize_request_token(
            &ExecutionContext::internal(&state),
            &SecretString::from(encoded_token.clone()),
        )
        .await;
    assert!(
        matches!(minimal, Err(TokenProviderError::TokenRevoked)),
        "revoked token must be rejected by the request authentication: {minimal:?}"
    );
    Ok(())
}
