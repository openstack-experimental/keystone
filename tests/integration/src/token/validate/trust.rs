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
//

use eyre::Report;
use sea_orm::{DbConn, entity::*};
use std::sync::Arc;
use tracing_test::traced_test;

use openstack_keystone_trust_driver_sql::entity::{trust as db_trust, trust_role as db_trust_role};

use openstack_keystone::keystone::Service;
use openstack_keystone::token::{FernetToken, TokenProviderError};
use openstack_keystone_api_types::v3::auth::token::TokenBuilder;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::auth::*;
use openstack_keystone_core_types::trust::*;

use super::grant_role_to_user_on_project;

use crate::common::get_state;
use crate::token::validate::revoke_role_from_user_on_project;
use crate::{create_domain, create_project, create_role, create_user};

async fn create_trust<S: Into<String>>(
    db: &DbConn,
    trust_id: S,
    trustor_id: S,
    trustee_id: S,
    project_id: S,
    role_ids: Vec<S>,
) -> Result<(), Report> {
    let trust_id = trust_id.into();
    db_trust::ActiveModel {
        id: Set(trust_id.clone()),
        trustor_user_id: Set(trustor_id.into()),
        trustee_user_id: Set(trustee_id.into()),
        project_id: Set(Some(project_id.into())),
        impersonation: Set(false),
        deleted_at: NotSet,
        expires_at: NotSet,
        remaining_uses: NotSet,
        extra: Set(Some("{}".into())),
        expires_at_int: NotSet,
        redelegated_trust_id: NotSet,
        redelegation_count: NotSet,
    }
    .insert(db)
    .await?;
    for role_id in role_ids {
        db_trust_role::ActiveModel {
            trust_id: Set(trust_id.clone()),
            role_id: Set(role_id.into()),
        }
        .insert(db)
        .await?;
    }

    Ok(())
}

async fn get_trust<U: AsRef<str>>(state: &Arc<Service>, id: U) -> Result<Option<Trust>, Report> {
    Ok(state
        .provider
        .get_trust_provider()
        .get_trust(&ExecutionContext::internal(state), id.as_ref())
        .await?)
}

#[tokio::test]
#[traced_test]
async fn test_valid() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let role_a = create_role!(state)?;

    let user_a = create_user!(state, domain.id.clone())?;
    let user_b = create_user!(state, domain.id.clone())?;
    grant_role_to_user_on_project(&state, &user_a.id, &project.id, &role_a.id).await?;

    create_trust(
        &state.db,
        "trust_a".to_string(),
        user_a.id.clone(),
        user_b.id.clone(),
        project.id.clone(),
        Vec::from([role_a.id.clone()]),
    )
    .await?;
    //setup(&state.db).await?;
    let trust = get_trust(&state, "trust_a")
        .await?
        .expect("trust_a is present");

    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user_b.id.clone())
                    .user(user_b.clone())
                    .build()?,
            ),
        })
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(auth).unwrap();

    let trust_project = state
        .provider
        .get_resource_provider()
        .get_project(
            &ExecutionContext::internal(&state),
            &trust.project_id.clone().unwrap(),
        )
        .await?
        .expect("trust project exists");
    let project_domain = state
        .provider
        .get_resource_provider()
        .get_domain(
            &ExecutionContext::internal(&state),
            &trust_project.domain_id,
        )
        .await?
        .expect("trust project domain exists");

    let vsc = state
        .provider
        .get_token_provider()
        .issue_token_context(
            &ExecutionContext::internal(&state),
            &ctx,
            &ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
                trust: trust.clone(),
                project: trust_project,
                project_domain,
            })),
        )
        .await?;

    let encoded_token = state
        .provider
        .get_token_provider()
        .encode_token(vsc.inner().token().unwrap())?;

    let vsc_result = state
        .provider
        .get_token_provider()
        .validate_to_context(
            &ExecutionContext::internal(&state),
            &encoded_token,
            None,
            None,
        )
        .await;

    if let Ok(ref vsc_result) = vsc_result {
        match vsc_result.inner().token().unwrap() {
            FernetToken::Trust(ttrust) => {
                assert_eq!(trust.id, ttrust.trust_id, "trust id matches");
                assert_eq!(
                    trust.trustee_user_id, ttrust.user_id,
                    "token uid is the trustee"
                );
                let roles = vsc_result
                    .inner()
                    .authorization()
                    .expect("authz present")
                    .effective_roles()
                    .expect("roles present");
                assert!(
                    roles.iter().any(|r| r.id == role_a.id),
                    "token should contain role_a"
                );
            }
            _ => {
                panic!("the trust token is expected");
            }
        }
    } else {
        panic!("the valid trust token is expected, {:?}", vsc_result);
    }

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_valid_redelegated() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let role_a = create_role!(state)?;

    let user_a = create_user!(state, domain.id.clone())?;
    let user_c = create_user!(state, domain.id.clone())?;
    grant_role_to_user_on_project(&state, &user_a.id, &project.id, &role_a.id).await?;
    create_trust(
        &state.db,
        "trust_a_b".to_string(),
        user_a.id.clone(),
        user_c.id.clone(),
        project.id.clone(),
        Vec::from([role_a.id.clone()]),
    )
    .await?;

    let trust = get_trust(&state, "trust_a_b")
        .await?
        .expect("trust_a_b is present");

    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user_c.id.clone())
                    .user(user_c.clone())
                    .build()?,
            ),
        })
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(auth).unwrap();
    let trust_project = state
        .provider
        .get_resource_provider()
        .get_project(
            &ExecutionContext::internal(&state),
            &trust.project_id.clone().unwrap(),
        )
        .await?
        .expect("trust project exists");
    let project_domain = state
        .provider
        .get_resource_provider()
        .get_domain(
            &ExecutionContext::internal(&state),
            &trust_project.domain_id,
        )
        .await?
        .expect("trust project domain exists");

    let vsc = state
        .provider
        .get_token_provider()
        .issue_token_context(
            &ExecutionContext::internal(&state),
            &ctx,
            &ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
                trust: trust.clone(),
                project: trust_project,
                project_domain,
            })),
        )
        .await?;

    let encoded_token = state
        .provider
        .get_token_provider()
        .encode_token(vsc.inner().token().unwrap())?;

    let vsc_result = state
        .provider
        .get_token_provider()
        .validate_to_context(
            &ExecutionContext::internal(&state),
            &encoded_token,
            None,
            None,
        )
        .await;

    if let Ok(ref vsc_result) = vsc_result {
        match vsc_result.inner().token().unwrap() {
            FernetToken::Trust(ttrust) => {
                assert_eq!(trust.id, ttrust.trust_id);
                let roles = vsc_result
                    .inner()
                    .authorization()
                    .expect("authz present")
                    .effective_roles()
                    .expect("roles present");
                assert!(
                    roles.iter().any(|r| r.id == role_a.id),
                    "token should contain role_a"
                );
            }
            _ => {
                panic!("the trust token is expected");
            }
        }
    } else {
        panic!(
            "the valid trust token is expected, it is {:?} instead",
            vsc_result
        );
    }

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_fewer_roles() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let role_a = create_role!(state)?;

    let user_a = create_user!(state, domain.id.clone())?;
    let user_b = create_user!(state, domain.id.clone())?;
    grant_role_to_user_on_project(&state, &user_a.id, &project.id, &role_a.id).await?;

    create_trust(
        &state.db,
        "trust_a".to_string(),
        user_a.id.clone(),
        user_b.id.clone(),
        project.id.clone(),
        Vec::from([role_a.id.clone()]),
    )
    .await?;
    let trust = get_trust(&state, "trust_a")
        .await?
        .expect("trust_a is present");

    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user_b.id.clone())
                    .user(user_b.clone())
                    .build()?,
            ),
        })
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(auth).unwrap();

    let trust_project = state
        .provider
        .get_resource_provider()
        .get_project(
            &ExecutionContext::internal(&state),
            &trust.project_id.clone().unwrap(),
        )
        .await?
        .expect("trust project exists");
    let project_domain = state
        .provider
        .get_resource_provider()
        .get_domain(
            &ExecutionContext::internal(&state),
            &trust_project.domain_id,
        )
        .await?
        .expect("trust project domain exists");

    let vsc = state
        .provider
        .get_token_provider()
        .issue_token_context(
            &ExecutionContext::internal(&state),
            &ctx,
            &ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
                trust: trust.clone(),
                project: trust_project,
                project_domain,
            })),
        )
        .await?;

    let encoded_token = state
        .provider
        .get_token_provider()
        .encode_token(vsc.inner().token().unwrap())?;

    revoke_role_from_user_on_project(&state, &user_a.id, &project.id, &role_a.id).await?;

    let unpacked_token = state
        .provider
        .get_token_provider()
        .validate_to_context(
            &ExecutionContext::internal(&state),
            &encoded_token,
            None,
            None,
        )
        .await;

    if let Err(TokenProviderError::Authentication(AuthenticationError::ActorHasNoRolesOnTarget)) =
        unpacked_token
    {
    } else {
        panic!(
            "should have returned error since the trustor is not having active role assignment: {:?}",
            unpacked_token
        );
    }
    Ok(())
}

/// Only global roles (without domain_id) can be delegated and consumed through
/// trust. Python keystone filters role in the token model.
#[tokio::test]
//#[traced_test]
async fn test_exclude_local_roles() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;

    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let role_a = create_role!(state)?;
    let role_x = create_role!(state, "role_x", domain.id.clone())?;

    let user_a = create_user!(state, domain.id.clone())?;
    let user_b = create_user!(state, domain.id.clone())?;
    grant_role_to_user_on_project(&state, &user_a.id, &project.id, &role_a.id).await?;
    grant_role_to_user_on_project(&state, &user_a.id, &project.id, &role_x.id).await?;

    create_trust(
        &state.db,
        "trust_a".to_string(),
        user_a.id.clone(),
        user_b.id.clone(),
        project.id.clone(),
        Vec::from([role_a.id.clone(), role_x.id.clone()]),
    )
    .await?;

    let trust = get_trust(&state, "trust_a")
        .await?
        .expect("trust_a is present");

    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user_b.id.clone())
                    .user(user_b.clone())
                    .build()?,
            ),
        })
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(auth).unwrap();

    let trust_project = state
        .provider
        .get_resource_provider()
        .get_project(
            &ExecutionContext::internal(&state),
            &trust.project_id.clone().unwrap(),
        )
        .await?
        .expect("trust project exists");
    let project_domain = state
        .provider
        .get_resource_provider()
        .get_domain(
            &ExecutionContext::internal(&state),
            &trust_project.domain_id,
        )
        .await?
        .expect("trust project domain exists");

    let vsc = state
        .provider
        .get_token_provider()
        .issue_token_context(
            &ExecutionContext::internal(&state),
            &ctx,
            &ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
                trust: trust.clone(),
                project: trust_project,
                project_domain,
            })),
        )
        .await?;

    let encoded_token = state
        .provider
        .get_token_provider()
        .encode_token(vsc.inner().token().unwrap())?;

    let vsc_result = state
        .provider
        .get_token_provider()
        .validate_to_context(
            &ExecutionContext::internal(&state),
            &encoded_token,
            None,
            None,
        )
        .await;

    if let Ok(ref vsc_result) = vsc_result {
        match vsc_result.inner().token().unwrap() {
            FernetToken::Trust(ttrust) => {
                assert_eq!(trust.id, ttrust.trust_id, "trust id matches");
                assert_eq!(
                    trust.trustee_user_id, ttrust.user_id,
                    "token uid is the trustee"
                );
                let roles = vsc_result
                    .inner()
                    .authorization()
                    .expect("authz present")
                    .effective_roles()
                    .expect("roles present");
                assert!(
                    roles.iter().any(|r| r.id == role_a.id),
                    "token should contain global role_a"
                );
                assert!(
                    !roles.iter().any(|r| r.id == role_x.id),
                    "token should NOT contain domain-scoped role_x"
                );
            }
            _ => {
                panic!("the trust token is expected");
            }
        }
    } else {
        panic!("the valid trust token is expected");
    }

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_trust_populated_in_api_token_response() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let role_a = create_role!(state)?;

    let user_a = create_user!(state, domain.id.clone())?;
    let user_b = create_user!(state, domain.id.clone())?;

    grant_role_to_user_on_project(
        &state,
        user_a.id.clone(),
        project.id.clone(),
        role_a.id.clone(),
    )
    .await?;

    create_trust(
        &state.db,
        "trust_a".to_string(),
        user_a.id.clone(),
        user_b.id.clone(),
        project.id.clone(),
        vec![role_a.id.clone()],
    )
    .await?;
    let trust = get_trust(&state, "trust_a")
        .await?
        .expect("trust_a is present");

    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user_b.id.clone())
                    .user(user_b.clone())
                    .build()?,
            ),
        })
        .build()
        .unwrap();
    let ctx = SecurityContext::try_from(auth).unwrap();

    let trust_project = state
        .provider
        .get_resource_provider()
        .get_project(
            &ExecutionContext::internal(&state),
            &trust.project_id.clone().unwrap(),
        )
        .await?
        .expect("trust project exists");
    let project_domain = state
        .provider
        .get_resource_provider()
        .get_domain(
            &ExecutionContext::internal(&state),
            &trust_project.domain_id,
        )
        .await?
        .expect("trust project domain exists");

    let vsc = state
        .provider
        .get_token_provider()
        .issue_token_context(
            &ExecutionContext::internal(&state),
            &ctx,
            &ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
                trust: trust.clone(),
                project: trust_project,
                project_domain,
            })),
        )
        .await?;

    let api_token = TokenBuilder::try_from(&vsc)?.build()?;
    assert!(
        api_token.trust.is_some(),
        "trust field should be populated in API token response"
    );
    let api_trust = api_token.trust.unwrap();
    assert_eq!(api_trust.id, trust.id, "trust id matches");
    assert_eq!(
        api_trust.trustor_user.id, trust.trustor_user_id,
        "trustor user id matches"
    );
    assert_eq!(
        api_trust.trustee_user.id, trust.trustee_user_id,
        "trustee user id matches"
    );
    assert_eq!(
        api_trust.impersonation, trust.impersonation,
        "impersonation flag matches"
    );

    Ok(())
}
