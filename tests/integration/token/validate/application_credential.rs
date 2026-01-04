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

use chrono::Utc;
use eyre::Report;
use std::collections::HashSet;
use tracing_test::traced_test;
use uuid::Uuid;

use super::{create_user, get_state, grant_role_to_user_on_project};
use crate::common::create_role;
use openstack_keystone::application_credential::ApplicationCredentialApi;
use openstack_keystone::application_credential::types::*;
use openstack_keystone::assignment::types::*;
use openstack_keystone::auth::*;
use openstack_keystone::resource::types::ProjectBuilder;
use openstack_keystone::token::{Token, TokenApi, TokenProviderError};

#[tokio::test]
#[traced_test]
async fn test_valid() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;

    let user = create_user(&state, Some("user_a")).await?;
    create_role(&state, "role_a").await?;
    grant_role_to_user_on_project(&state, &user.id, "project_a", "role_a").await?;

    let cred: ApplicationCredentialCreateResponse = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &state,
            ApplicationCredentialCreate {
                access_rules: None,
                name: Uuid::new_v4().to_string(),
                project_id: "project_a".into(),
                roles: vec![Role {
                    id: "role_a".into(),
                    ..Default::default()
                }],
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    let token = state.provider.get_token_provider().issue_token(
        AuthenticatedInfoBuilder::default()
            .application_credential(cred.clone())
            .user_id(user.id.clone())
            .user(user)
            .methods(vec!["application_credential".into()])
            .build()?,
        AuthzInfo::Project(
            ProjectBuilder::default()
                .id(cred.project_id.clone())
                .name("project_a")
                .domain_id("domain_a")
                .enabled(true)
                .build()?,
        ),
        None,
    )?;

    let encoded_token = state.provider.get_token_provider().encode_token(&token)?;

    let unpacked_token = state
        .provider
        .get_token_provider()
        .validate_token(&state, &encoded_token, None, None)
        .await;

    if let Ok(unpacked_token) = unpacked_token {
        match unpacked_token {
            Token::ApplicationCredential(ref data) => {
                assert_eq!(data.application_credential_id, cred.id);
                assert_eq!(
                    HashSet::from_iter(
                        unpacked_token
                            .roles()
                            .expect("roles present in the token")
                            .iter()
                            .map(|role| role.id.clone())
                    ),
                    HashSet::from(["role_a".to_string()])
                );
            }
            _ => {
                panic!("The unpacked token is not application credential");
            }
        }
    } else {
        panic!("the token should be valid, but it is {:?}", unpacked_token);
    }

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_expired() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;

    let user = create_user(&state, Some("user_a")).await?;
    create_role(&state, "role_a").await?;
    grant_role_to_user_on_project(&state, &user.id, "project_a", "role_a").await?;

    let cred: ApplicationCredentialCreateResponse = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &state,
            ApplicationCredentialCreate {
                access_rules: None,
                expires_at: Some(Utc::now()),
                name: Uuid::new_v4().to_string(),
                project_id: "project_a".into(),
                roles: vec![Role {
                    id: "role_a".into(),
                    ..Default::default()
                }],
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    let token = state.provider.get_token_provider().issue_token(
        AuthenticatedInfoBuilder::default()
            .application_credential(cred.clone())
            .user_id(user.id.clone())
            .user(user)
            .methods(vec!["application_credential".into()])
            .build()?,
        AuthzInfo::Project(
            ProjectBuilder::default()
                .id(cred.project_id.clone())
                .name("project_a")
                .domain_id("domain_a")
                .enabled(true)
                .build()?,
        ),
        None,
    )?;

    let encoded_token = state.provider.get_token_provider().encode_token(&token)?;

    let unpacked_token = state
        .provider
        .get_token_provider()
        .validate_token(&state, &encoded_token, None, None)
        .await;

    if let Err(TokenProviderError::Expired) = unpacked_token {
    } else {
        panic!("the token should be expired");
    }

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_valid_fewer_roles() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;

    let user = create_user(&state, Some("user_a")).await?;
    create_role(&state, "role_a").await?;
    create_role(&state, "role_b").await?;
    grant_role_to_user_on_project(&state, &user.id, "project_a", "role_a").await?;

    let cred: ApplicationCredentialCreateResponse = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &state,
            ApplicationCredentialCreate {
                access_rules: None,
                name: Uuid::new_v4().to_string(),
                project_id: "project_a".into(),
                roles: vec![
                    Role {
                        id: "role_a".into(),
                        ..Default::default()
                    },
                    Role {
                        id: "role_b".into(),
                        ..Default::default()
                    },
                ],
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    let token = state.provider.get_token_provider().issue_token(
        AuthenticatedInfoBuilder::default()
            .application_credential(cred.clone())
            .user_id(user.id.clone())
            .user(user)
            .methods(vec!["application_credential".into()])
            .build()?,
        AuthzInfo::Project(
            ProjectBuilder::default()
                .id(cred.project_id.clone())
                .name("project_a")
                .domain_id("domain_a")
                .enabled(true)
                .build()?,
        ),
        None,
    )?;

    let encoded_token = state.provider.get_token_provider().encode_token(&token)?;

    let unpacked_token = state
        .provider
        .get_token_provider()
        .validate_token(&state, &encoded_token, None, None)
        .await;

    if let Ok(unpacked_token) = unpacked_token {
        match unpacked_token {
            Token::ApplicationCredential(ref data) => {
                assert_eq!(data.application_credential_id, cred.id);
                assert_eq!(
                    HashSet::from_iter(
                        unpacked_token
                            .roles()
                            .expect("roles present in the token")
                            .iter()
                            .map(|role| role.id.clone())
                    ),
                    HashSet::from(["role_a".to_string()])
                );
            }
            _ => {
                panic!("The unpacked token is not application credential");
            }
        }
    } else {
        panic!("the token should be valid, but it is {:?}", unpacked_token);
    }

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_valid_all_roles_revoked() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;

    let user = create_user(&state, Some("user_a")).await?;
    create_role(&state, "role_b").await?;

    let cred: ApplicationCredentialCreateResponse = state
        .provider
        .get_application_credential_provider()
        .create_application_credential(
            &state,
            ApplicationCredentialCreate {
                access_rules: None,
                name: Uuid::new_v4().to_string(),
                project_id: "project_a".into(),
                roles: vec![Role {
                    id: "role_b".into(),
                    ..Default::default()
                }],
                user_id: user.id.clone(),
                ..Default::default()
            },
        )
        .await?;

    let token = state.provider.get_token_provider().issue_token(
        AuthenticatedInfoBuilder::default()
            .application_credential(cred.clone())
            .user_id(user.id.clone())
            .user(user)
            .methods(vec!["application_credential".into()])
            .build()?,
        AuthzInfo::Project(
            ProjectBuilder::default()
                .id(cred.project_id.clone())
                .name("project_a")
                .domain_id("domain_a")
                .enabled(true)
                .build()?,
        ),
        None,
    )?;

    let encoded_token = state.provider.get_token_provider().encode_token(&token)?;

    let unpacked_token = state
        .provider
        .get_token_provider()
        .validate_token(&state, &encoded_token, None, None)
        .await;

    if let Err(TokenProviderError::ActorHasNoRolesOnTarget) = unpacked_token {
    } else {
        panic!(
            "should have returned error since the application credential is not having any active role assignment"
        );
    }
    Ok(())
}
