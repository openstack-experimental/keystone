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
use openstack_keystone::assignment::types::RoleCreate;
use sea_orm::{DbConn, entity::*};
use std::collections::HashSet;
use std::sync::Arc;
use tracing_test::traced_test;

use super::{create_user, get_state, grant_role_to_user_on_project};
use openstack_keystone::assignment::AssignmentApi;
use openstack_keystone::auth::*;
use openstack_keystone::db::entity::prelude::{Trust as DbTrust, TrustRole as DbTrustRole};
use openstack_keystone::db::entity::{trust as db_trust, trust_role as db_trust_role};
use openstack_keystone::keystone::Service;
use openstack_keystone::token::{Token, TokenApi, TokenProviderError};
use openstack_keystone::trust::TrustApi;
use openstack_keystone::trust::types::*;

async fn setup(db: &DbConn) -> Result<(), Report> {
    DbTrust::insert_many([
        db_trust::ActiveModel {
            id: Set("trust_a".into()),
            trustor_user_id: Set("user_a".into()),
            trustee_user_id: Set("user_b".into()),
            project_id: Set(Some("project_a".into())),
            impersonation: Set(false),
            deleted_at: NotSet,
            expires_at: NotSet,
            remaining_uses: NotSet,
            extra: Set(Some("{}".into())),
            expires_at_int: NotSet,
            redelegated_trust_id: NotSet,
            redelegation_count: NotSet,
        },
        db_trust::ActiveModel {
            id: Set("trust_a_b".into()),
            trustor_user_id: Set("user_a".into()),
            trustee_user_id: Set("user_c".into()),
            project_id: Set(Some("project_a".into())),
            impersonation: Set(false),
            deleted_at: NotSet,
            expires_at: NotSet,
            remaining_uses: NotSet,
            extra: Set(Some("{}".into())),
            expires_at_int: NotSet,
            redelegated_trust_id: Set(Some("trust_a".into())),
            redelegation_count: NotSet,
        },
    ])
    .exec(db)
    .await?;

    DbTrustRole::insert_many([
        db_trust_role::ActiveModel {
            trust_id: Set("trust_a".into()),
            role_id: Set("role_a".into()),
        },
        db_trust_role::ActiveModel {
            trust_id: Set("trust_a_b".into()),
            role_id: Set("role_a".into()),
        },
    ])
    .exec(db)
    .await?;

    Ok(())
}

async fn get_trust<U: AsRef<str>>(state: &Arc<Service>, id: U) -> Result<Option<Trust>, Report> {
    Ok(state
        .provider
        .get_trust_provider()
        .get_trust(state, id.as_ref())
        .await?)
}

#[tokio::test]
#[traced_test]
async fn test_valid() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    setup(&state.db).await?;

    let user_a = create_user(&state, Some("user_a")).await?;
    let user_b = create_user(&state, Some("user_b")).await?;
    grant_role_to_user_on_project(&state, &user_a.id, "project_a", "role_a").await?;

    let trust = get_trust(&state, "trust_a")
        .await?
        .expect("trust_a is present");

    let token = state.provider.get_token_provider().issue_token(
        AuthenticatedInfoBuilder::default()
            .user_id(user_b.id.clone())
            .user(user_b)
            .methods(vec!["password".into()])
            .build()?,
        AuthzInfo::Trust(trust.clone()),
        None,
    )?;

    let encoded_token = state.provider.get_token_provider().encode_token(&token)?;

    let unpacked_token = state
        .provider
        .get_token_provider()
        .validate_token(&state, &encoded_token, None, None)
        .await;

    if let Ok(unpacked_token) = &unpacked_token {
        match unpacked_token {
            Token::Trust(ttrust) => {
                assert_eq!(trust.id, ttrust.trust_id, "trust id matches");
                assert_eq!(
                    trust.trustee_user_id, ttrust.user_id,
                    "token uid is the trustee"
                );
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
async fn test_valid_redelegated() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    setup(&state.db).await?;

    let user_a = create_user(&state, Some("user_a")).await?;
    let _user_b = create_user(&state, Some("user_b")).await?;
    let user_c = create_user(&state, Some("user_c")).await?;
    grant_role_to_user_on_project(&state, &user_a.id, "project_a", "role_a").await?;

    let trust = get_trust(&state, "trust_a_b")
        .await?
        .expect("trust_a_b is present");

    let token = state.provider.get_token_provider().issue_token(
        AuthenticatedInfoBuilder::default()
            .user_id(user_c.id.clone())
            .user(user_c)
            .methods(vec!["password".into()])
            .build()?,
        AuthzInfo::Trust(trust.clone()),
        None,
    )?;

    let encoded_token = state.provider.get_token_provider().encode_token(&token)?;

    let unpacked_token = state
        .provider
        .get_token_provider()
        .validate_token(&state, &encoded_token, None, None)
        .await;

    if let Ok(unpacked_token) = &unpacked_token {
        match unpacked_token {
            Token::Trust(ttrust) => {
                assert_eq!(trust.id, ttrust.trust_id);
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
                panic!("the trust token is expected");
            }
        }
    } else {
        panic!(
            "the valid trust token is expected, it is {:?} instead",
            unpacked_token
        );
    }

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_fewer_roles() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    setup(&state.db).await?;

    let _user_a = create_user(&state, Some("user_a")).await?;
    let user_b = create_user(&state, Some("user_b")).await?;

    let trust = get_trust(&state, "trust_a")
        .await?
        .expect("trust_a is present");

    let token = state.provider.get_token_provider().issue_token(
        AuthenticatedInfoBuilder::default()
            .user_id(user_b.id.clone())
            .user(user_b)
            .methods(vec!["password".into()])
            .build()?,
        AuthzInfo::Trust(trust.clone()),
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
        panic!("should have returned error since the trustor is not having active role assignment");
    }
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_exclude_local_roles() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    setup(&state.db).await?;

    let user_a = create_user(&state, Some("user_a")).await?;
    let user_b = create_user(&state, Some("user_b")).await?;

    let role_x = state
        .provider
        .get_assignment_provider()
        .create_role(
            &state,
            RoleCreate {
                id: Some("role_x".into()),
                domain_id: Some("domain_a".into()),
                ..Default::default()
            },
        )
        .await?;
    DbTrustRole::insert_many([db_trust_role::ActiveModel {
        trust_id: Set("trust_a".into()),
        role_id: Set(role_x.id.clone()),
    }])
    .exec(&state.db)
    .await?;

    grant_role_to_user_on_project(&state, &user_a.id, "project_a", "role_a").await?;
    grant_role_to_user_on_project(&state, &user_a.id, "project_a", "role_x").await?;

    let trust = get_trust(&state, "trust_a")
        .await?
        .expect("trust_a is present");

    let token = state.provider.get_token_provider().issue_token(
        AuthenticatedInfoBuilder::default()
            .user_id(user_b.id.clone())
            .user(user_b)
            .methods(vec!["password".into()])
            .build()?,
        AuthzInfo::Trust(trust.clone()),
        None,
    )?;

    let encoded_token = state.provider.get_token_provider().encode_token(&token)?;

    let unpacked_token = state
        .provider
        .get_token_provider()
        .validate_token(&state, &encoded_token, None, None)
        .await;

    if let Ok(unpacked_token) = &unpacked_token {
        match unpacked_token {
            Token::Trust(ttrust) => {
                assert_eq!(trust.id, ttrust.trust_id, "trust id matches");
                assert_eq!(
                    trust.trustee_user_id, ttrust.user_id,
                    "token uid is the trustee"
                );
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
                panic!("the trust token is expected");
            }
        }
    } else {
        panic!("the valid trust token is expected");
    }

    Ok(())
}
