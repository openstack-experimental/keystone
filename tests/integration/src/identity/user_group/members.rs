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
//! Test group member listing and membership check functionality.

use chrono::{DateTime, Utc};
use eyre::Report;
use sea_orm::entity::*;
use tracing_test::traced_test;

use openstack_keystone_identity_driver_sql::entity::{
    expiring_user_group_membership,
    prelude::ExpiringUserGroupMembership as DbExpiringUserGroupMembership,
};

use super::*;
use crate::common::get_state;
use crate::{create_domain, create_group, create_user};
use openstack_keystone_core::auth::ExecutionContext;

async fn list_group_users(state: &ServiceState, group_id: &str) -> Result<Vec<String>, Report> {
    let mut ids: Vec<String> = state
        .provider
        .get_identity_provider()
        .list_users(
            &ExecutionContext::internal(state),
            &UserListParameters {
                group_id: Some(group_id.to_string()),
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .map(|user| user.id)
        .collect();
    ids.sort();
    Ok(ids)
}

async fn is_member(state: &ServiceState, user_id: &str, group_id: &str) -> Result<bool, Report> {
    Ok(state
        .provider
        .get_identity_provider()
        .check_user_in_group(&ExecutionContext::internal(state), user_id, group_id)
        .await?)
}

#[tokio::test]
#[traced_test]
async fn test_list_group_users() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user_a = create_user!(state, domain.id.clone())?;
    let user_b = create_user!(state, domain.id.clone())?;
    let user_c = create_user!(state, domain.id.clone())?;
    let group = create_group!(state, domain.id.clone())?;
    let other = create_group!(state, domain.id.clone())?;
    let idp = state.provider.get_identity_provider();

    idp.add_user_to_group(&ExecutionContext::internal(&state), &user_a.id, &group.id)
        .await?;
    idp.add_user_to_group(&ExecutionContext::internal(&state), &user_b.id, &group.id)
        .await?;
    idp.add_user_to_group(&ExecutionContext::internal(&state), &user_c.id, &other.id)
        .await?;

    let mut expected = vec![user_a.id.clone(), user_b.id.clone()];
    expected.sort();
    assert_eq!(list_group_users(&state, &group.id).await?, expected);
    assert_eq!(
        list_group_users(&state, &other.id).await?,
        vec![user_c.id.clone()]
    );

    idp.remove_user_from_group(&ExecutionContext::internal(&state), &user_a.id, &group.id)
        .await?;
    assert_eq!(
        list_group_users(&state, &group.id).await?,
        vec![user_b.id.clone()],
        "removed member no longer listed"
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_list_group_users_empty_group() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    create_user!(state, domain.id.clone())?;
    let group = create_group!(state, domain.id.clone())?;

    assert!(list_group_users(&state, &group.id).await?.is_empty());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_list_group_users_expiring() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let direct = create_user!(state, domain.id.clone())?;
    let fresh = create_user!(state, domain.id.clone())?;
    let expired = create_user!(state, domain.id.clone())?;
    let group = create_group!(state, domain.id.clone())?;
    let idp = state.provider.get_identity_provider();

    idp.add_user_to_group(&ExecutionContext::internal(&state), &direct.id, &group.id)
        .await?;
    idp.add_user_to_group_expiring(
        &ExecutionContext::internal(&state),
        &fresh.id,
        &group.id,
        "idp_id",
    )
    .await?;
    DbExpiringUserGroupMembership::insert(expiring_user_group_membership::ActiveModel {
        user_id: Set(expired.id.clone()),
        group_id: Set(group.id.clone()),
        idp_id: Set("idp_id".to_string()),
        last_verified: Set(DateTime::<Utc>::default().naive_utc()),
    })
    .exec(&ExecutionContext::internal(&state).db.connection())
    .await?;

    let mut expected = vec![direct.id.clone(), fresh.id.clone()];
    expected.sort();
    assert_eq!(
        list_group_users(&state, &group.id).await?,
        expected,
        "expired membership is not listed"
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_check_user_in_group() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;
    let group = create_group!(state, domain.id.clone())?;
    let idp = state.provider.get_identity_provider();

    assert!(!is_member(&state, &user.id, &group.id).await?);

    idp.add_user_to_group(&ExecutionContext::internal(&state), &user.id, &group.id)
        .await?;
    assert!(is_member(&state, &user.id, &group.id).await?);

    idp.remove_user_from_group(&ExecutionContext::internal(&state), &user.id, &group.id)
        .await?;
    assert!(!is_member(&state, &user.id, &group.id).await?);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_check_user_in_group_expiring() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;
    let fresh_group = create_group!(state, domain.id.clone())?;
    let expired_group = create_group!(state, domain.id.clone())?;

    state
        .provider
        .get_identity_provider()
        .add_user_to_group_expiring(
            &ExecutionContext::internal(&state),
            &user.id,
            &fresh_group.id,
            "idp_id",
        )
        .await?;
    DbExpiringUserGroupMembership::insert(expiring_user_group_membership::ActiveModel {
        user_id: Set(user.id.clone()),
        group_id: Set(expired_group.id.clone()),
        idp_id: Set("idp_id".to_string()),
        last_verified: Set(DateTime::<Utc>::default().naive_utc()),
    })
    .exec(&ExecutionContext::internal(&state).db.connection())
    .await?;

    assert!(is_member(&state, &user.id, &fresh_group.id).await?);
    assert!(
        !is_member(&state, &user.id, &expired_group.id).await?,
        "expired membership does not count"
    );
    Ok(())
}
