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
//! Test user group functionality.

use chrono::{DateTime, Utc};
use eyre::Report;
use sea_orm::entity::*;
use tracing_test::traced_test;

use openstack_keystone_identity_sql::entity::{
    expiring_user_group_membership,
    prelude::ExpiringUserGroupMembership as DbExpiringUserGroupMembership,
};

use openstack_keystone::identity::IdentityApi;

use super::*;
use crate::common::get_state;
use crate::{create_domain, create_group, create_user};

#[tokio::test]
async fn test_list_user_groups() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;
    let group = create_group!(state, domain.id.clone())?;
    state
        .provider
        .get_identity_provider()
        .add_user_to_group(&state, &user.id, &group.id)
        .await?;

    assert_eq!(
        list_user_groups(&state, &user.id)
            .await?
            .into_iter()
            .map(|group| group.id.clone())
            .collect::<Vec<_>>(),
        vec![group.id.clone()],
        "user is member of group a"
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_expiring_groups() -> Result<(), Report> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;
    let group_a = create_group!(state, domain.id.clone())?;
    let group_b = create_group!(state, domain.id.clone())?;
    let group_c = create_group!(state, domain.id.clone())?;

    state
        .provider
        .get_identity_provider()
        .add_user_to_group(&state, &user.id, &group_a.id)
        .await?;

    // non expired membership
    state
        .provider
        .get_identity_provider()
        .add_user_to_group_expiring(&state, &user.id, &group_b.id, "idp_id")
        .await?;

    // TODO: Find a way to add expired group membership for the test
    DbExpiringUserGroupMembership::insert_many([
        // Add expired membership
        expiring_user_group_membership::ActiveModel {
            user_id: Set(user.id.clone()),
            group_id: Set(group_c.id.clone()),
            idp_id: Set("idp_id".to_string()),
            last_verified: Set(DateTime::<Utc>::default().naive_utc()),
        },
    ])
    .exec(&state.db)
    .await?;

    let groups = list_user_groups(&state, &user.id).await?;

    assert_eq!(2, groups.len());
    assert!(groups.iter().find(|x| x.id == group_a.id).is_some());
    assert!(groups.iter().find(|x| x.id == group_b.id).is_some());
    Ok(())
}
