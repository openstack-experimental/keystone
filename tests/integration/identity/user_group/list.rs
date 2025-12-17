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

use openstack_keystone::db::entity::{
    expiring_user_group_membership,
    prelude::ExpiringUserGroupMembership as DbExpiringUserGroupMembership,
};

use super::*;

#[tokio::test]
async fn test_list_user_groups() -> Result<(), Report> {
    let state = get_state().await?;

    assert_eq!(
        list_user_groups(&state, "user_a")
            .await?
            .into_iter()
            .map(|group| group.id.clone())
            .collect::<Vec<_>>(),
        vec!["group_a".to_string()],
        "user is member of group a"
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_expiring_groups() -> Result<(), Report> {
    let state = get_state().await?;

    DbExpiringUserGroupMembership::insert_many([
        // Add expired membership
        expiring_user_group_membership::ActiveModel {
            user_id: Set("user_a".to_string()),
            group_id: Set("group_c".to_string()),
            idp_id: Set("idp_id".to_string()),
            last_verified: Set(DateTime::<Utc>::default().naive_utc()),
        },
        // non expired membership
        expiring_user_group_membership::ActiveModel {
            user_id: Set("user_a".to_string()),
            group_id: Set("group_b".to_string()),
            idp_id: Set("idp_id".to_string()),
            last_verified: Set(Utc::now().naive_utc()),
        },
    ])
    .exec(&state.db)
    .await?;

    assert_eq!(
        list_user_groups(&state, "user_a")
            .await?
            .into_iter()
            .map(|group| group.id.clone())
            .collect::<Vec<_>>(),
        vec!["group_a".to_string(), "group_b".to_string()],
        "user is member of groups a and b"
    );
    Ok(())
}
