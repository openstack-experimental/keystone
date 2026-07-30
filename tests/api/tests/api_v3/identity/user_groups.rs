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
//! `GET /v3/users/{user_id}/groups` authorization matrix (issue #993).
//!
//! | case | test |
//! |------|------|
//! | admin reads a fresh user's (empty) memberships | `test_user_groups_success_admin_empty` |
//! | admin reads a SCIM-populated membership | `scim_v2/v3_user_groups.rs::test_scim_membership_is_visible_in_v3_user_groups` |
//! | project-scoped user reads another user (policy `identity/user/show`) | `test_user_groups_forbidden_project_scoped_user` |
//! | invalid token | `test_user_groups_unauthorized` |
//!
//! A populated-listing case is exercised from the SCIM suite because SCIM is
//! the only live write path for memberships; keeping that cross-protocol setup
//! out of this binary preserves its Python Keystone compatibility.

use std::sync::Arc;

use eyre::Result;

use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::asserts::{assert_forbidden, assert_unauthorized};
use test_api::common::raw_request;
use test_api::fixtures::{
    ProjectScopedUser, cleanup_project_scoped_users, warn_on_cleanup_failure,
};
use test_api::identity::user::{UserGroupsRequest, list_user_groups};

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&CloudConfig::from_env()?).await?,
    ))
}

#[tokio::test]
async fn test_user_groups_success_admin_empty() -> Result<()> {
    let admin = admin_session().await?;
    let fixture = ProjectScopedUser::provision(&admin, "default", "member").await?;

    let groups = list_user_groups(&admin, &fixture.user.id, UserGroupsRequest::default()).await?;
    assert!(
        groups.is_empty(),
        "a freshly created user must have no group memberships, got: {groups:?}"
    );

    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_user_groups_forbidden_project_scoped_user() -> Result<()> {
    let admin = admin_session().await?;
    let a = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let b = match ProjectScopedUser::provision(&admin, "default", "member").await {
        Ok(b) => b,
        Err(error) => {
            warn_on_cleanup_failure("member fixture", a.cleanup().await);
            return Err(error);
        }
    };

    let list_result = list_user_groups(&a.session, &b.user.id, UserGroupsRequest::default()).await;
    let cleanup_result = cleanup_project_scoped_users([a, b]).await;

    cleanup_result?;
    assert_forbidden(
        list_result,
        "a project-scoped user must not read another user's group memberships",
    );
    Ok(())
}

#[tokio::test]
async fn test_user_groups_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v3/users/some-user/groups",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}
