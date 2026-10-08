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

//! `GET /v3/users/{user_id}/projects` authorization matrix.
//!
//! | case | test |
//! |------|------|
//! | admin lists projects of a user with a role assignment | `test_user_projects_success_admin` |
//! | project-scoped user reads another user (policy `identity/user/show`) | `test_user_projects_forbidden_project_scoped_user` |
//! | project-scoped user lists their own projects | `test_user_projects_success_owner` |
//! | unknown user | `test_user_projects_not_found` |
//! | invalid token | `test_user_projects_unauthorized` |

use std::sync::Arc;

use eyre::Result;

use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::asserts::{assert_forbidden, assert_unauthorized};
use test_api::common::raw_request;
use test_api::fixtures::{
    ProjectScopedUser, cleanup_project_scoped_users, warn_on_cleanup_failure,
};
use test_api::identity::user::{UserProjectsRequest, list_user_projects};

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&CloudConfig::from_env()?).await?,
    ))
}

#[tokio::test]
async fn test_user_projects_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let fixture = ProjectScopedUser::provision(&admin, "default", "member").await?;

    let projects =
        list_user_projects(&admin, &fixture.user.id, UserProjectsRequest::default()).await;
    let cleanup = fixture.cleanup().await;
    let projects = projects?;
    cleanup?;

    assert_eq!(
        projects.len(),
        1,
        "the user is assigned a role on exactly one project: {projects:?}"
    );
    Ok(())
}

#[tokio::test]
async fn test_user_projects_forbidden_project_scoped_user() -> Result<()> {
    let admin = admin_session().await?;
    let a = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let b = match ProjectScopedUser::provision(&admin, "default", "member").await {
        Ok(b) => b,
        Err(error) => {
            warn_on_cleanup_failure("member fixture", a.cleanup().await);
            return Err(error);
        }
    };

    let list_result =
        list_user_projects(&a.session, &b.user.id, UserProjectsRequest::default()).await;
    let cleanup_result = cleanup_project_scoped_users([a, b]).await;

    cleanup_result?;
    assert_forbidden(
        list_result,
        "a project-scoped user must not list another user's projects",
    );
    Ok(())
}

#[tokio::test]
async fn test_user_projects_success_owner() -> Result<()> {
    let admin = admin_session().await?;
    let fixture = ProjectScopedUser::provision(&admin, "default", "member").await?;

    let projects = list_user_projects(
        &fixture.session,
        &fixture.user.id,
        UserProjectsRequest::default(),
    )
    .await;
    let cleanup = fixture.cleanup().await;
    let projects = projects?;
    cleanup?;

    assert_eq!(projects.len(), 1, "owner sees their project: {projects:?}");
    Ok(())
}

#[tokio::test]
async fn test_user_projects_not_found() -> Result<()> {
    let admin = admin_session().await?;
    let result =
        list_user_projects(&admin, "no-such-user-id", UserProjectsRequest::default()).await;
    assert!(result.is_err(), "unknown user must not be listable");
    Ok(())
}

#[tokio::test]
async fn test_user_projects_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v3/users/some-user/projects",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}
