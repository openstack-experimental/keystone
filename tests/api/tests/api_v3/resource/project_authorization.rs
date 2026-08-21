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
//! Project authorization matrix for issue #994.

use eyre::{OptionExt, Result};
use uuid::Uuid;

use openstack_keystone_api_types::v3::project::{
    ProjectCreateBuilder, ProjectResponse, ProjectUpdateBuilder,
};

use test_api::asserts::{
    RawUnauthorizedRequest, assert_forbidden, assert_raw_request_unauthorized_with_cleanup,
    assert_raw_requests_unauthorized, assert_unauthorized,
};
use test_api::common::get_system_scope_session;
use test_api::fixtures::{ProjectScopedUser, revoked_admin_client, warn_on_cleanup_failure};
use test_api::guard::ResourceGuard;
use test_api::resource::project::{
    ProjectListRequest, create_project, delete_project, get_project, list_projects, update_project,
};

fn project_create() -> Result<openstack_keystone_api_types::v3::project::ProjectCreate> {
    Ok(ProjectCreateBuilder::default()
        .name(format!("project-authz-{}", Uuid::new_v4().simple()))
        .domain_id("default")
        .enabled(true)
        .build()?)
}

fn project_non_create_unauthorized_requests() -> [RawUnauthorizedRequest<'static>; 4] {
    [
        RawUnauthorizedRequest {
            method: http::Method::GET,
            path: "v3/projects/missing-project",
            body: None,
            message: "unauthenticated requests must not show projects",
        },
        RawUnauthorizedRequest {
            method: http::Method::GET,
            path: "v3/projects",
            body: None,
            message: "unauthenticated requests must not list projects",
        },
        RawUnauthorizedRequest {
            method: http::Method::PATCH,
            path: "v3/projects/missing-project",
            body: Some(serde_json::json!({"project": {"enabled": false}})),
            message: "unauthenticated requests must not update projects",
        },
        RawUnauthorizedRequest {
            method: http::Method::DELETE,
            path: "v3/projects/missing-project",
            body: None,
            message: "unauthenticated requests must not delete projects",
        },
    ]
}

async fn assert_project_requests_unauthorized(token: Option<&str>) -> Result<()> {
    assert_project_create_unauthorized(token).await?;
    assert_raw_requests_unauthorized(project_non_create_unauthorized_requests(), token).await
}

async fn assert_project_create_unauthorized(token: Option<&str>) -> Result<()> {
    let admin = get_system_scope_session().await?;
    let admin_for_cleanup = admin.clone();
    assert_raw_request_unauthorized_with_cleanup(
        RawUnauthorizedRequest {
            method: http::Method::POST,
            path: "v3/projects",
            body: Some(serde_json::json!({
                "project": {
                    "name": format!("project-authz-{}", Uuid::new_v4().simple()),
                    "domain_id": "default",
                    "enabled": true
                }
            })),
            message: "unauthenticated requests must not create projects",
        },
        token,
        move |response| async move {
            let created: ProjectResponse = response.json().await?;
            delete_project(&admin_for_cleanup, &created.project.id).await
        },
    )
    .await
}

async fn assert_project_non_create_unauthorized(index: usize, token: Option<&str>) -> Result<()> {
    let request = project_non_create_unauthorized_requests()
        .into_iter()
        .nth(index)
        .ok_or_eyre("project authorization request must exist")?;
    test_api::asserts::assert_raw_request_unauthorized(request, token).await
}

#[tokio::test]
async fn test_project_create_forbidden_project_scoped_manager() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let manager = ProjectScopedUser::provision(&admin, "default", "manager").await?;
    let result = match create_project(&manager.session, project_create()?).await {
        Ok(project) => {
            delete_project(&admin, &project.id).await?;
            warn_on_cleanup_failure("unexpected project guard", project.delete().await);
            Ok(())
        }
        Err(error) => Err(error),
    };

    manager.cleanup().await?;
    assert_forbidden(
        result,
        "a project-scoped manager must not create projects without domain scope",
    );
    Ok(())
}

#[tokio::test]
async fn test_project_show_forbidden_project_scoped_manager() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let manager = ProjectScopedUser::provision(&admin, "default", "manager").await?;
    let result = get_project(&manager.session, &manager.project.id)
        .await
        .map(|_| ());

    manager.cleanup().await?;
    assert_forbidden(
        result,
        "a project-scoped reader must not show projects without domain scope",
    );
    Ok(())
}

#[tokio::test]
async fn test_project_list_forbidden_project_scoped_manager() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let manager = ProjectScopedUser::provision(&admin, "default", "manager").await?;
    let result = list_projects(&manager.session, ProjectListRequest::default())
        .await
        .map(|_| ());

    manager.cleanup().await?;
    assert_forbidden(
        result,
        "a project-scoped reader must not list projects without domain scope",
    );
    Ok(())
}

#[tokio::test]
async fn test_project_update_forbidden_project_scoped_manager() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let manager = ProjectScopedUser::provision(&admin, "default", "manager").await?;
    let result = update_project(
        &manager.session,
        &manager.project.id,
        ProjectUpdateBuilder::default()
            .name(format!("forbidden-{}", Uuid::new_v4().simple()))
            .build()?,
    )
    .await
    .map(|_| ());

    manager.cleanup().await?;
    assert_forbidden(
        result,
        "a project-scoped manager must not update projects without domain scope",
    );
    Ok(())
}

#[tokio::test]
async fn test_project_delete_forbidden_project_scoped_manager() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let manager = ProjectScopedUser::provision(&admin, "default", "manager").await?;
    let result = delete_project(&manager.session, &manager.project.id).await;

    if result.is_ok() {
        warn_on_cleanup_failure(
            "project fixture deleted by unauthorized caller",
            manager.cleanup().await,
        );
    } else {
        manager.cleanup().await?;
    }
    assert_forbidden(
        result,
        "a project-scoped manager must not delete projects without domain scope",
    );
    Ok(())
}

#[tokio::test]
async fn test_project_create_rejects_invalid_token() -> Result<()> {
    assert_project_create_unauthorized(Some("invalid-token")).await
}

#[tokio::test]
async fn test_project_show_rejects_invalid_token() -> Result<()> {
    assert_project_non_create_unauthorized(0, Some("invalid-token")).await
}

#[tokio::test]
async fn test_project_list_rejects_invalid_token() -> Result<()> {
    assert_project_non_create_unauthorized(1, Some("invalid-token")).await
}

#[tokio::test]
async fn test_project_update_rejects_invalid_token() -> Result<()> {
    assert_project_non_create_unauthorized(2, Some("invalid-token")).await
}

#[tokio::test]
async fn test_project_delete_rejects_invalid_token() -> Result<()> {
    assert_project_non_create_unauthorized(3, Some("invalid-token")).await
}

#[tokio::test]
async fn test_project_requests_reject_missing_token() -> Result<()> {
    assert_project_requests_unauthorized(None).await
}

#[tokio::test]
async fn test_project_create_rejects_revoked_token() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let caller = revoked_admin_client().await?;
    let response = caller
        .client
        .post(caller.base_url.join("v3/projects")?)
        .json(&serde_json::json!({
            "project": {
                "name": format!("project-authz-revoked-{}", Uuid::new_v4().simple()),
                "domain_id": "default",
                "enabled": true
            }
        }))
        .send()
        .await?;
    let result: Result<()> = match response.error_for_status() {
        Ok(response) => {
            let created: ProjectResponse = response.json().await?;
            delete_project(&admin, &created.project.id).await?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    };
    assert_unauthorized(result, "a revoked token must not create a project");
    Ok(())
}
