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
//! Role CRUD authorization matrix for issue #994.

use eyre::Result;
use uuid::Uuid;

use openstack_keystone_api_types::v3::role::{
    RoleCreate, RoleCreateBuilder, RoleResponse, RoleUpdateBuilder,
};

use test_api::asserts::{
    RawUnauthorizedRequest, assert_forbidden, assert_raw_request_unauthorized_with_cleanup,
    assert_raw_requests_unauthorized, assert_unauthorized,
};
use test_api::common::get_system_scope_session;
use test_api::fixtures::{ProjectScopedUser, revoked_admin_client};
use test_api::role::{create_role, delete_role, get_role, list_roles, update_role};

fn role_create() -> Result<RoleCreate> {
    Ok(RoleCreateBuilder::default()
        .name(format!("role-authz-{}", Uuid::new_v4().simple()))
        .build()?)
}

fn role_non_create_unauthorized_requests() -> [RawUnauthorizedRequest<'static>; 4] {
    [
        RawUnauthorizedRequest {
            method: http::Method::GET,
            path: "v3/roles/missing-role",
            body: None,
            message: "unauthenticated requests must not show roles",
        },
        RawUnauthorizedRequest {
            method: http::Method::GET,
            path: "v3/roles",
            body: None,
            message: "unauthenticated requests must not list roles",
        },
        RawUnauthorizedRequest {
            method: http::Method::PATCH,
            path: "v3/roles/missing-role",
            body: Some(serde_json::json!({"role": {"name": "renamed"}})),
            message: "unauthenticated requests must not update roles",
        },
        RawUnauthorizedRequest {
            method: http::Method::DELETE,
            path: "v3/roles/missing-role",
            body: None,
            message: "unauthenticated requests must not delete roles",
        },
    ]
}

async fn assert_role_requests_unauthorized(token: Option<&str>) -> Result<()> {
    let admin = get_system_scope_session().await?;
    let admin_for_cleanup = admin.clone();
    assert_raw_request_unauthorized_with_cleanup(
        RawUnauthorizedRequest {
            method: http::Method::POST,
            path: "v3/roles",
            body: Some(serde_json::json!({
                "role": {
                    "name": format!("role-authz-{}", Uuid::new_v4().simple())
                }
            })),
            message: "unauthenticated requests must not create roles",
        },
        token,
        move |response| async move {
            let created: RoleResponse = response.json().await?;
            delete_role(&admin_for_cleanup, &created.role.id).await
        },
    )
    .await?;
    assert_raw_requests_unauthorized(role_non_create_unauthorized_requests(), token).await
}

#[tokio::test]
async fn test_role_show_success_admin() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let role = create_role(&admin, role_create()?).await?;
    let shown = get_role(&admin, &role.id).await?;
    let matches = shown.id == role.id && shown.name == role.name;

    delete_role(&admin, &role.id).await?;
    assert!(matches, "shown role must match the created role");
    Ok(())
}

#[tokio::test]
async fn test_role_create_forbidden_project_scoped_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = match create_role(&member.session, role_create()?).await {
        Ok(role) => {
            delete_role(&admin, &role.id).await?;
            Ok(())
        }
        Err(error) => Err(error),
    };

    member.cleanup().await?;
    assert_forbidden(result, "a project-scoped member must not create roles");
    Ok(())
}

#[tokio::test]
async fn test_role_show_forbidden_project_scoped_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let role = create_role(&admin, role_create()?).await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = get_role(&member.session, &role.id)
        .await
        .map(|shown| shown.id);

    member.cleanup().await?;
    delete_role(&admin, &role.id).await?;
    assert_forbidden(result, "a project-scoped member must not show roles");
    Ok(())
}

#[tokio::test]
async fn test_role_list_forbidden_project_scoped_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = list_roles(&member.session).await.map(|_| ());

    member.cleanup().await?;
    assert_forbidden(result, "a project-scoped member must not list roles");
    Ok(())
}

#[tokio::test]
async fn test_role_update_forbidden_project_scoped_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let role = create_role(&admin, role_create()?).await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = update_role(
        &member.session,
        &role.id,
        RoleUpdateBuilder::default()
            .name(format!("forbidden-{}", Uuid::new_v4().simple()))
            .build()?,
    )
    .await
    .map(|updated| updated.id);

    member.cleanup().await?;
    delete_role(&admin, &role.id).await?;
    assert_forbidden(result, "a project-scoped member must not update roles");
    Ok(())
}

#[tokio::test]
async fn test_role_delete_forbidden_project_scoped_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let role = create_role(&admin, role_create()?).await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = delete_role(&member.session, &role.id).await;

    member.cleanup().await?;
    if result.is_err() {
        delete_role(&admin, &role.id).await?;
    }
    assert_forbidden(result, "a project-scoped member must not delete roles");
    Ok(())
}

#[tokio::test]
async fn test_role_requests_reject_invalid_token() -> Result<()> {
    assert_role_requests_unauthorized(Some("invalid-token")).await
}

#[tokio::test]
async fn test_role_requests_reject_missing_token() -> Result<()> {
    assert_role_requests_unauthorized(None).await
}

#[tokio::test]
async fn test_role_create_rejects_revoked_token() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let caller = revoked_admin_client().await?;
    let response = caller
        .client
        .post(caller.base_url.join("v3/roles")?)
        .json(&serde_json::json!({
            "role": {
                "name": format!("role-authz-revoked-{}", Uuid::new_v4().simple())
            }
        }))
        .send()
        .await?;
    let result: Result<()> = match response.error_for_status() {
        Ok(response) => {
            let created: RoleResponse = response.json().await?;
            delete_role(&admin, &created.role.id).await?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    };
    assert_unauthorized(result, "a revoked token must not create a role");
    Ok(())
}
