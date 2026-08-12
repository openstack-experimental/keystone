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
//! User CRUD authorization matrix for issue #994.

use eyre::{OptionExt, Result};
use uuid::Uuid;

use openstack_keystone_api_types::v3::user::{
    UserCreate, UserCreateBuilder, UserResponse, UserUpdateBuilder,
};

use test_api::asserts::{
    RawUnauthorizedRequest, assert_forbidden, assert_raw_request_unauthorized_with_cleanup,
    assert_raw_requests_unauthorized, assert_status, assert_unauthorized,
};
use test_api::common::get_system_scope_session;
use test_api::fixtures::{ProjectScopedUser, revoked_admin_client, warn_on_cleanup_failure};
use test_api::guard::ResourceGuard;
use test_api::identity::user::{
    UserListRequest, create_user, delete_user, get_user, list_users, update_user,
};

fn user_create() -> Result<UserCreate> {
    Ok(UserCreateBuilder::default()
        .name(format!("user-authz-{}", Uuid::new_v4().simple()))
        .domain_id("default")
        .enabled(true)
        .build()?)
}

fn user_non_create_unauthorized_requests() -> [RawUnauthorizedRequest<'static>; 4] {
    [
        RawUnauthorizedRequest {
            method: http::Method::GET,
            path: "v3/users/missing-user",
            body: None,
            message: "unauthenticated requests must not show users",
        },
        RawUnauthorizedRequest {
            method: http::Method::GET,
            path: "v3/users",
            body: None,
            message: "unauthenticated requests must not list users",
        },
        RawUnauthorizedRequest {
            method: http::Method::PATCH,
            path: "v3/users/missing-user",
            body: Some(serde_json::json!({"user": {"enabled": false}})),
            message: "unauthenticated requests must not update users",
        },
        RawUnauthorizedRequest {
            method: http::Method::DELETE,
            path: "v3/users/missing-user",
            body: None,
            message: "unauthenticated requests must not delete users",
        },
    ]
}

async fn assert_user_requests_unauthorized(token: Option<&str>) -> Result<()> {
    assert_user_create_unauthorized(token).await?;
    assert_raw_requests_unauthorized(user_non_create_unauthorized_requests(), token).await
}

async fn assert_user_create_unauthorized(token: Option<&str>) -> Result<()> {
    let admin = get_system_scope_session().await?;
    let admin_for_cleanup = admin.clone();
    assert_raw_request_unauthorized_with_cleanup(
        RawUnauthorizedRequest {
            method: http::Method::POST,
            path: "v3/users",
            body: Some(serde_json::json!({
                "user": {
                    "name": format!("user-authz-{}", Uuid::new_v4().simple()),
                    "domain_id": "default",
                    "enabled": true
                }
            })),
            message: "unauthenticated requests must not create users",
        },
        token,
        move |response| async move {
            let created: UserResponse = response.json().await?;
            delete_user(&admin_for_cleanup, &created.user.id).await
        },
    )
    .await
}

async fn assert_user_non_create_unauthorized(index: usize, token: Option<&str>) -> Result<()> {
    let request = user_non_create_unauthorized_requests()
        .into_iter()
        .nth(index)
        .ok_or_eyre("user authorization request must exist")?;
    test_api::asserts::assert_raw_request_unauthorized(request, token).await
}

#[tokio::test]
async fn test_user_show_success_admin() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let user = create_user(&admin, user_create()?).await?;
    let shown = get_user(&admin, &user.id).await?;
    let matches = shown.id == user.id && shown.domain_id == user.domain_id;

    user.delete().await?;
    assert!(matches, "shown user must match the created user");
    Ok(())
}

#[tokio::test]
async fn test_user_list_success_admin() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let user = create_user(&admin, user_create()?).await?;
    let users = list_users(
        &admin,
        UserListRequest {
            domain_id: Some(user.domain_id.clone()),
            name: Some(user.name.clone()),
            unique_id: None,
        },
    )
    .await?;
    let contains_user = users.iter().any(|item| item.id == user.id);

    user.delete().await?;
    assert!(contains_user, "user list must contain the created user");
    Ok(())
}

#[tokio::test]
async fn test_user_delete_success_admin() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let user = create_user(&admin, user_create()?).await?;
    let user_id = user.id.clone();

    user.delete().await?;
    assert_status(
        get_user(&admin, user_id).await,
        http::StatusCode::NOT_FOUND,
        "deleted user must be gone",
    );
    Ok(())
}

#[tokio::test]
async fn test_user_create_forbidden_project_scoped_manager() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let manager = ProjectScopedUser::provision(&admin, "default", "manager").await?;
    let result = match create_user(&manager.session, user_create()?).await {
        Ok(user) => {
            delete_user(&admin, &user.id).await?;
            warn_on_cleanup_failure("unexpected user guard", user.delete().await);
            Ok(())
        }
        Err(error) => Err(error),
    };

    manager.cleanup().await?;
    assert_forbidden(
        result,
        "a project-scoped manager must not create users without domain scope",
    );
    Ok(())
}

#[tokio::test]
async fn test_user_show_forbidden_project_scoped_manager() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let manager = ProjectScopedUser::provision(&admin, "default", "manager").await?;
    let result = get_user(&manager.session, &manager.user.id)
        .await
        .map(|_| ());

    manager.cleanup().await?;
    assert_forbidden(
        result,
        "a project-scoped reader must not show users without domain scope",
    );
    Ok(())
}

#[tokio::test]
async fn test_user_list_forbidden_project_scoped_manager() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let manager = ProjectScopedUser::provision(&admin, "default", "manager").await?;
    let result = list_users(
        &manager.session,
        UserListRequest {
            domain_id: Some("default".to_string()),
            name: None,
            unique_id: None,
        },
    )
    .await
    .map(|_| ());

    manager.cleanup().await?;
    assert_forbidden(
        result,
        "a project-scoped reader must not list users without domain scope",
    );
    Ok(())
}

#[tokio::test]
async fn test_user_update_forbidden_project_scoped_manager() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let manager = ProjectScopedUser::provision(&admin, "default", "manager").await?;
    let result = update_user(
        &manager.session,
        &manager.user.id,
        UserUpdateBuilder::default()
            .name(format!("forbidden-{}", Uuid::new_v4().simple()))
            .build()?,
    )
    .await
    .map(|_| ());

    manager.cleanup().await?;
    assert_forbidden(
        result,
        "a project-scoped manager must not update users without domain scope",
    );
    Ok(())
}

#[tokio::test]
async fn test_user_delete_forbidden_project_scoped_manager() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let manager = ProjectScopedUser::provision(&admin, "default", "manager").await?;
    let result = delete_user(&manager.session, &manager.user.id).await;

    if result.is_ok() {
        warn_on_cleanup_failure(
            "user fixture deleted by unauthorized caller",
            manager.cleanup().await,
        );
    } else {
        manager.cleanup().await?;
    }
    assert_forbidden(
        result,
        "a project-scoped manager must not delete users without domain scope",
    );
    Ok(())
}

#[tokio::test]
async fn test_user_create_rejects_invalid_token() -> Result<()> {
    assert_user_create_unauthorized(Some("invalid-token")).await
}

#[tokio::test]
async fn test_user_show_rejects_invalid_token() -> Result<()> {
    assert_user_non_create_unauthorized(0, Some("invalid-token")).await
}

#[tokio::test]
async fn test_user_list_rejects_invalid_token() -> Result<()> {
    assert_user_non_create_unauthorized(1, Some("invalid-token")).await
}

#[tokio::test]
async fn test_user_update_rejects_invalid_token() -> Result<()> {
    assert_user_non_create_unauthorized(2, Some("invalid-token")).await
}

#[tokio::test]
async fn test_user_delete_rejects_invalid_token() -> Result<()> {
    assert_user_non_create_unauthorized(3, Some("invalid-token")).await
}

#[tokio::test]
async fn test_user_requests_reject_missing_token() -> Result<()> {
    assert_user_requests_unauthorized(None).await
}

#[tokio::test]
async fn test_user_create_rejects_revoked_token() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let caller = revoked_admin_client().await?;
    let response = caller
        .client
        .post(caller.base_url.join("v3/users")?)
        .json(&serde_json::json!({
            "user": {
                "name": format!("user-authz-revoked-{}", Uuid::new_v4().simple()),
                "domain_id": "default",
                "enabled": true
            }
        }))
        .send()
        .await?;
    let result: Result<()> = match response.error_for_status() {
        Ok(response) => {
            let created: UserResponse = response.json().await?;
            delete_user(&admin, &created.user.id).await?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    };
    assert_unauthorized(result, "a revoked token must not create a user");
    Ok(())
}
