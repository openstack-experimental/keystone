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
//! Role-assignment authorization matrix for issue #994.

use std::sync::Arc;

use eyre::Result;

use openstack_sdk::AsyncOpenStack;

use test_api::asserts::{
    RawUnauthorizedRequest, assert_forbidden, assert_raw_request_unauthorized, assert_status,
    assert_unauthorized,
};
use test_api::assignment::{
    RoleAssignmentListRequest, grant::add_project_grant, grant::add_system_grant,
    grant::check_project_grant, grant::check_system_grant, grant::list_project_roles,
    grant::list_system_roles, grant::revoke_project_grant, grant::revoke_system_grant,
    list_role_assignments,
};
use test_api::common::get_system_scope_session;
use test_api::fixtures::{
    ProjectScopedUser, SystemScopedUser, cleanup_project_scoped_users, provision_fixture_pair,
    revoked_admin_client,
};
use test_api::role::list_roles;

async fn role_id(admin: &Arc<AsyncOpenStack>, name: &str) -> Result<String> {
    list_roles(admin)
        .await?
        .into_iter()
        .find(|role| role.name == name)
        .map(|role| role.id)
        .ok_or_else(|| eyre::eyre!("bootstrap `{name}` role must exist"))
}

fn unauthorized_request(method: http::Method, path: &str) -> RawUnauthorizedRequest<'_> {
    RawUnauthorizedRequest {
        method,
        path,
        body: None,
        message: "an invalid token must not access role assignments",
    }
}

#[tokio::test]
async fn test_role_assignment_list_success_admin() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let target = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let request = RoleAssignmentListRequest {
        project_id: Some(target.project.id.clone()),
        user_id: Some(target.user.id.clone()),
        include_names: Some(true),
        ..Default::default()
    };
    let result = list_role_assignments(&admin, request)
        .await
        .map(|assignments| {
            assignments.iter().any(|assignment| {
                assignment
                    .user
                    .as_ref()
                    .is_some_and(|user| user.id == target.user.id)
            })
        });

    target.cleanup().await?;
    assert!(
        result?,
        "the administrator must see the target user's project assignment"
    );
    Ok(())
}

#[tokio::test]
async fn test_role_assignment_list_success_system_reader() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let target = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let (target, reader) = provision_fixture_pair(
        target,
        SystemScopedUser::provision(&admin, "default", "reader"),
        |target| target.cleanup(),
        "project-scoped assignment target",
    )
    .await?;
    let request = RoleAssignmentListRequest {
        project_id: Some(target.project.id.clone()),
        user_id: Some(target.user.id.clone()),
        ..Default::default()
    };
    let result = list_role_assignments(&reader.session, request)
        .await
        .map(|assignments| {
            assignments.iter().any(|assignment| {
                assignment
                    .user
                    .as_ref()
                    .is_some_and(|user| user.id == target.user.id)
            })
        });

    let target_cleanup = target.cleanup().await;
    let reader_cleanup = reader.cleanup().await;
    target_cleanup?;
    reader_cleanup?;
    assert!(
        result?,
        "a system-scoped reader must see matching role assignments"
    );
    Ok(())
}

#[tokio::test]
async fn test_role_assignment_list_forbidden_project_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = list_role_assignments(
        &member.session,
        RoleAssignmentListRequest {
            project_id: Some(member.project.id.clone()),
            user_id: Some(member.user.id.clone()),
            ..Default::default()
        },
    )
    .await
    .map(|_| ());

    member.cleanup().await?;
    assert_forbidden(
        result,
        "a project-scoped member must not list role assignments",
    );
    Ok(())
}

#[tokio::test]
async fn test_role_assignment_list_unauthorized() -> Result<()> {
    assert_raw_request_unauthorized(
        unauthorized_request(http::Method::GET, "v3/role_assignments"),
        Some("invalid-token"),
    )
    .await
}

#[tokio::test]
async fn test_project_user_role_admin_read_and_revoke() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let member_role_id = role_id(&admin, "member").await?;
    let target = ProjectScopedUser::provision(&admin, "default", "member").await?;

    let result: Result<(bool, Result<()>)> = async {
        check_project_grant(&admin, &target.project.id, &target.user.id, &member_role_id).await?;
        let listed = list_project_roles(&admin, &target.project.id, &target.user.id)
            .await?
            .iter()
            .any(|role| role.id == member_role_id);
        revoke_project_grant(&admin, &target.project.id, &target.user.id, &member_role_id).await?;
        let revoked =
            check_project_grant(&admin, &target.project.id, &target.user.id, &member_role_id).await;
        Ok((listed, revoked))
    }
    .await;

    target.cleanup().await?;
    let (listed, revoked) = result?;
    assert!(listed, "the direct project grant must be listed");
    assert_status(
        revoked,
        http::StatusCode::NOT_FOUND,
        "checking the revoked project grant must return 404",
    );
    Ok(())
}

#[tokio::test]
async fn test_project_user_role_operations_forbidden_project_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let member_role_id = role_id(&admin, "member").await?;
    let target = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let (target, caller) = provision_fixture_pair(
        target,
        ProjectScopedUser::provision(&admin, "default", "member"),
        |target| target.cleanup(),
        "project role-assignment target",
    )
    .await?;

    let grant = add_project_grant(
        &caller.session,
        &target.project.id,
        &target.user.id,
        &member_role_id,
    )
    .await;
    let check = check_project_grant(
        &caller.session,
        &target.project.id,
        &target.user.id,
        &member_role_id,
    )
    .await;
    let list = list_project_roles(&caller.session, &target.project.id, &target.user.id)
        .await
        .map(|_| ());
    let revoke = revoke_project_grant(
        &caller.session,
        &target.project.id,
        &target.user.id,
        &member_role_id,
    )
    .await;

    cleanup_project_scoped_users([target, caller]).await?;
    assert_forbidden(
        grant,
        "a project-scoped member must not grant project roles",
    );
    assert_forbidden(
        check,
        "a project-scoped member must not check project roles",
    );
    assert_forbidden(list, "a project-scoped member must not list project roles");
    assert_forbidden(
        revoke,
        "a project-scoped member must not revoke project roles",
    );
    Ok(())
}

#[tokio::test]
async fn test_project_user_role_operations_unauthorized() -> Result<()> {
    let path = "v3/projects/missing-project/users/missing-user/roles/missing-role";
    assert_raw_request_unauthorized(
        unauthorized_request(http::Method::PUT, path),
        Some("invalid-token"),
    )
    .await?;
    assert_raw_request_unauthorized(
        unauthorized_request(http::Method::HEAD, path),
        Some("invalid-token"),
    )
    .await?;
    assert_raw_request_unauthorized(
        unauthorized_request(
            http::Method::GET,
            "v3/projects/missing-project/users/missing-user/roles",
        ),
        Some("invalid-token"),
    )
    .await?;
    assert_raw_request_unauthorized(
        unauthorized_request(http::Method::DELETE, path),
        Some("invalid-token"),
    )
    .await?;
    assert_raw_request_unauthorized(
        RawUnauthorizedRequest {
            message: "a missing token must not grant project roles",
            ..unauthorized_request(http::Method::PUT, path)
        },
        None,
    )
    .await
}

#[tokio::test]
async fn test_system_user_role_admin_read_and_revoke() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let member_role_id = role_id(&admin, "member").await?;
    let target = SystemScopedUser::provision(&admin, "default", "member").await?;

    let result: Result<(bool, Result<()>)> = async {
        check_system_grant(&admin, &target.user.id, &member_role_id).await?;
        let listed = list_system_roles(&admin, &target.user.id)
            .await?
            .iter()
            .any(|role| role.id == member_role_id);
        revoke_system_grant(&admin, &target.user.id, &member_role_id).await?;
        let revoked = check_system_grant(&admin, &target.user.id, &member_role_id).await;
        Ok((listed, revoked))
    }
    .await;

    target.cleanup().await?;
    let (listed, revoked) = result?;
    assert!(listed, "the direct system grant must be listed");
    assert_status(
        revoked,
        http::StatusCode::NOT_FOUND,
        "checking the revoked system grant must return 404",
    );
    Ok(())
}

#[tokio::test]
async fn test_system_reader_can_read_but_not_mutate_system_grants() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let member_role_id = role_id(&admin, "member").await?;
    let target = SystemScopedUser::provision(&admin, "default", "member").await?;
    let (target, reader) = provision_fixture_pair(
        target,
        SystemScopedUser::provision(&admin, "default", "reader"),
        |target| target.cleanup(),
        "system role-assignment target",
    )
    .await?;

    let check = check_system_grant(&reader.session, &target.user.id, &member_role_id).await;
    let list = list_system_roles(&reader.session, &target.user.id)
        .await
        .map(|roles| roles.iter().any(|role| role.id == member_role_id));
    let grant = add_system_grant(&reader.session, &target.user.id, &member_role_id).await;
    let revoke = revoke_system_grant(&reader.session, &target.user.id, &member_role_id).await;

    let target_cleanup = target.cleanup().await;
    let reader_cleanup = reader.cleanup().await;
    target_cleanup?;
    reader_cleanup?;

    check?;
    assert!(list?, "a system reader must see a direct system grant");
    assert_forbidden(grant, "a system reader must not grant system roles");
    assert_forbidden(revoke, "a system reader must not revoke system roles");
    Ok(())
}

#[tokio::test]
async fn test_system_user_role_operations_forbidden_project_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let member_role_id = role_id(&admin, "member").await?;
    let target = SystemScopedUser::provision(&admin, "default", "member").await?;
    let (target, caller) = provision_fixture_pair(
        target,
        ProjectScopedUser::provision(&admin, "default", "member"),
        |target| target.cleanup(),
        "system role-assignment target",
    )
    .await?;

    let grant = add_system_grant(&caller.session, &target.user.id, &member_role_id).await;
    let check = check_system_grant(&caller.session, &target.user.id, &member_role_id).await;
    let list = list_system_roles(&caller.session, &target.user.id)
        .await
        .map(|_| ());
    let revoke = revoke_system_grant(&caller.session, &target.user.id, &member_role_id).await;

    let target_cleanup = target.cleanup().await;
    let caller_cleanup = caller.cleanup().await;
    target_cleanup?;
    caller_cleanup?;

    assert_forbidden(grant, "a project-scoped member must not grant system roles");
    assert_forbidden(check, "a project-scoped member must not check system roles");
    assert_forbidden(list, "a project-scoped member must not list system roles");
    assert_forbidden(
        revoke,
        "a project-scoped member must not revoke system roles",
    );
    Ok(())
}

#[tokio::test]
async fn test_system_user_role_operations_unauthorized() -> Result<()> {
    let path = "v3/system/users/missing-user/roles/missing-role";
    assert_raw_request_unauthorized(
        unauthorized_request(http::Method::PUT, path),
        Some("invalid-token"),
    )
    .await?;
    assert_raw_request_unauthorized(
        unauthorized_request(http::Method::HEAD, path),
        Some("invalid-token"),
    )
    .await?;
    assert_raw_request_unauthorized(
        unauthorized_request(http::Method::GET, "v3/system/users/missing-user/roles"),
        Some("invalid-token"),
    )
    .await?;
    assert_raw_request_unauthorized(
        unauthorized_request(http::Method::DELETE, path),
        Some("invalid-token"),
    )
    .await
}

#[tokio::test]
async fn test_project_role_grant_rejects_revoked_token() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let member_role_id = role_id(&admin, "member").await?;
    let caller = revoked_admin_client().await?;
    let target = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let path = format!(
        "v3/projects/{}/users/{}/roles/{member_role_id}",
        target.project.id, target.user.id
    );
    let result: Result<()> = async {
        let response = caller
            .client
            .put(caller.base_url.join(&path)?)
            .send()
            .await?;
        match response.error_for_status() {
            Ok(_) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    .await;

    target.cleanup().await?;
    assert_unauthorized(result, "a revoked token must not grant a project role");
    Ok(())
}
