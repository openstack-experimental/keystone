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
//! v4 user CRUD authorization matrix (issue #993).
//!
//! `/v4/users` is served by its own handlers
//! (`crates/keystone/src/api/v4/user/`) — unlike v4 roles, role assignments
//! and auth tokens, which re-mount the v3 router. Only the request/response
//! types are shared with v3, so the full matrix is exercised here rather
//! than deferred to the v3 suite.
//!
//! | endpoint                     | 2xx                        | 403                              | 401                     |
//! |------------------------------|----------------------------|----------------------------------|-------------------------|
//! | POST   /v4/users             | `create_success_admin`     | `create_forbidden_project_scoped`| `create_unauthorized`   |
//! | GET    /v4/users/{id}        | `show_success_admin`       | `show_forbidden_project_scoped`  | `show_unauthorized`     |
//! | GET    /v4/users             | `list_success_admin`, `list_success_system_reader` | `list_forbidden_project_scoped` | `list_unauthorized` |
//! | PUT    /v4/users/{id}        | `update_success_admin`     | `update_forbidden_project_scoped`| `update_unauthorized`   |
//! | DELETE /v4/users/{id}        | `delete_success_admin`     | `delete_forbidden_project_scoped`| `delete_unauthorized`   |
//! | GET    /v4/users/{id}/groups | `groups_success_admin`     | `groups_forbidden_project_scoped`| `groups_unauthorized`   |
//! | GET    /v4/users/{id}/projects | `projects_success_admin` | `projects_forbidden_project_scoped`| `projects_unauthorized` |
//!
//! `policy/identity/user/*.rego` allows `admin`, or `manager`/`reader`
//! together with a genuine **domain** scope
//! (`identity.domain_matches_domain_scope`). `credentials.domain_id` is never
//! populated from a project-scoped token (`Credentials` in
//! `crates/core/src/policy.rs`), so the 403 fixture is a real project-scoped
//! `manager` — it *holds* the role (and `member`/`reader` by the bootstrap
//! implication chain) and is still denied, which proves the domain-scope gate
//! rather than mere role absence.
//!
//! The domain-scoped `manager`/`reader` **success** path is still not
//! provisionable: there is no
//! `PUT /v3/domains/{domain_id}/users/{user_id}/roles/{role_id}` handler, so
//! no real user can obtain a domain-scoped token carrying those roles. See
//! the note in `tests/api/tests/api_v3/identity/group.rs`. `list` is the one
//! operation with a reachable non-admin allow rule — `reader` plus
//! `system == "all"` — so it gets a genuine underprivileged 2xx case.

use std::sync::Arc;

use eyre::Result;
use reqwest::StatusCode;
use uuid::Uuid;

// `v4::user` re-exports only a subset of the v3 user types — the `UserUpdate`
// patch and the `builder`-feature builders are not among them, so those come
// from `v3` directly. They are the same types either way.
use openstack_keystone_api_types::v3::user::{UserCreateBuilder, UserUpdateBuilder};
use openstack_keystone_api_types::v4::user::UserCreate;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::asserts::{assert_forbidden, assert_unauthorized};
use test_api::common::raw_request;
use test_api::fixtures::{ProjectScopedUser, SystemScopedUser};
use test_api::guard::ResourceGuard;
use test_api::identity::user_v4::*;

const DOMAIN: &str = "default";

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&CloudConfig::from_env()?).await?,
    ))
}

fn user_create() -> Result<UserCreate> {
    Ok(UserCreateBuilder::default()
        .name(format!("v4usr-{}", Uuid::new_v4().simple()))
        .domain_id(DOMAIN)
        .enabled(true)
        .build()?)
}

/// A project-scoped `manager`: holds the role but never a domain scope, so
/// every `policy/identity/user/*` rule that pairs a role with
/// `domain_matches_domain_scope` denies it.
async fn project_scoped_manager(admin: &Arc<AsyncOpenStack>) -> Result<ProjectScopedUser> {
    ProjectScopedUser::provision(admin, DOMAIN, "manager").await
}

// --- create -------------------------------------------------------------

#[tokio::test]
async fn test_v4_user_create_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let payload = user_create()?;
    let name = payload.name.clone();

    let user = create_user_v4(&admin, payload).await?;
    assert_eq!(user.name, name);
    assert_eq!(user.domain_id, DOMAIN);
    assert!(user.enabled);
    assert!(!user.id.is_empty(), "created user must have an id");

    user.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_user_create_forbidden_project_scoped() -> Result<()> {
    let admin = admin_session().await?;
    let manager = project_scoped_manager(&admin).await?;

    assert_forbidden(
        create_user_v4(&manager.session, user_create()?).await,
        "a project-scoped manager must not create users through /v4",
    );

    manager.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_user_create_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::POST,
        "v4/users",
        Some("invalid-token"),
        Some(serde_json::json!({"user": {"name": "nope", "domain_id": DOMAIN}})),
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- show ---------------------------------------------------------------

#[tokio::test]
async fn test_v4_user_show_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let user = create_user_v4(&admin, user_create()?).await?;

    let shown = get_user_v4(&admin, &user.id).await?;
    assert_eq!(shown.id, user.id);
    assert_eq!(shown.name, user.name);
    assert_eq!(shown.domain_id, DOMAIN);

    user.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_user_show_forbidden_project_scoped() -> Result<()> {
    let admin = admin_session().await?;
    let manager = project_scoped_manager(&admin).await?;
    let target = create_user_v4(&admin, user_create()?).await?;

    assert_forbidden(
        get_user_v4(&manager.session, &target.id).await,
        "a project-scoped manager must not read another user through /v4",
    );

    target.delete().await?;
    manager.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_user_show_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v4/users/some-user",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- list ---------------------------------------------------------------

#[tokio::test]
async fn test_v4_user_list_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let user = create_user_v4(&admin, user_create()?).await?;

    let by_name = list_users_v4(
        &admin,
        UserV4ListRequest {
            name: Some(user.name.clone()),
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(by_name.len(), 1, "name filter must match exactly one user");
    assert_eq!(by_name[0].id, user.id);

    let by_domain = list_users_v4(
        &admin,
        UserV4ListRequest {
            domain_id: Some(DOMAIN.to_string()),
            ..Default::default()
        },
    )
    .await?;
    assert!(
        by_domain.iter().any(|u| u.id == user.id),
        "domain listing must contain the created user"
    );

    user.delete().await?;
    Ok(())
}

/// The one non-admin allow rule reachable through the public API:
/// `policy/identity/user/list.rego` permits `reader` with `system == "all"`,
/// and system grants *are* provisionable (unlike domain grants).
#[tokio::test]
async fn test_v4_user_list_success_system_reader() -> Result<()> {
    let admin = admin_session().await?;
    let reader = SystemScopedUser::provision(&admin, DOMAIN, "reader").await?;
    let user = create_user_v4(&admin, user_create()?).await?;

    let listed = list_users_v4(
        &reader.session,
        UserV4ListRequest {
            name: Some(user.name.clone()),
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(listed.len(), 1, "system-scoped reader must see the user");
    assert_eq!(listed[0].id, user.id);

    user.delete().await?;
    reader.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_user_list_forbidden_project_scoped() -> Result<()> {
    let admin = admin_session().await?;
    let manager = project_scoped_manager(&admin).await?;

    assert_forbidden(
        list_users_v4(&manager.session, UserV4ListRequest::default()).await,
        "a project-scoped manager must not list users through /v4",
    );

    manager.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_user_list_unauthorized() -> Result<()> {
    let rsp = raw_request(http::Method::GET, "v4/users", Some("invalid-token"), None).await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- update -------------------------------------------------------------

#[tokio::test]
async fn test_v4_user_update_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let user = create_user_v4(&admin, user_create()?).await?;
    let renamed = format!("{}-renamed", user.name);

    let updated = update_user_v4(
        &admin,
        &user.id,
        UserUpdateBuilder::default()
            .name(renamed.clone())
            .enabled(false)
            .build()?,
    )
    .await?;
    assert_eq!(updated.id, user.id);
    assert_eq!(updated.name, renamed);
    assert!(!updated.enabled, "update must disable the user");

    // The change is durable, not just echoed by the update response.
    let shown = get_user_v4(&admin, &user.id).await?;
    assert_eq!(shown.name, renamed);
    assert!(!shown.enabled);

    user.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_user_update_forbidden_project_scoped() -> Result<()> {
    let admin = admin_session().await?;
    let manager = project_scoped_manager(&admin).await?;
    let target = create_user_v4(&admin, user_create()?).await?;

    assert_forbidden(
        update_user_v4(
            &manager.session,
            &target.id,
            UserUpdateBuilder::default().enabled(false).build()?,
        )
        .await,
        "a project-scoped manager must not update another user through /v4",
    );

    target.delete().await?;
    manager.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_user_update_unauthorized() -> Result<()> {
    // PUT, not PATCH: v4 update handlers declare `put`.
    let rsp = raw_request(
        http::Method::PUT,
        "v4/users/some-user",
        Some("invalid-token"),
        Some(serde_json::json!({"user": {"enabled": false}})),
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- delete -------------------------------------------------------------

#[tokio::test]
async fn test_v4_user_delete_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    // `into_inner`: this test's subject *is* the delete endpoint, so the
    // guard must not also delete (a second DELETE would 404).
    let user = create_user_v4(&admin, user_create()?).await?.into_inner();
    let id = user.id.clone();

    delete_user_v4(&admin, &id).await?;

    let rsp = raw_request(http::Method::GET, &format!("v4/users/{id}"), None, None).await?;
    assert_ne!(
        rsp.status(),
        StatusCode::OK,
        "a deleted user must not be readable"
    );
    Ok(())
}

#[tokio::test]
async fn test_v4_user_delete_forbidden_project_scoped() -> Result<()> {
    let admin = admin_session().await?;
    let manager = project_scoped_manager(&admin).await?;
    let target = create_user_v4(&admin, user_create()?).await?;

    assert_forbidden(
        delete_user_v4(&manager.session, &target.id).await,
        "a project-scoped manager must not delete another user through /v4",
    );

    // Still there — the denial was enforced before any mutation.
    assert_eq!(get_user_v4(&admin, &target.id).await?.id, target.id);

    target.delete().await?;
    manager.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_user_delete_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::DELETE,
        "v4/users/some-user",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- groups sub-resource ------------------------------------------------

#[tokio::test]
async fn test_v4_user_groups_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let user = create_user_v4(&admin, user_create()?).await?;

    let groups = list_user_groups_v4(&admin, &user.id, UserV4GroupsRequest::default()).await?;
    assert!(
        groups.is_empty(),
        "a freshly created user must have no group memberships, got: {groups:?}"
    );

    user.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_user_groups_forbidden_project_scoped() -> Result<()> {
    let admin = admin_session().await?;
    let manager = project_scoped_manager(&admin).await?;
    let target = create_user_v4(&admin, user_create()?).await?;

    assert_forbidden(
        list_user_groups_v4(&manager.session, &target.id, UserV4GroupsRequest::default()).await,
        "a project-scoped manager must not read another user's memberships",
    );

    target.delete().await?;
    manager.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_user_groups_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v4/users/some-user/groups",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- projects sub-resource ----------------------------------------------

#[tokio::test]
async fn test_v4_user_projects_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let fixture = ProjectScopedUser::provision(&admin, "default", "member").await?;

    let projects =
        list_user_projects_v4(&admin, &fixture.user.id, UserV4ProjectsRequest::default()).await;
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
async fn test_v4_user_projects_success_owner() -> Result<()> {
    let admin = admin_session().await?;
    let fixture = ProjectScopedUser::provision(&admin, "default", "member").await?;

    let projects = list_user_projects_v4(
        &fixture.session,
        &fixture.user.id,
        UserV4ProjectsRequest::default(),
    )
    .await;
    let cleanup = fixture.cleanup().await;
    let projects = projects?;
    cleanup?;

    assert_eq!(projects.len(), 1, "owner sees their project: {projects:?}");
    Ok(())
}

#[tokio::test]
async fn test_v4_user_projects_forbidden_project_scoped() -> Result<()> {
    let admin = admin_session().await?;
    let manager = project_scoped_manager(&admin).await?;
    let target = create_user_v4(&admin, user_create()?).await?;

    assert_forbidden(
        list_user_projects_v4(
            &manager.session,
            &target.id,
            UserV4ProjectsRequest::default(),
        )
        .await,
        "a project-scoped manager must not list another user's projects",
    );

    target.delete().await?;
    manager.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_user_projects_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v4/users/some-user/projects",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}
