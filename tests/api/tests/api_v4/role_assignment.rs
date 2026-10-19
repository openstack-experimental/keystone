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
//! v4 role assignment authorization matrix (issue #993).
//!
//! `crates/keystone/src/api/v4/role_assignment/mod.rs` re-mounts the v3
//! router, whose sub-routes carry absolute paths, so v4 publishes
//! `/v4/projects/…`, `/v4/system/…` and `/v4/role_assignments`. Those paths
//! only exist since the mount was changed from `.nest()` to `.merge()`; the
//! router shape itself is pinned by
//! `api::tests::v4_role_assignment_routes_are_merged_not_nested`.
//!
//! The v3 live suite (`tests/api_v3/assignment/grant/**`) is positive-only —
//! one success case per operation, no policy-denial or invalid-auth cases —
//! so the full matrix is built here.
//!
//! | endpoint                                        | 2xx                                                | 403                       | 401                        |
//! |-------------------------------------------------|----------------------------------------------------|---------------------------|----------------------------|
//! | PUT    /v4/projects/{p}/users/{u}/roles/{r}      | `grant_project_success_admin`                      | `grant_project_forbidden` | `grant_project_unauthorized` |
//! | HEAD   /v4/projects/{p}/users/{u}/roles/{r}      | `check_project_success_admin`, `..._system_reader` | `check_project_forbidden` | `check_project_unauthorized` |
//! | GET    /v4/projects/{p}/users/{u}/roles          | `list_project_success_admin`                       | `list_project_forbidden`  | `list_project_unauthorized`  |
//! | DELETE /v4/projects/{p}/users/{u}/roles/{r}      | `revoke_project_success_admin`                     | `revoke_project_forbidden`| `revoke_project_unauthorized`|
//! | PUT    /v4/system/users/{u}/roles/{r}            | `grant_system_success_admin`, `..._system_manager` | `grant_system_forbidden`  | `grant_system_unauthorized`  |
//! | HEAD   /v4/system/users/{u}/roles/{r}            | `check_system_success_admin`                       | `check_system_forbidden`  | `check_system_unauthorized`  |
//! | GET    /v4/system/users/{u}/roles                | `list_system_success_admin`                        | `list_system_forbidden`   | `list_system_unauthorized`   |
//! | DELETE /v4/system/users/{u}/roles/{r}            | `revoke_system_success_admin`                      | `revoke_system_forbidden` | `revoke_system_unauthorized` |
//! | GET    /v4/role_assignments                      | `list_assignments_success_admin`                   | `list_assignments_forbidden` | `list_assignments_unauthorized` |
//!
//! Two non-admin allow rules are reachable without a domain-scoped token and
//! get real 2xx coverage:
//!
//! - `policy/resource/system/user/role/grant.rego` allows `manager` with
//!   `system == "all"`, and system grants *are* provisionable.
//! - `policy/resource/project/user/role/check.rego` allows `reader` with
//!   `system == "all"`.
//!
//! The project-scope `manager` rules all route through
//! `assignment.project_role_domain_matches`, which needs
//! `credentials.domain_id` — never set for a project-scoped token — so those
//! remain unexercised for the same reason documented in
//! `tests/api_v3/identity/group.rs`.

use std::sync::Arc;

use eyre::{OptionExt, Result};

use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::asserts::{assert_forbidden, assert_unauthorized};
use test_api::assignment::v4::*;
use test_api::common::raw_request;
use test_api::fixtures::{ProjectScopedUser, SystemScopedUser};
use test_api::role::list_roles;

const DOMAIN: &str = "default";

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&CloudConfig::from_env()?).await?,
    ))
}

/// The id of a bootstrap role by name.
async fn role_id(admin: &Arc<AsyncOpenStack>, name: &str) -> Result<String> {
    Ok(list_roles(admin)
        .await?
        .into_iter()
        .find(|role| role.name == name)
        .ok_or_eyre(format!("bootstrap `{name}` role must exist"))?
        .id)
}

/// A `member` on a fresh project — holds `member`/`reader` but never
/// `manager`, and never a domain scope.
async fn member(admin: &Arc<AsyncOpenStack>) -> Result<ProjectScopedUser> {
    ProjectScopedUser::provision(admin, DOMAIN, "member").await
}

// --- project grant ------------------------------------------------------

#[tokio::test]
async fn test_v4_grant_project_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let target = member(&admin).await?;
    let reader = role_id(&admin, "reader").await?;

    grant_project_role_v4(&admin, &target.project.id, &target.user.id, &reader).await?;

    // The grant is observable through the check endpoint.
    check_project_role_v4(&admin, &target.project.id, &target.user.id, &reader).await?;

    target.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_grant_project_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let target = member(&admin).await?;
    let reader = role_id(&admin, "reader").await?;

    assert_forbidden(
        grant_project_role_v4(&actor.session, &target.project.id, &target.user.id, &reader).await,
        "a project-scoped member must not grant project roles",
    );

    actor.cleanup().await?;
    target.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_grant_project_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::PUT,
        "v4/projects/p1/users/u1/roles/r1",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- project check ------------------------------------------------------

#[tokio::test]
async fn test_v4_check_project_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let target = member(&admin).await?;
    let member_role = role_id(&admin, "member").await?;

    // The fixture already holds `member` on its own project.
    check_project_role_v4(&admin, &target.project.id, &target.user.id, &member_role).await?;

    target.cleanup().await?;
    Ok(())
}

/// `policy/resource/project/user/role/check.rego` allows `reader` with
/// `system == "all"` — reachable, since system grants are provisionable.
#[tokio::test]
async fn test_v4_check_project_success_system_reader() -> Result<()> {
    let admin = admin_session().await?;
    let reader = SystemScopedUser::provision(&admin, DOMAIN, "reader").await?;
    let target = member(&admin).await?;
    let member_role = role_id(&admin, "member").await?;

    check_project_role_v4(
        &reader.session,
        &target.project.id,
        &target.user.id,
        &member_role,
    )
    .await?;

    target.cleanup().await?;
    reader.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_check_project_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let target = member(&admin).await?;
    let member_role = role_id(&admin, "member").await?;

    assert_forbidden(
        check_project_role_v4(
            &actor.session,
            &target.project.id,
            &target.user.id,
            &member_role,
        )
        .await,
        "a project-scoped member must not check another user's project grants",
    );

    actor.cleanup().await?;
    target.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_check_project_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::HEAD,
        "v4/projects/p1/users/u1/roles/r1",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- project list -------------------------------------------------------

#[tokio::test]
async fn test_v4_list_project_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let target = member(&admin).await?;
    let member_role = role_id(&admin, "member").await?;

    // The listing carries role ids only (`name` comes back `None`), so the
    // assertion resolves the bootstrap role id rather than matching a name.
    let roles = list_project_roles_v4(&admin, &target.project.id, &target.user.id).await?;
    assert!(
        roles.iter().any(|role| role.id == member_role),
        "the fixture's `member` grant must be listed, got: {roles:?}"
    );

    target.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_list_project_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let target = member(&admin).await?;

    assert_forbidden(
        list_project_roles_v4(&actor.session, &target.project.id, &target.user.id).await,
        "a project-scoped member must not list another user's project grants",
    );

    actor.cleanup().await?;
    target.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_list_project_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v4/projects/p1/users/u1/roles",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- project revoke -----------------------------------------------------

#[tokio::test]
async fn test_v4_revoke_project_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let target = member(&admin).await?;
    let reader = role_id(&admin, "reader").await?;

    grant_project_role_v4(&admin, &target.project.id, &target.user.id, &reader).await?;
    revoke_project_role_v4(&admin, &target.project.id, &target.user.id, &reader).await?;

    // The explicit `reader` grant is gone; only the fixture's own `member`
    // grant remains.
    let roles = list_project_roles_v4(&admin, &target.project.id, &target.user.id).await?;
    assert!(
        !roles.iter().any(|role| role.id == reader),
        "the revoked `reader` grant must no longer be listed, got: {roles:?}"
    );

    target.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_revoke_project_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let target = member(&admin).await?;
    let member_role = role_id(&admin, "member").await?;

    assert_forbidden(
        revoke_project_role_v4(
            &actor.session,
            &target.project.id,
            &target.user.id,
            &member_role,
        )
        .await,
        "a project-scoped member must not revoke project grants",
    );

    // Still granted — the denial was enforced before any mutation.
    check_project_role_v4(&admin, &target.project.id, &target.user.id, &member_role).await?;

    actor.cleanup().await?;
    target.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_revoke_project_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::DELETE,
        "v4/projects/p1/users/u1/roles/r1",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- system grant -------------------------------------------------------

#[tokio::test]
async fn test_v4_grant_system_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let target = member(&admin).await?;
    let reader = role_id(&admin, "reader").await?;

    grant_system_role_v4(&admin, &target.user.id, &reader).await?;
    check_system_role_v4(&admin, &target.user.id, &reader).await?;

    revoke_system_role_v4(&admin, &target.user.id, &reader).await?;
    target.cleanup().await?;
    Ok(())
}

/// `policy/resource/system/user/role/grant.rego` allows `manager` with
/// `system == "all"` — the one grant rule reachable without `admin`.
#[tokio::test]
async fn test_v4_grant_system_success_system_manager() -> Result<()> {
    let admin = admin_session().await?;
    let actor = SystemScopedUser::provision(&admin, DOMAIN, "manager").await?;
    let target = member(&admin).await?;
    let reader = role_id(&admin, "reader").await?;

    grant_system_role_v4(&actor.session, &target.user.id, &reader).await?;
    check_system_role_v4(&admin, &target.user.id, &reader).await?;

    revoke_system_role_v4(&admin, &target.user.id, &reader).await?;
    target.cleanup().await?;
    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_grant_system_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let target = member(&admin).await?;
    let reader = role_id(&admin, "reader").await?;

    assert_forbidden(
        grant_system_role_v4(&actor.session, &target.user.id, &reader).await,
        "a project-scoped member must not grant system roles",
    );

    actor.cleanup().await?;
    target.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_grant_system_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::PUT,
        "v4/system/users/u1/roles/r1",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- system check / list / revoke ---------------------------------------

#[tokio::test]
async fn test_v4_check_system_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let actor = SystemScopedUser::provision(&admin, DOMAIN, "reader").await?;
    let reader = role_id(&admin, "reader").await?;

    // `SystemScopedUser` provisioning granted exactly this.
    check_system_role_v4(&admin, &actor.user.id, &reader).await?;

    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_check_system_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let target = SystemScopedUser::provision(&admin, DOMAIN, "reader").await?;
    let reader = role_id(&admin, "reader").await?;

    assert_forbidden(
        check_system_role_v4(&actor.session, &target.user.id, &reader).await,
        "a project-scoped member must not check system grants",
    );

    actor.cleanup().await?;
    target.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_check_system_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::HEAD,
        "v4/system/users/u1/roles/r1",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

#[tokio::test]
async fn test_v4_list_system_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let actor = SystemScopedUser::provision(&admin, DOMAIN, "reader").await?;
    let reader = role_id(&admin, "reader").await?;

    let roles = list_system_roles_v4(&admin, &actor.user.id).await?;
    assert!(
        roles.iter().any(|role| role.id == reader),
        "the fixture's system `reader` grant must be listed, got: {roles:?}"
    );

    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_list_system_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let target = SystemScopedUser::provision(&admin, DOMAIN, "reader").await?;

    assert_forbidden(
        list_system_roles_v4(&actor.session, &target.user.id).await,
        "a project-scoped member must not list system grants",
    );

    actor.cleanup().await?;
    target.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_list_system_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v4/system/users/u1/roles",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

#[tokio::test]
async fn test_v4_revoke_system_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let target = member(&admin).await?;
    let reader = role_id(&admin, "reader").await?;

    grant_system_role_v4(&admin, &target.user.id, &reader).await?;
    revoke_system_role_v4(&admin, &target.user.id, &reader).await?;

    let roles = list_system_roles_v4(&admin, &target.user.id).await?;
    assert!(
        !roles.iter().any(|role| role.id == reader),
        "the revoked system `reader` grant must no longer be listed, got: {roles:?}"
    );

    target.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_revoke_system_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;
    let target = SystemScopedUser::provision(&admin, DOMAIN, "reader").await?;
    let reader = role_id(&admin, "reader").await?;

    assert_forbidden(
        revoke_system_role_v4(&actor.session, &target.user.id, &reader).await,
        "a project-scoped member must not revoke system grants",
    );

    // Still granted — the denial was enforced before any mutation.
    check_system_role_v4(&admin, &target.user.id, &reader).await?;

    actor.cleanup().await?;
    target.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_revoke_system_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::DELETE,
        "v4/system/users/u1/roles/r1",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- GET /v4/role_assignments -------------------------------------------

#[tokio::test]
async fn test_v4_list_assignments_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let target = member(&admin).await?;

    let assignments = list_role_assignments_v4(&admin).await?;
    assert!(
        !assignments.is_empty(),
        "the bootstrap grants alone must make this listing non-empty"
    );

    target.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_list_assignments_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = member(&admin).await?;

    assert_forbidden(
        list_role_assignments_v4(&actor.session).await,
        "a project-scoped member must not list role assignments",
    );

    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_list_assignments_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v4/role_assignments",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}
