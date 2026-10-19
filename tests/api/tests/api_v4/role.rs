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
//! v4 role CRUD authorization matrix (issue #993).
//!
//! `crates/keystone/src/api/v4/role/mod.rs` re-mounts the v3 router, so
//! `/v4/roles` runs the v3 handlers. The v3 live suite
//! (`tests/api_v3/role/*.rs`) is positive-only — it has no policy-denial or
//! invalid-auth cases — so the full matrix is built here rather than
//! deferred to it.
//!
//! | endpoint              | 2xx                                              | 403                                | 401                   |
//! |-----------------------|--------------------------------------------------|------------------------------------|-----------------------|
//! | POST   /v4/roles      | `create_success_admin`                           | `create_forbidden_manager`         | `create_unauthorized` |
//! | GET    /v4/roles/{id} | `show_success_admin`, `show_success_manager_global` | `show_forbidden_member`          | `show_unauthorized`   |
//! | GET    /v4/roles      | `list_success_admin`                             | `list_forbidden_manager`           | `list_unauthorized`   |
//! | PATCH  /v4/roles/{id} | `update_success_admin`, `update_success_manager_global` | `update_forbidden_member`     | `update_unauthorized` |
//! | DELETE /v4/roles/{id} | `delete_success_admin`                           | `delete_forbidden_member`          | `delete_unauthorized` |
//!
//! `policy/role/*.rego` allows `admin` everywhere. `show`, `update` and
//! `delete` additionally allow `manager` together with
//! `identity.own_role_or_global_role`, and a role created without a
//! `domain_id` is *global* (`policy/identity.rego`'s `orphaned_role`) — so a
//! project-scoped `manager` genuinely passes those three, giving real
//! underprivileged 2xx coverage without a domain-scoped token. `create` has
//! no `manager` rule at all and `list` pairs it with
//! `domain_matches_domain_scope`, so both deny that same fixture.
//!
//! The 403 fixture for show/update/delete is therefore a project-scoped
//! `member`, which holds `member`/`reader` but not `manager` via the
//! bootstrap implication chain.
//!
//! `/v4/roles` keeps the v3 `PATCH` update verb; only the natively-v4
//! handlers use `PUT`.

use std::sync::Arc;

use eyre::Result;
use uuid::Uuid;

use openstack_keystone_api_types::v3::role::{
    Role, RoleCreate, RoleCreateBuilder, RoleUpdateBuilder,
};
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::asserts::{assert_forbidden, assert_unauthorized};
use test_api::common::raw_request;
use test_api::fixtures::ProjectScopedUser;
use test_api::role::v4::*;

const DOMAIN: &str = "default";

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&CloudConfig::from_env()?).await?,
    ))
}

/// A role payload with no `domain_id`, i.e. a *global* role — the shape
/// `identity.own_role_or_global_role` accepts for any `manager`.
fn global_role_create() -> Result<RoleCreate> {
    Ok(RoleCreateBuilder::default()
        .name(format!("v4role-{}", Uuid::new_v4().simple()))
        .build()?)
}

/// Create a global role as admin, returning it for the caller to clean up.
async fn admin_global_role(admin: &Arc<AsyncOpenStack>) -> Result<Role> {
    create_role_v4(admin, global_role_create()?)
        .await
        .map(|guard| guard.into_inner())
}

// --- create -------------------------------------------------------------

#[tokio::test]
async fn test_v4_role_create_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let payload = global_role_create()?;
    let name = payload.name.clone();

    let role = create_role_v4(&admin, payload).await?;
    assert_eq!(role.name, name);
    assert!(!role.id.is_empty(), "created role must have an id");

    delete_role_v4(&admin, &role.id).await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_role_create_forbidden_manager() -> Result<()> {
    let admin = admin_session().await?;
    let manager = ProjectScopedUser::provision(&admin, DOMAIN, "manager").await?;

    assert_forbidden(
        create_role_v4(&manager.session, global_role_create()?).await,
        "role creation is admin-only; `manager` must not create roles",
    );

    manager.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_role_create_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::POST,
        "v4/roles",
        Some("invalid-token"),
        Some(serde_json::json!({"role": {"name": "nope"}})),
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- show ---------------------------------------------------------------

#[tokio::test]
async fn test_v4_role_show_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let role = admin_global_role(&admin).await?;

    let shown = get_role_v4(&admin, &role.id).await?;
    assert_eq!(shown.id, role.id);
    assert_eq!(shown.name, role.name);

    delete_role_v4(&admin, &role.id).await?;
    Ok(())
}

/// `policy/role/show.rego` allows `manager` + `own_role_or_global_role`; a
/// role with no `domain_id` is global, so this passes without any domain
/// scope.
#[tokio::test]
async fn test_v4_role_show_success_manager_global() -> Result<()> {
    let admin = admin_session().await?;
    let manager = ProjectScopedUser::provision(&admin, DOMAIN, "manager").await?;
    let role = admin_global_role(&admin).await?;

    let shown = get_role_v4(&manager.session, &role.id).await?;
    assert_eq!(shown.id, role.id);

    delete_role_v4(&admin, &role.id).await?;
    manager.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_role_show_forbidden_member() -> Result<()> {
    let admin = admin_session().await?;
    let member = ProjectScopedUser::provision(&admin, DOMAIN, "member").await?;
    let role = admin_global_role(&admin).await?;

    assert_forbidden(
        get_role_v4(&member.session, &role.id).await,
        "`member` lacks `manager` and must not read a role",
    );

    delete_role_v4(&admin, &role.id).await?;
    member.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_role_show_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v4/roles/some-role",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- list ---------------------------------------------------------------

#[tokio::test]
async fn test_v4_role_list_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let role = admin_global_role(&admin).await?;

    let by_name = list_roles_v4(
        &admin,
        RoleV4ListRequest {
            name: Some(role.name.clone()),
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(by_name.len(), 1, "name filter must match exactly one role");
    assert_eq!(by_name[0].id, role.id);

    let all = list_roles_v4(&admin, RoleV4ListRequest::default()).await?;
    assert!(
        all.iter().any(|r| r.name == "admin"),
        "unfiltered listing must contain the bootstrap `admin` role"
    );

    delete_role_v4(&admin, &role.id).await?;
    Ok(())
}

/// Unlike show/update/delete, `policy/role/list.rego` pairs `manager` with
/// `domain_matches_domain_scope`, which a project-scoped token never
/// satisfies.
#[tokio::test]
async fn test_v4_role_list_forbidden_manager() -> Result<()> {
    let admin = admin_session().await?;
    let manager = ProjectScopedUser::provision(&admin, DOMAIN, "manager").await?;

    assert_forbidden(
        list_roles_v4(&manager.session, RoleV4ListRequest::default()).await,
        "listing roles requires `manager` with a genuine domain scope",
    );

    manager.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_role_list_unauthorized() -> Result<()> {
    let rsp = raw_request(http::Method::GET, "v4/roles", Some("invalid-token"), None).await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- update -------------------------------------------------------------

#[tokio::test]
async fn test_v4_role_update_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let role = admin_global_role(&admin).await?;
    let renamed = format!("{}-renamed", role.name);

    let updated = update_role_v4(
        &admin,
        &role.id,
        RoleUpdateBuilder::default().name(renamed.clone()).build()?,
    )
    .await?;
    assert_eq!(updated.id, role.id);
    assert_eq!(updated.name, renamed);

    // Durable, not just echoed back.
    assert_eq!(get_role_v4(&admin, &role.id).await?.name, renamed);

    delete_role_v4(&admin, &role.id).await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_role_update_success_manager_global() -> Result<()> {
    let admin = admin_session().await?;
    let manager = ProjectScopedUser::provision(&admin, DOMAIN, "manager").await?;
    let role = admin_global_role(&admin).await?;
    let renamed = format!("{}-mgr", role.name);

    let updated = update_role_v4(
        &manager.session,
        &role.id,
        RoleUpdateBuilder::default().name(renamed.clone()).build()?,
    )
    .await?;
    assert_eq!(updated.name, renamed);

    delete_role_v4(&admin, &role.id).await?;
    manager.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_role_update_forbidden_member() -> Result<()> {
    let admin = admin_session().await?;
    let member = ProjectScopedUser::provision(&admin, DOMAIN, "member").await?;
    let role = admin_global_role(&admin).await?;

    assert_forbidden(
        update_role_v4(
            &member.session,
            &role.id,
            RoleUpdateBuilder::default().name("nope").build()?,
        )
        .await,
        "`member` lacks `manager` and must not update a role",
    );

    delete_role_v4(&admin, &role.id).await?;
    member.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_role_update_unauthorized() -> Result<()> {
    // PATCH, not PUT: `/v4/roles` re-mounts the v3 handler.
    let rsp = raw_request(
        http::Method::PATCH,
        "v4/roles/some-role",
        Some("invalid-token"),
        Some(serde_json::json!({"role": {"name": "nope"}})),
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- delete -------------------------------------------------------------

#[tokio::test]
async fn test_v4_role_delete_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let role = admin_global_role(&admin).await?;

    delete_role_v4(&admin, &role.id).await?;

    let listed = list_roles_v4(
        &admin,
        RoleV4ListRequest {
            name: Some(role.name.clone()),
            ..Default::default()
        },
    )
    .await?;
    assert!(listed.is_empty(), "a deleted role must not be listed");
    Ok(())
}

#[tokio::test]
async fn test_v4_role_delete_forbidden_member() -> Result<()> {
    let admin = admin_session().await?;
    let member = ProjectScopedUser::provision(&admin, DOMAIN, "member").await?;
    let role = admin_global_role(&admin).await?;

    assert_forbidden(
        delete_role_v4(&member.session, &role.id).await,
        "`member` lacks `manager` and must not delete a role",
    );

    // Still there — the denial was enforced before any mutation.
    assert_eq!(get_role_v4(&admin, &role.id).await?.id, role.id);

    delete_role_v4(&admin, &role.id).await?;
    member.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_v4_role_delete_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::DELETE,
        "v4/roles/some-role",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}
