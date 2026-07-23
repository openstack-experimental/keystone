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
//! v3 group CRUD authorization matrix (issue #992 vertical slice).
//!
//! Coverage matrix — every endpoint is exercised for the three mandated
//! cases (valid auth + allowed policy / valid auth + denied policy /
//! invalid auth):
//!
//! | endpoint          | 2xx admin                | 403 policy                                   | 401 invalid token |
//! |-------------------|--------------------------|----------------------------------------------|-------------------|
//! | POST   /v3/groups | `create_success_admin`   | `create_forbidden_for_project_scoped_manager`| `create_unauthorized` |
//! | GET    /v3/groups/{id} | `show_success_admin`| `show_forbidden_for_project_scoped_manager`  | `show_unauthorized`   |
//! | GET    /v3/groups | `list_success_admin`     | `list_forbidden_for_project_scoped_manager`  | `list_unauthorized`   |
//! | PATCH  /v3/groups/{id} | `update_success_admin`| `update_forbidden_for_project_scoped_manager`| `update_unauthorized` |
//! | DELETE /v3/groups/{id} | `delete_success_admin`| `delete_forbidden_for_project_scoped_manager`| `delete_unauthorized` |
//!
//! The 403 fixture is deliberate: the user *holds* the `manager` role
//! (which implies `member` and `reader` via the bootstrap implication
//! chain) but only on a **project** scope. `policy/identity/group/*.rego`
//! requires the role together with a genuine **domain** scope
//! (`domain_matches_domain_scope`), and `credentials.domain_id` is never
//! populated from a project-scoped token (see `Credentials` in
//! `crates/core/src/policy.rs`). A 403 here therefore proves the
//! domain-scope gate itself, not mere role absence.
//!
//! The domain-scoped *success* path for `manager`/`reader` cannot be
//! provisioned through the public API today: there is no
//! `PUT /v3/domains/{domain_id}/users/{user_id}/roles/{role_id}` handler
//! (only project and system grants exist), so no real user can obtain a
//! domain-scoped token with those roles. Tracked as a coverage gap for
//! Phase 2 (#993).

use std::sync::Arc;

use eyre::Result;
use uuid::Uuid;

use openstack_keystone_api_types::v3::domain::DomainCreateBuilder;
use openstack_keystone_api_types::v3::group::*;
use openstack_sdk::AsyncOpenStack;

use test_api::asserts::{assert_forbidden, assert_status, assert_unauthorized};
use test_api::common::raw_request;
use test_api::fixtures::ProjectScopedUser;
use test_api::guard::{AsyncResourceGuard, ResourceGuard};
use test_api::identity::group::*;
use test_api::resource::domain::create_domain;
use test_api::resource::get_system_scope_config;

/// System-scoped admin session for fixture management — the same
/// convention as the v3 domain tests, which also create domains.
async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&get_system_scope_config()?).await?,
    ))
}

/// A fresh, uniquely named domain owned by `admin`.
async fn fresh_domain(
    admin: &Arc<AsyncOpenStack>,
) -> Result<AsyncResourceGuard<openstack_keystone_api_types::v3::domain::Domain>> {
    create_domain(
        admin,
        DomainCreateBuilder::default()
            .name(format!("grp-dom-{}", Uuid::new_v4().simple()))
            .enabled(true)
            .build()?,
    )
    .await
}

fn group_create(domain_id: &str) -> Result<GroupCreate> {
    Ok(GroupCreateBuilder::default()
        .name(format!("grp-{}", Uuid::new_v4().simple()))
        .domain_id(domain_id)
        .build()?)
}

// --- 2xx: valid auth + allowed policy (admin) --------------------------

#[tokio::test]
async fn test_group_create_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let domain = fresh_domain(&admin).await?;

    let group = create_group(&admin, group_create(&domain.id)?).await?;
    assert_eq!(group.domain_id, domain.id);
    assert!(!group.id.is_empty(), "created group must have an id");

    group.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_group_show_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let domain = fresh_domain(&admin).await?;
    let group = create_group(&admin, group_create(&domain.id)?).await?;

    let shown = get_group(&admin, &group.id).await?;
    assert_eq!(shown.id, group.id);
    assert_eq!(shown.name, group.name);
    assert_eq!(shown.domain_id, domain.id);

    group.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_group_list_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let domain = fresh_domain(&admin).await?;
    let group = create_group(&admin, group_create(&domain.id)?).await?;

    let by_domain = list_groups(
        &admin,
        GroupListRequest {
            domain_id: Some(domain.id.clone()),
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(by_domain.len(), 1, "fresh domain must contain one group");
    assert_eq!(by_domain[0].id, group.id);

    let by_name = list_groups(
        &admin,
        GroupListRequest {
            name: Some(group.name.clone()),
            ..Default::default()
        },
    )
    .await?;
    assert!(
        by_name.iter().any(|found| found.id == group.id),
        "name filter must find the created group"
    );

    group.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_group_update_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let domain = fresh_domain(&admin).await?;
    let group = create_group(&admin, group_create(&domain.id)?).await?;
    let new_name = format!("{}-updated", group.name);

    let updated = update_group(
        &admin,
        &group.id,
        GroupUpdateBuilder::default()
            .name(new_name.clone())
            .build()?,
    )
    .await?;
    assert_eq!(updated.id, group.id);
    assert_eq!(updated.name, new_name);

    let shown = get_group(&admin, &group.id).await?;
    assert_eq!(shown.name, new_name, "update must persist");

    group.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_group_delete_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let domain = fresh_domain(&admin).await?;
    let group = create_group(&admin, group_create(&domain.id)?).await?;
    let group_id = group.id.clone();

    group.delete().await?;
    assert_status(
        get_group(&admin, &group_id).await,
        http::StatusCode::NOT_FOUND,
        "deleted group must be gone",
    );

    domain.delete().await?;
    Ok(())
}

// --- 403: valid auth + denied policy (project-scoped manager) ----------

#[tokio::test]
async fn test_group_create_forbidden_for_project_scoped_manager() -> Result<()> {
    let admin = admin_session().await?;
    let domain = fresh_domain(&admin).await?;
    let manager = ProjectScopedUser::provision(&admin, &domain.id, "manager").await?;

    assert_forbidden(
        create_group(&manager.session, group_create(&domain.id)?).await,
        "manager role without domain scope must not create groups",
    );

    manager.cleanup().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_group_show_forbidden_for_project_scoped_manager() -> Result<()> {
    let admin = admin_session().await?;
    let domain = fresh_domain(&admin).await?;
    let group = create_group(&admin, group_create(&domain.id)?).await?;
    let manager = ProjectScopedUser::provision(&admin, &domain.id, "manager").await?;

    assert_forbidden(
        get_group(&manager.session, &group.id).await,
        "reader role without domain scope must not show groups",
    );

    manager.cleanup().await?;
    group.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_group_list_forbidden_for_project_scoped_manager() -> Result<()> {
    let admin = admin_session().await?;
    let domain = fresh_domain(&admin).await?;
    let manager = ProjectScopedUser::provision(&admin, &domain.id, "manager").await?;

    assert_forbidden(
        list_groups(&manager.session, GroupListRequest::default()).await,
        "reader role without domain scope must not list groups",
    );

    manager.cleanup().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_group_update_forbidden_for_project_scoped_manager() -> Result<()> {
    let admin = admin_session().await?;
    let domain = fresh_domain(&admin).await?;
    let group = create_group(&admin, group_create(&domain.id)?).await?;
    let manager = ProjectScopedUser::provision(&admin, &domain.id, "manager").await?;

    assert_forbidden(
        update_group(
            &manager.session,
            &group.id,
            GroupUpdateBuilder::default().name("renamed").build()?,
        )
        .await,
        "manager role without domain scope must not update groups",
    );

    manager.cleanup().await?;
    group.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_group_delete_forbidden_for_project_scoped_manager() -> Result<()> {
    let admin = admin_session().await?;
    let domain = fresh_domain(&admin).await?;
    let group = create_group(&admin, group_create(&domain.id)?).await?;
    let manager = ProjectScopedUser::provision(&admin, &domain.id, "manager").await?;

    assert_forbidden(
        delete_group(&manager.session, &group.id).await,
        "manager role without domain scope must not delete groups",
    );

    manager.cleanup().await?;
    // The group must have survived the forbidden delete; admin cleans up.
    group.delete().await?;
    domain.delete().await?;
    Ok(())
}

// --- 401: invalid authentication ----------------------------------------

#[tokio::test]
async fn test_group_create_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::POST,
        "v3/groups",
        Some("invalid-token"),
        Some(serde_json::json!({"group": {"name": "x", "domain_id": "default"}})),
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

#[tokio::test]
async fn test_group_show_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v3/groups/some-group-id",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

#[tokio::test]
async fn test_group_list_unauthorized() -> Result<()> {
    let rsp = raw_request(http::Method::GET, "v3/groups", Some("invalid-token"), None).await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

#[tokio::test]
async fn test_group_update_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::PATCH,
        "v3/groups/some-group-id",
        Some("invalid-token"),
        Some(serde_json::json!({"group": {"name": "x"}})),
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

#[tokio::test]
async fn test_group_delete_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::DELETE,
        "v3/groups/some-group-id",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}
