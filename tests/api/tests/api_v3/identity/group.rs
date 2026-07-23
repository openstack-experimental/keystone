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

use std::env;
use std::sync::Arc;

use eyre::{OptionExt, Result, WrapErr};
use uuid::Uuid;

use openstack_keystone_api_types::scope::{DomainBuilder, Scope, ScopeProjectBuilder};
use openstack_keystone_api_types::v3::domain::DomainCreateBuilder;
use openstack_keystone_api_types::v3::group::*;
use openstack_keystone_api_types::v3::project::{Project, ProjectCreateBuilder};
use openstack_keystone_api_types::v3::user::{User, UserCreateBuilder};
use openstack_sdk::AsyncOpenStack;

use test_api::asserts::{assert_forbidden, assert_status};
use test_api::assignment::grant::add_project_grant;
use test_api::common::get_user_session;
use test_api::guard::{AsyncResourceGuard, ResourceGuard};
use test_api::identity::group::*;
use test_api::identity::user::create_user;
use test_api::resource::domain::create_domain;
use test_api::resource::get_system_scope_config;
use test_api::resource::project::create_project;
use test_api::role::list_roles;

const FIXTURE_PASSWORD: &str = "group-fixture-password";

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

/// A real user in `domain_id` holding the `manager` role (implies
/// `member`/`reader`) on a project in the same domain, authenticated with
/// a **project-scoped** token through the live password-auth path. All
/// fixture resources are created by — and cleaned up with — the admin
/// session, so cleanup never depends on the underprivileged session.
struct ProjectScopedManager {
    session: Arc<AsyncOpenStack>,
    user: AsyncResourceGuard<User>,
    project: AsyncResourceGuard<Project>,
}

impl ProjectScopedManager {
    async fn provision(admin: &Arc<AsyncOpenStack>, domain_id: &str) -> Result<Self> {
        let unique = Uuid::new_v4().simple().to_string();
        let project = create_project(
            admin,
            ProjectCreateBuilder::default()
                .name(format!("grp-proj-{unique}"))
                .domain_id(domain_id)
                .build()?,
        )
        .await?;
        let user = create_user(
            admin,
            UserCreateBuilder::default()
                .name(format!("grp-mgr-{unique}"))
                .domain_id(domain_id)
                .password(FIXTURE_PASSWORD)
                .enabled(true)
                .build()?,
        )
        .await?;
        let manager_role = list_roles(admin)
            .await?
            .into_iter()
            .find(|role| role.name == "manager")
            .ok_or_eyre("bootstrap `manager` role must exist")?;
        add_project_grant(admin, &project.id, &user.id, &manager_role.id).await?;

        let scope = Scope::Project(
            ScopeProjectBuilder::default()
                .id(project.id.clone())
                .domain(DomainBuilder::default().id(domain_id).build()?)
                .build()?,
        );
        let session =
            get_user_session(&user.name, FIXTURE_PASSWORD, domain_id, Some(&scope)).await?;
        Ok(Self {
            session,
            user,
            project,
        })
    }

    async fn cleanup(self) -> Result<()> {
        self.user.delete().await?;
        self.project.delete().await?;
        Ok(())
    }
}

/// Raw request with an invalid token; returns the response status.
async fn status_with_invalid_token(
    method: http::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<reqwest::StatusCode> {
    let base_url: url::Url = env::var("KEYSTONE_URL")
        .wrap_err("KEYSTONE_URL must be set")?
        .parse()?;
    let mut request = reqwest::Client::new()
        .request(method, base_url.join(path)?)
        .header("x-auth-token", "invalid-token");
    if let Some(body) = body {
        request = request.json(&body);
    }
    Ok(request.send().await?.status())
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
    let manager = ProjectScopedManager::provision(&admin, &domain.id).await?;

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
    let manager = ProjectScopedManager::provision(&admin, &domain.id).await?;

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
    let manager = ProjectScopedManager::provision(&admin, &domain.id).await?;

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
    let manager = ProjectScopedManager::provision(&admin, &domain.id).await?;

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
    let manager = ProjectScopedManager::provision(&admin, &domain.id).await?;

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
    let status = status_with_invalid_token(
        http::Method::POST,
        "v3/groups",
        Some(serde_json::json!({"group": {"name": "x", "domain_id": "default"}})),
    )
    .await?;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn test_group_show_unauthorized() -> Result<()> {
    let status =
        status_with_invalid_token(http::Method::GET, "v3/groups/some-group-id", None).await?;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn test_group_list_unauthorized() -> Result<()> {
    let status = status_with_invalid_token(http::Method::GET, "v3/groups", None).await?;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn test_group_update_unauthorized() -> Result<()> {
    let status = status_with_invalid_token(
        http::Method::PATCH,
        "v3/groups/some-group-id",
        Some(serde_json::json!({"group": {"name": "x"}})),
    )
    .await?;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn test_group_delete_unauthorized() -> Result<()> {
    let status =
        status_with_invalid_token(http::Method::DELETE, "v3/groups/some-group-id", None).await?;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    Ok(())
}
