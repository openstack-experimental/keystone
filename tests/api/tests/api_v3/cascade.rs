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
//! Functional tests for the delete cascades: what is deleted together with a
//! user, a project and a domain.
//!
//! Every test creates its own domain: the `default` domain is seeded straight
//! into the database and is not the place to delete things from.

use std::sync::Arc;

use eyre::{OptionExt, Result};
use http::StatusCode;
use secrecy::ExposeSecret;
use uuid::Uuid;

use openstack_keystone_api_types::scope::{DomainBuilder, Scope, ScopeProjectBuilder};
use openstack_keystone_api_types::v3::domain::{Domain, DomainCreateBuilder, DomainUpdateBuilder};
use openstack_keystone_api_types::v3::group::GroupCreateBuilder;
use openstack_keystone_api_types::v3::project::ProjectCreateBuilder;
use openstack_keystone_api_types::v3::trust::{TrustCreate, TrustRoleRef};
use openstack_keystone_api_types::v3::user::UserCreateBuilder;
use openstack_sdk::AsyncOpenStack;

use test_api::asserts::{assert_forbidden, assert_status};
use test_api::assignment::grant::{add_project_grant, add_system_group_grant};
use test_api::assignment::{RoleAssignmentListRequest, list_role_assignments};
use test_api::common::{self, raw_request};
use test_api::fixtures::{FIXTURE_PASSWORD, ProjectScopedUser};
use test_api::guard::{AsyncResourceGuard, ResourceGuard};
use test_api::identity::group::{create_group, get_group};
use test_api::identity::user::{create_user, get_user};
use test_api::resource::domain::{create_domain, get_domain, update_domain};
use test_api::resource::get_system_scope_config;
use test_api::resource::project::{create_project, get_project};
use test_api::role::list_roles;
use test_api::trust::{create_trust, show_trust};

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&get_system_scope_config()?).await?,
    ))
}

async fn new_domain(admin: &Arc<AsyncOpenStack>) -> Result<AsyncResourceGuard<Domain>> {
    create_domain(
        admin,
        DomainCreateBuilder::default()
            .name(format!("cascade-dom-{}", Uuid::new_v4().simple()))
            .enabled(true)
            .build()?,
    )
    .await
}

async fn assignments_of_user(admin: &Arc<AsyncOpenStack>, user_id: &str) -> Result<usize> {
    Ok(list_role_assignments(
        admin,
        RoleAssignmentListRequest {
            user_id: Some(user_id.to_string()),
            ..Default::default()
        },
    )
    .await?
    .len())
}

async fn assignments_on_project(admin: &Arc<AsyncOpenStack>, project_id: &str) -> Result<usize> {
    Ok(list_role_assignments(
        admin,
        RoleAssignmentListRequest {
            project_id: Some(project_id.to_string()),
            ..Default::default()
        },
    )
    .await?
    .len())
}

/// Create an application credential for the fixture user through the API and
/// return `(id, secret)`.
async fn create_app_cred(
    fixture: &ProjectScopedUser,
    domain_id: &str,
    role_id: &str,
) -> Result<(String, String)> {
    let mut tc = common::TestClient::new()?;
    tc.auth_password(
        common::get_password_auth(&fixture.user.name, FIXTURE_PASSWORD, domain_id)?,
        Some(Scope::Project(
            ScopeProjectBuilder::default()
                .id(fixture.project.id.clone())
                .domain(DomainBuilder::default().id(domain_id).build()?)
                .build()?,
        )),
    )
    .await?;
    let rsp = raw_request(
        http::Method::POST,
        &format!("v3/users/{}/application_credentials", fixture.user.id),
        Some(tc.token.as_ref().ok_or_eyre("token")?.expose_secret()),
        Some(serde_json::json!({
            "application_credential": {
                "name": format!("ac_{}", Uuid::new_v4().simple()),
                "roles": [{"id": role_id}],
            }
        })),
    )
    .await?;
    assert_eq!(rsp.status(), StatusCode::CREATED);
    let body: serde_json::Value = rsp.json().await?;
    let cred = &body["application_credential"];
    Ok((
        cred["id"].as_str().ok_or_eyre("id")?.to_string(),
        cred["secret"].as_str().ok_or_eyre("secret")?.to_string(),
    ))
}

/// Status of an authentication request with the application credential.
async fn app_cred_auth_status(id: &str, secret: &str) -> Result<StatusCode> {
    let rsp = raw_request(
        http::Method::POST,
        "v3/auth/tokens",
        None,
        Some(serde_json::json!({
            "auth": {"identity": {
                "methods": ["application_credential"],
                "application_credential": {"id": id, "secret": secret},
            }}
        })),
    )
    .await?;
    Ok(rsp.status())
}

/// Deleting a user removes its role assignments and application credentials.
#[tokio::test]
async fn test_user_delete_removes_grants_and_app_credentials() -> Result<()> {
    let admin = admin_session().await?;
    let domain = new_domain(&admin).await?;
    let fixture = ProjectScopedUser::provision(&admin, &domain.id, "member").await?;
    let role = list_roles(&admin)
        .await?
        .into_iter()
        .find(|x| x.name == "member")
        .ok_or_eyre("member role")?;
    let (cred_id, cred_secret) = create_app_cred(&fixture, &domain.id, &role.id).await?;

    // The `member` role implies further roles, so there is more than one.
    assert!(assignments_of_user(&admin, &fixture.user.id).await? > 0);
    assert_eq!(
        StatusCode::CREATED,
        app_cred_auth_status(&cred_id, &cred_secret).await?
    );

    let ProjectScopedUser { user, project, .. } = fixture;
    let user_id = user.id.clone();
    user.delete().await?;

    assert_eq!(0, assignments_of_user(&admin, &user_id).await?);
    assert_eq!(
        StatusCode::UNAUTHORIZED,
        app_cred_auth_status(&cred_id, &cred_secret).await?
    );

    project.delete().await?;
    domain.delete().await?;
    Ok(())
}

/// Deleting a project removes the role assignments on it.
#[tokio::test]
async fn test_project_delete_removes_grants() -> Result<()> {
    let admin = admin_session().await?;
    let domain = new_domain(&admin).await?;
    let fixture = ProjectScopedUser::provision(&admin, &domain.id, "member").await?;
    assert!(assignments_on_project(&admin, &fixture.project.id).await? > 0);

    let ProjectScopedUser { user, project, .. } = fixture;
    let project_id = project.id.clone();
    project.delete().await?;

    assert_eq!(0, assignments_on_project(&admin, &project_id).await?);
    // The user is a sibling, not a child, and stays.
    get_user(&admin, &user.id).await?;

    user.delete().await?;
    domain.delete().await?;
    Ok(())
}

/// An enabled domain that still owns anything is not deleted, and nothing in
/// it is touched; once disabled, the delete takes its contents along.
#[tokio::test]
async fn test_domain_delete_cascades_once_disabled() -> Result<()> {
    let admin = admin_session().await?;
    let domain = new_domain(&admin).await?;
    let parent = create_project(
        &admin,
        ProjectCreateBuilder::default()
            .name(format!("cascade-parent-{}", Uuid::new_v4().simple()))
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;
    let child = create_project(
        &admin,
        ProjectCreateBuilder::default()
            .name(format!("cascade-child-{}", Uuid::new_v4().simple()))
            .domain_id(domain.id.clone())
            .parent_id(parent.id.clone())
            .build()?,
    )
    .await?;
    let user = create_user(
        &admin,
        UserCreateBuilder::default()
            .name(format!("cascade-usr-{}", Uuid::new_v4().simple()))
            .domain_id(domain.id.clone())
            .password(FIXTURE_PASSWORD)
            .enabled(true)
            .build()?,
    )
    .await?;
    let group = create_group(
        &admin,
        GroupCreateBuilder::default()
            .name(format!("cascade-grp-{}", Uuid::new_v4().simple()))
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;
    let role = list_roles(&admin)
        .await?
        .into_iter()
        .find(|x| x.name == "member")
        .ok_or_eyre("member role")?;
    add_project_grant(&admin, &child.id, &user.id, &role.id).await?;

    // Enabled and not empty: refused, and everything is still there.
    assert_forbidden(
        test_api::resource::domain::delete_domain(&admin, domain.id.clone()).await,
        "an enabled domain with contents must not be deleted",
    );
    get_project(&admin, &child.id).await?;
    get_user(&admin, &user.id).await?;
    assert!(assignments_on_project(&admin, &child.id).await? > 0);

    update_domain(
        &admin,
        domain.id.clone(),
        DomainUpdateBuilder::default().enabled(false).build()?,
    )
    .await?;
    let domain_id = domain.id.clone();
    domain.delete().await?;

    assert_status(
        get_domain(&admin, &domain_id).await,
        StatusCode::NOT_FOUND,
        "the domain must be deleted",
    );
    assert_status(
        get_project(&admin, &child.id).await,
        StatusCode::NOT_FOUND,
        "child must be deleted with the domain",
    );
    assert_status(
        get_project(&admin, &parent.id).await,
        StatusCode::NOT_FOUND,
        "parent must be deleted with the domain",
    );
    assert_status(
        get_user(&admin, &user.id).await,
        StatusCode::NOT_FOUND,
        "user must be deleted with the domain",
    );
    assert_status(
        get_group(&admin, &group.id).await,
        StatusCode::NOT_FOUND,
        "group must be deleted with the domain",
    );
    assert_eq!(0, assignments_of_user(&admin, &user.id).await?);

    // Everything is gone already: release the guards without a delete.
    child.into_inner();
    parent.into_inner();
    user.into_inner();
    group.into_inner();
    Ok(())
}

/// Which party of the trust is deleted.
#[derive(Clone, Copy)]
enum Party {
    Trustor,
    Trustee,
}

/// Deleting either the trustor or the trustee removes the (role-carrying)
/// trust.
async fn trust_removed_with_user(party: Party) -> Result<()> {
    let admin = admin_session().await?;
    let domain = new_domain(&admin).await?;
    let trustor = ProjectScopedUser::provision(&admin, &domain.id, "member").await?;
    let trustee = create_user(
        &admin,
        UserCreateBuilder::default()
            .name(format!("cascade-trustee-{}", Uuid::new_v4().simple()))
            .domain_id(domain.id.clone())
            .password(FIXTURE_PASSWORD)
            .enabled(true)
            .build()?,
    )
    .await?;
    let member = list_roles(&admin)
        .await?
        .into_iter()
        .find(|r| r.name == "member")
        .ok_or_eyre("member role")?;
    let trust = create_trust(
        &trustor.session,
        TrustCreate {
            id: None,
            trustor_user_id: trustor.user.id.clone(),
            trustee_user_id: trustee.id.clone(),
            project_id: Some(trustor.project.id.clone()),
            impersonation: false,
            expires_at: None,
            remaining_uses: None,
            redelegated_trust_id: None,
            redelegation_count: None,
            roles: vec![TrustRoleRef {
                domain_id: None,
                id: Some(member.id.clone()),
                name: None,
            }],
            extra: None,
        },
    )
    .await?;
    let trust_id = trust.id.clone();
    show_trust(&admin, &trust_id).await?;

    let ProjectScopedUser { user, project, .. } = trustor;
    match party {
        Party::Trustor => {
            user.delete().await?;
            trustee.delete().await?;
        }
        Party::Trustee => {
            trustee.delete().await?;
            user.delete().await?;
        }
    }

    assert_status(
        show_trust(&admin, &trust_id).await,
        StatusCode::NOT_FOUND,
        "the trust must be deleted with its user",
    );

    // The trust is gone already: release the guard without a delete.
    trust.into_inner();
    project.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_trustor_delete_removes_trust() -> Result<()> {
    trust_removed_with_user(Party::Trustor).await
}

#[tokio::test]
async fn test_trustee_delete_removes_trust() -> Result<()> {
    trust_removed_with_user(Party::Trustee).await
}

/// Deleting a group removes the grants it holds, including the ones on a
/// target outside of its own domain (the system).
#[tokio::test]
async fn test_group_delete_removes_system_grants() -> Result<()> {
    let admin = admin_session().await?;
    let domain = new_domain(&admin).await?;
    let group = create_group(
        &admin,
        GroupCreateBuilder::default()
            .name(format!("cascade-grp-{}", Uuid::new_v4().simple()))
            .domain_id(domain.id.clone())
            .build()?,
    )
    .await?;
    let role = list_roles(&admin)
        .await?
        .into_iter()
        .find(|x| x.name == "reader")
        .ok_or_eyre("reader role")?;
    add_system_group_grant(&admin, &group.id, &role.id).await?;
    let held = list_role_assignments(
        &admin,
        RoleAssignmentListRequest {
            group_id: Some(group.id.clone()),
            ..Default::default()
        },
    )
    .await?;
    assert!(!held.is_empty(), "the group must hold the system grant");

    let group_id = group.id.clone();
    group.delete().await?;

    let left = list_role_assignments(
        &admin,
        RoleAssignmentListRequest {
            group_id: Some(group_id),
            ..Default::default()
        },
    )
    .await?;
    assert!(left.is_empty(), "grants must not outlive the group");

    domain.delete().await?;
    Ok(())
}
