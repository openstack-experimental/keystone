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
//! Role implication authorization matrix for issue #994.

use std::sync::Arc;

use eyre::Result;
use uuid::Uuid;

use openstack_keystone_api_types::v3::role::{Role, RoleCreateBuilder};
use openstack_sdk::AsyncOpenStack;

use test_api::asserts::{
    RawUnauthorizedRequest, assert_forbidden, assert_raw_request_unauthorized,
};
use test_api::common::get_system_scope_session;
use test_api::fixtures::{ProjectScopedUser, provision_fixture_pair};
use test_api::role::imply::{
    check_implied_role, create_implied_role, delete_implied_role, get_implied_role,
    list_implied_role,
};
use test_api::role::{create_role, delete_role};

async fn role_pair(admin: &Arc<AsyncOpenStack>) -> Result<(Role, Role)> {
    let prior = create_role(
        admin,
        RoleCreateBuilder::default()
            .name(format!("prior-authz-{}", Uuid::new_v4().simple()))
            .build()?,
    )
    .await?;
    provision_fixture_pair(
        prior,
        create_role(
            admin,
            RoleCreateBuilder::default()
                .name(format!("implied-authz-{}", Uuid::new_v4().simple()))
                .build()?,
        ),
        |prior| async move { delete_role(admin, &prior.id).await },
        "prior role fixture",
    )
    .await
}

async fn delete_role_pair(admin: &Arc<AsyncOpenStack>, prior: &Role, implied: &Role) -> Result<()> {
    let implied_result = delete_role(admin, &implied.id).await;
    let prior_result = delete_role(admin, &prior.id).await;
    implied_result?;
    prior_result
}

fn unauthorized_request(method: http::Method, path: &str) -> RawUnauthorizedRequest<'_> {
    RawUnauthorizedRequest {
        method,
        path,
        body: None,
        message: "an invalid token must not access role implications",
    }
}

#[tokio::test]
async fn test_implied_role_create_forbidden_project_scoped_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let (prior, implied) = role_pair(&admin).await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = match create_implied_role(&member.session, &prior.id, &implied.id).await {
        Ok(_) => {
            delete_implied_role(&admin, &prior.id, &implied.id).await?;
            Ok(())
        }
        Err(error) => Err(error),
    };

    member.cleanup().await?;
    delete_role_pair(&admin, &prior, &implied).await?;
    assert_forbidden(
        result,
        "a project-scoped member must not create role implications",
    );
    Ok(())
}

#[tokio::test]
async fn test_implied_role_show_forbidden_project_scoped_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let (prior, implied) = role_pair(&admin).await?;
    create_implied_role(&admin, &prior.id, &implied.id).await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = get_implied_role(&member.session, &prior.id, &implied.id)
        .await
        .map(|_| ());

    member.cleanup().await?;
    delete_implied_role(&admin, &prior.id, &implied.id).await?;
    delete_role_pair(&admin, &prior, &implied).await?;
    assert_forbidden(
        result,
        "a project-scoped member must not show role implications",
    );
    Ok(())
}

#[tokio::test]
async fn test_implied_role_list_forbidden_project_scoped_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let (prior, implied) = role_pair(&admin).await?;
    create_implied_role(&admin, &prior.id, &implied.id).await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = list_implied_role(&member.session, &prior.id)
        .await
        .map(|_| ());

    member.cleanup().await?;
    delete_implied_role(&admin, &prior.id, &implied.id).await?;
    delete_role_pair(&admin, &prior, &implied).await?;
    assert_forbidden(
        result,
        "a project-scoped member must not list role implications",
    );
    Ok(())
}

#[tokio::test]
async fn test_implied_role_check_forbidden_project_scoped_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let (prior, implied) = role_pair(&admin).await?;
    create_implied_role(&admin, &prior.id, &implied.id).await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = check_implied_role(&member.session, &prior.id, &implied.id).await;

    member.cleanup().await?;
    delete_implied_role(&admin, &prior.id, &implied.id).await?;
    delete_role_pair(&admin, &prior, &implied).await?;
    assert_forbidden(
        result,
        "a project-scoped member must not check role implications",
    );
    Ok(())
}

#[tokio::test]
async fn test_implied_role_delete_forbidden_project_scoped_member() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let (prior, implied) = role_pair(&admin).await?;
    create_implied_role(&admin, &prior.id, &implied.id).await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let result = delete_implied_role(&member.session, &prior.id, &implied.id).await;

    member.cleanup().await?;
    if result.is_err() {
        delete_implied_role(&admin, &prior.id, &implied.id).await?;
    }
    delete_role_pair(&admin, &prior, &implied).await?;
    assert_forbidden(
        result,
        "a project-scoped member must not delete role implications",
    );
    Ok(())
}

#[tokio::test]
async fn test_implied_role_create_unauthorized() -> Result<()> {
    assert_raw_request_unauthorized(
        unauthorized_request(http::Method::PUT, "v3/roles/prior/implies/implied"),
        Some("invalid-token"),
    )
    .await
}

#[tokio::test]
async fn test_implied_role_show_unauthorized() -> Result<()> {
    assert_raw_request_unauthorized(
        unauthorized_request(http::Method::GET, "v3/roles/prior/implies/implied"),
        Some("invalid-token"),
    )
    .await
}

#[tokio::test]
async fn test_implied_role_list_unauthorized() -> Result<()> {
    assert_raw_request_unauthorized(
        unauthorized_request(http::Method::GET, "v3/roles/prior/implies"),
        Some("invalid-token"),
    )
    .await
}

#[tokio::test]
async fn test_implied_role_check_unauthorized() -> Result<()> {
    assert_raw_request_unauthorized(
        unauthorized_request(http::Method::HEAD, "v3/roles/prior/implies/implied"),
        Some("invalid-token"),
    )
    .await
}

#[tokio::test]
async fn test_implied_role_delete_unauthorized() -> Result<()> {
    assert_raw_request_unauthorized(
        unauthorized_request(http::Method::DELETE, "v3/roles/prior/implies/implied"),
        Some("invalid-token"),
    )
    .await
}
