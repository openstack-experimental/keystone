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
//! OS-EC2 credential authorization matrix (issue #993).
//!
//! | endpoint (under /v3/users/{uid}/credentials/OS-EC2) | 2xx | 403 | 401 |
//! |------------------------------------------------------|-----|-----|-----|
//! | POST   /            | `create_success_owner`  | `create_forbidden_cross_user` | `create_unauthorized` |
//! | GET    /{access}    | `show_success_owner`    | `show_forbidden_cross_user`   | `show_unauthorized`   |
//! | GET    /            | `list_success_owner`    | `list_forbidden_cross_user`   | `list_unauthorized`   |
//! | DELETE /{access}    | `delete_success_owner`  | `delete_forbidden_cross_user` | `delete_unauthorized` |
//!
//! Policy (`policy/os_ec2/*.rego`): admin, or a `member` acting on their
//! **own** `user_id`. The 403 fixture is therefore a real project-scoped
//! `member` operating on a *different* user's credentials.

use std::sync::Arc;

use eyre::Result;
use reqwest::StatusCode;

use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::asserts::{assert_forbidden, assert_status};
use test_api::common::raw_request;
use test_api::credential::ec2::*;
use test_api::fixtures::ProjectScopedUser;

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&CloudConfig::from_env()?).await?,
    ))
}

/// Two independent member users; `a` will attempt operations on `b`'s
/// credentials.
async fn two_members(
    admin: &Arc<AsyncOpenStack>,
) -> Result<(ProjectScopedUser, ProjectScopedUser)> {
    let a = ProjectScopedUser::provision(admin, "default", "member").await?;
    let b = ProjectScopedUser::provision(admin, "default", "member").await?;
    Ok((a, b))
}

// --- create -------------------------------------------------------------

#[tokio::test]
async fn test_ec2_credential_create_success_owner() -> Result<()> {
    let admin = admin_session().await?;
    let owner = ProjectScopedUser::provision(&admin, "default", "member").await?;

    let cred = create_ec2_credential(&owner.session, &owner.user.id, &owner.project.id).await?;
    assert!(!cred.access.is_empty(), "access key must be generated");
    assert!(!cred.secret.is_empty(), "secret must be returned on create");
    assert_eq!(cred.user_id, owner.user.id);
    assert_eq!(cred.project_id, owner.project.id);

    delete_ec2_credential(&admin, &owner.user.id, &cred.access).await?;
    owner.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_ec2_credential_create_forbidden_cross_user() -> Result<()> {
    let admin = admin_session().await?;
    let (a, b) = two_members(&admin).await?;

    assert_forbidden(
        create_ec2_credential(&a.session, &b.user.id, &b.project.id).await,
        "a member must not create EC2 credentials for another user",
    );

    a.cleanup().await?;
    b.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_ec2_credential_create_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::POST,
        "v3/users/some-user/credentials/OS-EC2",
        Some("invalid-token"),
        Some(serde_json::json!({"tenant_id": "some-project"})),
    )
    .await?;
    assert_eq!(rsp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

// --- show ---------------------------------------------------------------

#[tokio::test]
async fn test_ec2_credential_show_success_owner() -> Result<()> {
    let admin = admin_session().await?;
    let owner = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let cred = create_ec2_credential(&owner.session, &owner.user.id, &owner.project.id).await?;

    let shown = get_ec2_credential(&owner.session, &owner.user.id, &cred.access).await?;
    assert_eq!(shown.access, cred.access);
    assert_eq!(shown.user_id, owner.user.id);
    assert_eq!(shown.project_id, owner.project.id);

    delete_ec2_credential(&admin, &owner.user.id, &cred.access).await?;
    owner.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_ec2_credential_show_forbidden_cross_user() -> Result<()> {
    let admin = admin_session().await?;
    let (a, b) = two_members(&admin).await?;
    let cred = create_ec2_credential(&b.session, &b.user.id, &b.project.id).await?;

    assert_forbidden(
        get_ec2_credential(&a.session, &b.user.id, &cred.access).await,
        "a member must not read another user's EC2 credential",
    );

    delete_ec2_credential(&admin, &b.user.id, &cred.access).await?;
    a.cleanup().await?;
    b.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_ec2_credential_show_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v3/users/some-user/credentials/OS-EC2/some-access",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_eq!(rsp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

// --- list ---------------------------------------------------------------

#[tokio::test]
async fn test_ec2_credential_list_success_owner() -> Result<()> {
    let admin = admin_session().await?;
    let owner = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let cred = create_ec2_credential(&owner.session, &owner.user.id, &owner.project.id).await?;

    let creds = list_ec2_credentials(&owner.session, &owner.user.id).await?;
    assert!(
        creds.iter().any(|found| found.access == cred.access),
        "owner's listing must contain the created credential"
    );

    delete_ec2_credential(&admin, &owner.user.id, &cred.access).await?;
    owner.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_ec2_credential_list_forbidden_cross_user() -> Result<()> {
    let admin = admin_session().await?;
    let (a, b) = two_members(&admin).await?;

    assert_forbidden(
        list_ec2_credentials(&a.session, &b.user.id).await,
        "a member must not list another user's EC2 credentials",
    );

    a.cleanup().await?;
    b.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_ec2_credential_list_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        "v3/users/some-user/credentials/OS-EC2",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_eq!(rsp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

// --- delete -------------------------------------------------------------

#[tokio::test]
async fn test_ec2_credential_delete_success_owner() -> Result<()> {
    let admin = admin_session().await?;
    let owner = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let cred = create_ec2_credential(&owner.session, &owner.user.id, &owner.project.id).await?;

    delete_ec2_credential(&owner.session, &owner.user.id, &cred.access).await?;
    assert_status(
        get_ec2_credential(&admin, &owner.user.id, &cred.access).await,
        StatusCode::NOT_FOUND,
        "deleted EC2 credential must be gone",
    );

    owner.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_ec2_credential_delete_forbidden_cross_user() -> Result<()> {
    let admin = admin_session().await?;
    let (a, b) = two_members(&admin).await?;
    let cred = create_ec2_credential(&b.session, &b.user.id, &b.project.id).await?;

    assert_forbidden(
        delete_ec2_credential(&a.session, &b.user.id, &cred.access).await,
        "a member must not delete another user's EC2 credential",
    );

    // The credential must have survived; admin cleans up.
    delete_ec2_credential(&admin, &b.user.id, &cred.access).await?;
    a.cleanup().await?;
    b.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_ec2_credential_delete_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::DELETE,
        "v3/users/some-user/credentials/OS-EC2/some-access",
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_eq!(rsp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}
