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
//! `/v3/groups/{group_id}/users[/{user_id}]` group membership endpoints.
//!
//! | case | test |
//! |------|------|
//! | add, check, list, remove lifecycle | `test_group_user_lifecycle` |
//! | missing group / user | `test_group_user_not_found` |
//! | project-scoped user (policy `identity/group/user/*`) | `test_group_user_forbidden_project_scoped_user` |
//! | invalid token | `test_group_user_unauthorized` |

use std::sync::Arc;

use eyre::{OptionExt, Result};
use http::{Method, StatusCode};
use secrecy::ExposeSecret;
use uuid::Uuid;

use openstack_keystone_api_types::scope::{DomainBuilder, Scope, ScopeProjectBuilder};
use openstack_keystone_api_types::v3::group::GroupCreateBuilder;
use openstack_keystone_api_types::v3::user::UserCreateBuilder;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::asserts::assert_response_status;
use test_api::common::{TestClient, get_password_auth, raw_request};
use test_api::fixtures::{FIXTURE_PASSWORD, ProjectScopedUser, warn_on_cleanup_failure};
use test_api::guard::*;
use test_api::identity::group::create_group;
use test_api::identity::user::create_user;

async fn admin_client() -> Result<TestClient> {
    let mut client = TestClient::new()?;
    client.auth_admin_system().await?;
    Ok(client)
}

async fn send(client: &TestClient, method: Method, path: &str) -> Result<reqwest::Response> {
    Ok(client
        .client
        .request(method, client.base_url.join(path)?)
        .send()
        .await?)
}

#[tokio::test]
async fn test_group_user_lifecycle() -> Result<()> {
    let sdk = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let admin = admin_client().await?;

    let group = create_group(
        &sdk,
        GroupCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .domain_id("default")
            .build()?,
    )
    .await?;
    let user = create_user(
        &sdk,
        UserCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .domain_id("default")
            .enabled(true)
            .build()?,
    )
    .await?;
    let member = format!("v3/groups/{}/users/{}", group.id, user.id);
    let members = format!("v3/groups/{}/users", group.id);

    let result: Result<()> = async {
        let rsp = send(&admin, Method::HEAD, &member).await?;
        assert_response_status(&rsp, StatusCode::NOT_FOUND, "not yet a member");

        let rsp = send(&admin, Method::DELETE, &member).await?;
        assert_response_status(&rsp, StatusCode::NOT_FOUND, "removing a non-member");

        let rsp = send(&admin, Method::PUT, &member).await?;
        assert_response_status(&rsp, StatusCode::NO_CONTENT, "adding the user");

        let rsp = send(&admin, Method::HEAD, &member).await?;
        assert_response_status(&rsp, StatusCode::NO_CONTENT, "membership exists");

        let rsp = send(&admin, Method::GET, &members).await?;
        assert_response_status(&rsp, StatusCode::OK, "listing members");
        let body: serde_json::Value = rsp.json().await?;
        let ids: Vec<&str> = body["users"]
            .as_array()
            .map(|u| u.iter().filter_map(|u| u["id"].as_str()).collect())
            .unwrap_or_default();
        assert_eq!(ids, vec![user.id.as_str()]);

        let rsp = send(&admin, Method::GET, &format!("v3/users/{}/groups", user.id)).await?;
        let body: serde_json::Value = rsp.json().await?;
        assert_eq!(body["groups"][0]["id"].as_str(), Some(group.id.as_str()));

        let rsp = send(&admin, Method::DELETE, &member).await?;
        assert_response_status(&rsp, StatusCode::NO_CONTENT, "removing the user");

        let rsp = send(&admin, Method::HEAD, &member).await?;
        assert_response_status(&rsp, StatusCode::NOT_FOUND, "membership removed");
        Ok(())
    }
    .await;

    warn_on_cleanup_failure("group", group.delete().await);
    warn_on_cleanup_failure("user", user.delete().await);
    result
}

#[tokio::test]
async fn test_group_user_not_found() -> Result<()> {
    let admin = admin_client().await?;
    for method in [Method::HEAD, Method::PUT, Method::DELETE] {
        let rsp = send(&admin, method.clone(), "v3/groups/missing/users/missing").await?;
        assert_response_status(
            &rsp,
            StatusCode::NOT_FOUND,
            &format!("{method} unknown ids"),
        );
    }
    let rsp = send(&admin, Method::GET, "v3/groups/missing/users").await?;
    assert_response_status(&rsp, StatusCode::NOT_FOUND, "listing an unknown group");
    Ok(())
}

#[tokio::test]
async fn test_group_user_forbidden_project_scoped_user() -> Result<()> {
    let sdk = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let fixture = ProjectScopedUser::provision(&sdk, "default", "member").await?;
    let group = create_group(
        &sdk,
        GroupCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .domain_id("default")
            .build()?,
    )
    .await?;

    // Authenticate as the unprivileged fixture user.
    let mut caller = TestClient::new()?;
    caller
        .auth_password(
            get_password_auth(&fixture.user.name, FIXTURE_PASSWORD, "default")?,
            Some(Scope::Project(
                ScopeProjectBuilder::default()
                    .id(fixture.project.id.clone())
                    .domain(DomainBuilder::default().id("default").build()?)
                    .build()?,
            )),
        )
        .await?;
    let token = caller.token.as_ref().ok_or_eyre("token")?.expose_secret();
    let path = format!("v3/groups/{}/users/{}", group.id, fixture.user.id);
    let put = raw_request(Method::PUT, &path, Some(token), None).await;
    let list = raw_request(
        Method::GET,
        &format!("v3/groups/{}/users", group.id),
        Some(token),
        None,
    )
    .await;

    warn_on_cleanup_failure("group", group.delete().await);
    warn_on_cleanup_failure("fixture", fixture.cleanup().await);
    assert_response_status(&put?, StatusCode::FORBIDDEN, "member must not add users");
    assert_response_status(
        &list?,
        StatusCode::FORBIDDEN,
        "member must not list members",
    );
    Ok(())
}

#[tokio::test]
async fn test_group_user_unauthorized() -> Result<()> {
    for (method, path) in [
        (Method::GET, "v3/groups/g/users"),
        (Method::HEAD, "v3/groups/g/users/u"),
        (Method::PUT, "v3/groups/g/users/u"),
        (Method::DELETE, "v3/groups/g/users/u"),
    ] {
        let rsp = raw_request(method.clone(), path, Some("invalid-token"), None).await?;
        assert_response_status(&rsp, StatusCode::UNAUTHORIZED, &format!("{method} {path}"));
    }
    Ok(())
}
