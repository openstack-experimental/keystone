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
//! Functional tests for authentication by application credential.

use std::collections::HashMap;
use std::sync::Arc;

use eyre::Result;
use secrecy::ExposeSecret;
use uuid::Uuid;

use openstack_keystone_api_types::scope::{DomainBuilder, Scope, ScopeProjectBuilder};
use openstack_keystone_api_types::v3::auth::token::*;
use openstack_keystone_api_types::v3::project::ProjectCreateBuilder;
use openstack_keystone_api_types::v3::user::UserCreateBuilder;
use openstack_sdk::AsyncOpenStack;
use openstack_sdk::config::CloudConfig;

use test_api::assignment::grant::add_project_grant;
use test_api::auth::token::auth_token;
use test_api::common;
use test_api::guard::ResourceGuard;
use test_api::identity::user::create_user;
use test_api::resource::project::create_project;
use test_api::role::list_roles;

fn app_cred_identity_by_id(id: &str, secret: &str) -> Identity {
    IdentityBuilder::default()
        .methods(vec!["application_credential".into()])
        .application_credential(ApplicationCredentialAuth {
            id: Some(id.into()),
            name: None,
            secret: secret.into(),
            user: None,
        })
        .build()
        .unwrap()
}

fn app_cred_identity_by_name(name: &str, secret: &str, user_id: &str) -> Identity {
    IdentityBuilder::default()
        .methods(vec!["application_credential".into()])
        .application_credential(ApplicationCredentialAuth {
            id: None,
            name: Some(name.into()),
            secret: secret.into(),
            user: Some(ApplicationCredentialUser {
                id: Some(user_id.into()),
                name: None,
                domain: None,
            }),
        })
        .build()
        .unwrap()
}

/// Authenticate the user with password, then create an application credential
/// via raw HTTP. Returns the credential ID.
async fn create_app_cred_for_user(
    user_id: &str,
    user_name: &str,
    password: &str,
    user_domain_id: &str,
    project_id: &str,
    project_domain_id: &str,
    app_cred_secret: &str,
    roles: &[serde_json::Value],
) -> Result<(String, String)> {
    let mut tc = common::TestClient::default()?;
    tc.auth_password(
        common::get_password_auth(user_name, password, user_domain_id)?,
        Some(Scope::Project(
            ScopeProjectBuilder::default()
                .id(project_id)
                .domain(DomainBuilder::default().id(project_domain_id).build()?)
                .build()?,
        )),
    )
    .await?;

    let app_cred_name = format!("ac_{}", Uuid::new_v4().simple());
    let create_body = serde_json::json!({
        "application_credential": {
            "name": &app_cred_name,
            "secret": app_cred_secret,
            "roles": roles,
        }
    });
    let rsp = common::raw_request(
        http::Method::POST,
        &format!("v3/users/{}/application_credentials", user_id),
        Some(tc.token.as_ref().unwrap().expose_secret()),
        Some(create_body),
    )
    .await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::CREATED);
    let cred_resp: serde_json::Value = rsp.json().await?;
    let cred_id = cred_resp["application_credential"]["id"]
        .as_str()
        .expect("app cred id must be present")
        .to_string();
    Ok((cred_id, app_cred_name))
}
#[tokio::test]
async fn test_auth_by_application_credential_id() -> Result<()> {
    let admin = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let password = "TestPassword123!";

    let user = create_user(
        &admin,
        UserCreateBuilder::default()
            .name(format!("usr_{}", Uuid::new_v4().simple()))
            .domain_id("default")
            .enabled(true)
            .password(password)
            .build()?,
    )
    .await?;

    let project = create_project(
        &admin,
        ProjectCreateBuilder::default()
            .domain_id("default")
            .parent_id("default")
            .name(format!("prj_{}", Uuid::new_v4().simple()))
            .is_domain(false)
            .enabled(true)
            .build()?,
    )
    .await?;

    let roles: HashMap<String, String> = list_roles(&admin)
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let member = roles.get("member").expect("member role must exist");
    add_project_grant(&admin, &project.id, &user.id, member).await?;

    let app_cred_secret = "my_app_cred_secret_value";
    let (cred_id, _) = create_app_cred_for_user(
        &user.id,
        &user.name,
        password,
        &user.domain_id,
        &project.id,
        "default",
        app_cred_secret,
        &[serde_json::json!({"id": member, "name": "member"})],
    )
    .await?;

    let body = serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["application_credential"],
                "application_credential": {
                    "id": &cred_id,
                    "secret": app_cred_secret
                }
            }
        }
    });
    let rsp = common::raw_request(http::Method::POST, "v3/auth/tokens", None, Some(body)).await?;

    assert_eq!(rsp.status(), reqwest::StatusCode::CREATED);
    let token_resp: serde_json::Value = rsp.json().await?;
    assert!(
        token_resp["token"]["methods"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "application_credential"),
        "methods must contain application_credential"
    );
    assert_eq!(token_resp["token"]["user"]["id"].as_str().unwrap(), user.id);

    user.delete().await?;
    project.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_auth_by_application_credential_name() -> Result<()> {
    let admin = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let password = "TestPassword123!";

    let user = create_user(
        &admin,
        UserCreateBuilder::default()
            .name(format!("usr_{}", Uuid::new_v4().simple()))
            .domain_id("default")
            .enabled(true)
            .password(password)
            .build()?,
    )
    .await?;

    let project = create_project(
        &admin,
        ProjectCreateBuilder::default()
            .domain_id("default")
            .parent_id("default")
            .name(format!("prj_{}", Uuid::new_v4().simple()))
            .is_domain(false)
            .enabled(true)
            .build()?,
    )
    .await?;

    let roles: HashMap<String, String> = list_roles(&admin)
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let member = roles.get("member").expect("member role must exist");
    add_project_grant(&admin, &project.id, &user.id, member).await?;

    let mut tc = common::TestClient::default()?;
    tc.auth_password(
        common::get_password_auth(&user.name, password, &user.domain_id)?,
        Some(Scope::Project(
            ScopeProjectBuilder::default()
                .id(&project.id)
                .domain(DomainBuilder::default().id("default").build()?)
                .build()?,
        )),
    )
    .await?;

    let app_cred_secret = "by_name_secret";
    let app_cred_name = format!("ac_{}", Uuid::new_v4().simple());
    let create_body = serde_json::json!({
        "application_credential": {
            "name": &app_cred_name,
            "secret": app_cred_secret,
            "roles": [{"id": member, "name": "member"}],
        }
    });
    let rsp = common::raw_request(
        http::Method::POST,
        &format!("v3/users/{}/application_credentials", user.id),
        Some(tc.token.as_ref().unwrap().expose_secret()),
        Some(create_body),
    )
    .await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::CREATED);

    let (token, _) = auth_token(
        &admin,
        app_cred_identity_by_name(&app_cred_name, app_cred_secret, &user.id),
        None,
    )
    .await?;

    assert!(
        token
            .methods
            .contains(&"application_credential".to_string()),
        "methods must contain application_credential"
    );
    assert_eq!(token.user.id, user.id);

    user.delete().await?;
    project.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_auth_by_application_credential_wrong_secret() -> Result<()> {
    let admin = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let password = "TestPassword123!";

    let user = create_user(
        &admin,
        UserCreateBuilder::default()
            .name(format!("usr_{}", Uuid::new_v4().simple()))
            .domain_id("default")
            .enabled(true)
            .password(password)
            .build()?,
    )
    .await?;

    let project = create_project(
        &admin,
        ProjectCreateBuilder::default()
            .domain_id("default")
            .parent_id("default")
            .name(format!("prj_{}", Uuid::new_v4().simple()))
            .is_domain(false)
            .enabled(true)
            .build()?,
    )
    .await?;

    let roles: HashMap<String, String> = list_roles(&admin)
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let member = roles.get("member").expect("member role must exist");
    add_project_grant(&admin, &project.id, &user.id, member).await?;

    let (cred_id, _) = create_app_cred_for_user(
        &user.id,
        &user.name,
        password,
        &user.domain_id,
        &project.id,
        "default",
        "correct_secret",
        &[serde_json::json!({"id": member, "name": "member"})],
    )
    .await?;

    let result = auth_token(
        &admin,
        app_cred_identity_by_id(&cred_id, "wrong_secret"),
        None,
    )
    .await;

    assert!(result.is_err(), "wrong secret must be rejected");

    user.delete().await?;
    project.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_auth_by_application_credential_nonexistent() -> Result<()> {
    let admin = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let result = auth_token(
        &admin,
        app_cred_identity_by_id("totally_nonexistent_id", "any_secret"),
        None,
    )
    .await;

    assert!(result.is_err(), "nonexistent credential must be rejected");
    Ok(())
}

#[tokio::test]
async fn test_auth_by_application_credential_disabled_user() -> Result<()> {
    let admin = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let password = "TestPassword123!";

    let user = create_user(
        &admin,
        UserCreateBuilder::default()
            .name(format!("usr_{}", Uuid::new_v4().simple()))
            .domain_id("default")
            .enabled(true)
            .password(password)
            .build()?,
    )
    .await?;

    let project = create_project(
        &admin,
        ProjectCreateBuilder::default()
            .domain_id("default")
            .parent_id("default")
            .name(format!("prj_{}", Uuid::new_v4().simple()))
            .is_domain(false)
            .enabled(true)
            .build()?,
    )
    .await?;

    let roles: HashMap<String, String> = list_roles(&admin)
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let member = roles.get("member").expect("member role must exist");
    add_project_grant(&admin, &project.id, &user.id, member).await?;

    let app_cred_secret = "disabled_user_secret";
    let (cred_id, _) = create_app_cred_for_user(
        &user.id,
        &user.name,
        password,
        &user.domain_id,
        &project.id,
        "default",
        app_cred_secret,
        &[serde_json::json!({"id": member, "name": "member"})],
    )
    .await?;

    // Disable the user
    test_api::identity::user::update_user(
        &admin,
        &user.id,
        openstack_keystone_api_types::v3::user::UserUpdateBuilder::default()
            .enabled(false)
            .build()?,
    )
    .await?;

    let result = auth_token(
        &admin,
        app_cred_identity_by_id(&cred_id, app_cred_secret),
        None,
    )
    .await;

    assert!(result.is_err(), "disabled user must be rejected");

    // Re-enable for cleanup
    test_api::identity::user::update_user(
        &admin,
        &user.id,
        openstack_keystone_api_types::v3::user::UserUpdateBuilder::default()
            .enabled(true)
            .build()?,
    )
    .await?;

    user.delete().await?;
    project.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_auth_by_application_credential_disabled_project() -> Result<()> {
    let admin = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let password = "TestPassword123!";

    let user = create_user(
        &admin,
        UserCreateBuilder::default()
            .name(format!("usr_{}", Uuid::new_v4().simple()))
            .domain_id("default")
            .enabled(true)
            .password(password)
            .build()?,
    )
    .await?;

    let project = create_project(
        &admin,
        ProjectCreateBuilder::default()
            .domain_id("default")
            .parent_id("default")
            .name(format!("prj_{}", Uuid::new_v4().simple()))
            .is_domain(false)
            .enabled(true)
            .build()?,
    )
    .await?;

    let roles: HashMap<String, String> = list_roles(&admin)
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let member = roles.get("member").expect("member role must exist");
    add_project_grant(&admin, &project.id, &user.id, member).await?;

    let app_cred_secret = "disabled_project_secret";
    let (cred_id, _) = create_app_cred_for_user(
        &user.id,
        &user.name,
        password,
        &user.domain_id,
        &project.id,
        "default",
        app_cred_secret,
        &[serde_json::json!({"id": member, "name": "member"})],
    )
    .await?;

    // Disable the project
    test_api::resource::project::update_project(
        &admin,
        &project.id,
        openstack_keystone_api_types::v3::project::ProjectUpdateBuilder::default()
            .enabled(false)
            .build()?,
    )
    .await?;

    let result = auth_token(
        &admin,
        app_cred_identity_by_id(&cred_id, app_cred_secret),
        None,
    )
    .await;

    assert!(result.is_err(), "disabled project must be rejected");

    // Re-enable for cleanup
    test_api::resource::project::update_project(
        &admin,
        &project.id,
        openstack_keystone_api_types::v3::project::ProjectUpdateBuilder::default()
            .enabled(true)
            .build()?,
    )
    .await?;

    user.delete().await?;
    project.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_auth_by_application_credential_disabled_domain() -> Result<()> {
    let admin = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let password = "TestPassword123!";

    let domain = test_api::resource::domain::create_domain(
        &admin,
        openstack_keystone_api_types::v3::domain::DomainCreateBuilder::default()
            .name(format!("dom_{}", Uuid::new_v4().simple()))
            .enabled(true)
            .build()?,
    )
    .await?;

    let user = create_user(
        &admin,
        UserCreateBuilder::default()
            .name(format!("usr_{}", Uuid::new_v4().simple()))
            .domain_id(&domain.id)
            .enabled(true)
            .password(password)
            .build()?,
    )
    .await?;

    let project = create_project(
        &admin,
        ProjectCreateBuilder::default()
            .domain_id(&domain.id)
            .parent_id(&domain.id)
            .name(format!("prj_{}", Uuid::new_v4().simple()))
            .is_domain(false)
            .enabled(true)
            .build()?,
    )
    .await?;

    let roles: HashMap<String, String> = list_roles(&admin)
        .await?
        .into_iter()
        .map(|r| (r.name, r.id))
        .collect();
    let member = roles.get("member").expect("member role must exist");
    add_project_grant(&admin, &project.id, &user.id, member).await?;

    let app_cred_secret = "disabled_domain_secret";
    let (cred_id, _) = create_app_cred_for_user(
        &user.id,
        &user.name,
        password,
        &domain.id,
        &project.id,
        &domain.id,
        app_cred_secret,
        &[serde_json::json!({"id": member, "name": "member"})],
    )
    .await?;

    // Disable the domain
    test_api::resource::domain::update_domain(
        &admin,
        &domain.id,
        openstack_keystone_api_types::v3::domain::DomainUpdateBuilder::default()
            .enabled(false)
            .build()?,
    )
    .await?;

    let result = auth_token(
        &admin,
        app_cred_identity_by_id(&cred_id, app_cred_secret),
        None,
    )
    .await;

    assert!(result.is_err(), "disabled domain must be rejected");

    // Re-enable for cleanup
    test_api::resource::domain::update_domain(
        &admin,
        &domain.id,
        openstack_keystone_api_types::v3::domain::DomainUpdateBuilder::default()
            .enabled(true)
            .build()?,
    )
    .await?;

    user.delete().await?;
    project.delete().await?;
    domain.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_auth_by_application_credential_raw_401() -> Result<()> {
    let body = serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["application_credential"],
                "application_credential": {
                    "id": "nonexistent",
                    "secret": "bad_secret"
                }
            }
        }
    });

    let rsp = common::raw_request(http::Method::POST, "v3/auth/tokens", None, Some(body)).await?;

    assert_eq!(
        rsp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "must return 401 for invalid application credential"
    );

    Ok(())
}
