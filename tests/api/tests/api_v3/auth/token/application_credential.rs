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
use test_api::guard::{AsyncResourceGuard, ResourceGuard};
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

/// User credentials and scope used to create an application credential.
struct AppCredOwner<'a> {
    user_id: &'a str,
    user_name: &'a str,
    password: &'a str,
    user_domain_id: &'a str,
    project_id: &'a str,
    project_domain_id: &'a str,
}

/// Authenticate the user with password, then create an application credential
/// via raw HTTP, sending the secret only when given. Returns the creation
/// response.
async fn create_app_cred_raw(
    owner: &AppCredOwner<'_>,
    app_cred_secret: Option<&str>,
    roles: &[serde_json::Value],
) -> Result<serde_json::Value> {
    let mut tc = common::TestClient::new()?;
    tc.auth_password(
        common::get_password_auth(owner.user_name, owner.password, owner.user_domain_id)?,
        Some(Scope::Project(
            ScopeProjectBuilder::default()
                .id(owner.project_id)
                .domain(
                    DomainBuilder::default()
                        .id(owner.project_domain_id)
                        .build()?,
                )
                .build()?,
        )),
    )
    .await?;

    let mut create_body = serde_json::json!({
        "application_credential": {
            "name": format!("ac_{}", Uuid::new_v4().simple()),
            "roles": roles,
        }
    });
    if let Some(secret) = app_cred_secret {
        create_body["application_credential"]["secret"] = secret.into();
    }
    let rsp = common::raw_request(
        http::Method::POST,
        &format!("v3/users/{}/application_credentials", owner.user_id),
        Some(tc.token.as_ref().unwrap().expose_secret()),
        Some(create_body),
    )
    .await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::CREATED);
    Ok(rsp.json().await?)
}

/// Create an application credential with the given secret. Returns the
/// credential ID and name.
async fn create_app_cred_for_user(
    owner: &AppCredOwner<'_>,
    app_cred_secret: &str,
    roles: &[serde_json::Value],
) -> Result<(String, String)> {
    let cred_resp = create_app_cred_raw(owner, Some(app_cred_secret), roles).await?;
    let cred = &cred_resp["application_credential"];
    Ok((
        cred["id"]
            .as_str()
            .expect("app cred id must be present")
            .to_string(),
        cred["name"]
            .as_str()
            .expect("app cred name must be present")
            .to_string(),
    ))
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
        &AppCredOwner {
            user_id: &user.id,
            user_name: &user.name,
            password,
            user_domain_id: &user.domain_id,
            project_id: &project.id,
            project_domain_id: "default",
        },
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

    let mut tc = common::TestClient::new()?;
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
        &AppCredOwner {
            user_id: &user.id,
            user_name: &user.name,
            password,
            user_domain_id: &user.domain_id,
            project_id: &project.id,
            project_domain_id: "default",
        },
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
        &AppCredOwner {
            user_id: &user.id,
            user_name: &user.name,
            password,
            user_domain_id: &user.domain_id,
            project_id: &project.id,
            project_domain_id: "default",
        },
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
        &AppCredOwner {
            user_id: &user.id,
            user_name: &user.name,
            password,
            user_domain_id: &user.domain_id,
            project_id: &project.id,
            project_domain_id: "default",
        },
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
        &AppCredOwner {
            user_id: &user.id,
            user_name: &user.name,
            password,
            user_domain_id: &domain.id,
            project_id: &project.id,
            project_domain_id: &domain.id,
        },
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

/// Create a user with a member role grant on a fresh project, plus an
/// application credential of that user. Returns the guards of the created
/// resources, the credential ID and name.
async fn setup_user_with_app_cred(
    secret: &str,
) -> Result<(
    AsyncResourceGuard<openstack_keystone_api_types::v3::user::User>,
    AsyncResourceGuard<openstack_keystone_api_types::v3::project::Project>,
    String,
    String,
)> {
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
    let (cred_id, cred_name) = create_app_cred_for_user(
        &AppCredOwner {
            user_id: &user.id,
            user_name: &user.name,
            password,
            user_domain_id: &user.domain_id,
            project_id: &project.id,
            project_domain_id: "default",
        },
        secret,
        &[serde_json::json!({"id": member, "name": "member"})],
    )
    .await?;
    Ok((user, project, cred_id, cred_name))
}

#[tokio::test]
async fn test_auth_by_application_credential_explicit_scope_forbidden() -> Result<()> {
    let secret = "scope_forbidden_secret";
    let (user, project, cred_id, _) = setup_user_with_app_cred(secret).await?;

    // Requesting a scope is prohibited, even the credential's own project.
    let body = serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["application_credential"],
                "application_credential": {"id": &cred_id, "secret": secret}
            },
            "scope": {"project": {"id": &project.id}}
        }
    });
    let rsp = common::raw_request(http::Method::POST, "v3/auth/tokens", None, Some(body)).await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::FORBIDDEN);

    // A token obtained with the credential cannot be exchanged with a scope.
    let body = serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["application_credential"],
                "application_credential": {"id": &cred_id, "secret": secret}
            }
        }
    });
    let rsp = common::raw_request(http::Method::POST, "v3/auth/tokens", None, Some(body)).await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::CREATED);
    let token = rsp
        .headers()
        .get("X-Subject-Token")
        .expect("token header")
        .to_str()?
        .to_string();
    let body = serde_json::json!({
        "auth": {
            "identity": {"methods": ["token"], "token": {"id": &token}},
            "scope": {"project": {"id": &project.id}}
        }
    });
    let rsp = common::raw_request(http::Method::POST, "v3/auth/tokens", None, Some(body)).await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::FORBIDDEN);

    user.delete().await?;
    project.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_auth_by_application_credential_foreign_user_rejected() -> Result<()> {
    let secret = "foreign_user_secret";
    let (user, project, cred_id, _) = setup_user_with_app_cred(secret).await?;

    let body = serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["application_credential"],
                "application_credential": {
                    "id": &cred_id,
                    "secret": secret,
                    "user": {"id": "some_other_user_id"}
                }
            }
        }
    });
    let rsp = common::raw_request(http::Method::POST, "v3/auth/tokens", None, Some(body)).await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::UNAUTHORIZED);

    user.delete().await?;
    project.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_auth_by_application_credential_name_with_user_name_and_domain() -> Result<()> {
    let secret = "by_user_name_secret";
    let (user, project, _, cred_name) = setup_user_with_app_cred(secret).await?;

    let body = serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["application_credential"],
                "application_credential": {
                    "name": &cred_name,
                    "secret": secret,
                    "user": {"name": &user.name, "domain": {"id": "default"}}
                }
            }
        }
    });
    let rsp = common::raw_request(http::Method::POST, "v3/auth/tokens", None, Some(body)).await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::CREATED);
    let token_resp: serde_json::Value = rsp.json().await?;
    assert_eq!(token_resp["token"]["user"]["id"].as_str().unwrap(), user.id);

    user.delete().await?;
    project.delete().await?;
    Ok(())
}

/// The secret is generated when the creation request does not carry one (same
/// as python keystone), is returned in the response and authenticates.
#[tokio::test]
async fn test_auth_by_application_credential_generated_secret() -> Result<()> {
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

    let cred_resp = create_app_cred_raw(
        &AppCredOwner {
            user_id: &user.id,
            user_name: &user.name,
            password,
            user_domain_id: &user.domain_id,
            project_id: &project.id,
            project_domain_id: "default",
        },
        None,
        &[serde_json::json!({"id": member, "name": "member"})],
    )
    .await?;
    let cred = &cred_resp["application_credential"];
    let cred_id = cred["id"].as_str().expect("id").to_string();
    let cred_name = cred["name"].as_str().expect("name").to_string();
    let secret = cred["secret"]
        .as_str()
        .expect("a generated secret must be returned on creation")
        .to_string();
    assert!(!secret.is_empty());

    let authenticate = |identity: serde_json::Value| async move {
        common::raw_request(
            http::Method::POST,
            "v3/auth/tokens",
            None,
            Some(serde_json::json!({
                "auth": {
                    "identity": {
                        "methods": ["application_credential"],
                        "application_credential": identity
                    }
                }
            })),
        )
        .await
    };

    // By ID.
    let rsp = authenticate(serde_json::json!({"id": &cred_id, "secret": &secret})).await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::CREATED);
    let token_resp: serde_json::Value = rsp.json().await?;
    assert_eq!(token_resp["token"]["user"]["id"].as_str().unwrap(), user.id);

    // By name.
    let rsp = authenticate(serde_json::json!({
        "name": &cred_name,
        "secret": &secret,
        "user": {"id": &user.id}
    }))
    .await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::CREATED);

    // A modified secret is rejected. The first character is modified: bcrypt
    // only considers the first 72 bytes and the generated secret is longer.
    let flipped = format!(
        "{}{}",
        if secret.starts_with('A') { 'B' } else { 'A' },
        &secret[1..]
    );
    let rsp = authenticate(serde_json::json!({
        "id": &cred_id,
        "secret": flipped
    }))
    .await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::UNAUTHORIZED);

    user.delete().await?;
    project.delete().await?;
    Ok(())
}

/// Obtain a token with the application credential, no scope in the request.
async fn app_cred_token(cred_id: &str, secret: &str) -> Result<(String, serde_json::Value)> {
    let body = serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["application_credential"],
                "application_credential": {"id": cred_id, "secret": secret}
            }
        }
    });
    let rsp = common::raw_request(http::Method::POST, "v3/auth/tokens", None, Some(body)).await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::CREATED);
    let token = rsp
        .headers()
        .get("X-Subject-Token")
        .expect("token header")
        .to_str()?
        .to_string();
    Ok((token, rsp.json().await?))
}

#[tokio::test]
async fn test_auth_by_application_credential_other_project_forbidden() -> Result<()> {
    let secret = "other_project_secret";
    let (user, project, cred_id, _) = setup_user_with_app_cred(secret).await?;

    // Another existing project the user is granted a role on.
    let admin = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let other = create_project(
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
    add_project_grant(
        &admin,
        &other.id,
        &user.id,
        roles.get("member").expect("member role must exist"),
    )
    .await?;

    // Scope in the authentication request, other project.
    let body = serde_json::json!({
        "auth": {
            "identity": {
                "methods": ["application_credential"],
                "application_credential": {"id": &cred_id, "secret": secret}
            },
            "scope": {"project": {"id": &other.id}}
        }
    });
    let rsp = common::raw_request(http::Method::POST, "v3/auth/tokens", None, Some(body)).await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::FORBIDDEN);

    // Rescope by token to the other project.
    let (token, _) = app_cred_token(&cred_id, secret).await?;
    let body = serde_json::json!({
        "auth": {
            "identity": {"methods": ["token"], "token": {"id": &token}},
            "scope": {"project": {"id": &other.id}}
        }
    });
    let rsp = common::raw_request(http::Method::POST, "v3/auth/tokens", None, Some(body)).await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::FORBIDDEN);

    // Rescope by token to the default domain.
    let body = serde_json::json!({
        "auth": {
            "identity": {"methods": ["token"], "token": {"id": &token}},
            "scope": {"domain": {"id": "default"}}
        }
    });
    let rsp = common::raw_request(http::Method::POST, "v3/auth/tokens", None, Some(body)).await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::FORBIDDEN);

    other.delete().await?;
    user.delete().await?;
    project.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_auth_by_application_credential_token_reauth_keeps_expiry() -> Result<()> {
    let secret = "reauth_expiry_secret";
    let (user, project, cred_id, _) = setup_user_with_app_cred(secret).await?;

    let (token, first) = app_cred_token(&cred_id, secret).await?;
    let first_expires = first["token"]["expires_at"]
        .as_str()
        .expect("expires_at")
        .to_string();

    // Ensure a freshly computed expiration would differ.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let body = serde_json::json!({
        "auth": {"identity": {"methods": ["token"], "token": {"id": &token}}}
    });
    let rsp = common::raw_request(http::Method::POST, "v3/auth/tokens", None, Some(body)).await?;
    assert_eq!(rsp.status(), reqwest::StatusCode::CREATED);
    let second: serde_json::Value = rsp.json().await?;
    // Token payloads keep second precision only: compare up to the seconds.
    let second_expires = second["token"]["expires_at"].as_str().expect("expires_at");
    assert_eq!(
        &second_expires[..19],
        &first_expires[..19],
        "the token obtained by re-authentication must inherit the expiration"
    );
    assert_eq!(
        second["token"]["project"]["id"].as_str(),
        Some(project.id.as_str())
    );

    user.delete().await?;
    project.delete().await?;
    Ok(())
}
