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
//! Live-server remembered consent and the per-user consents API.

use eyre::{Result, eyre};
use reqwest::{Method, StatusCode};
use serde_json::json;
use tracing_test::traced_test;

use test_api::common::TestClient;
use test_api::oauth2_browser::*;

struct Fixture {
    domain_id: String,
    client: BrowserClient,
    user_id: String,
    username: String,
}

async fn fixture() -> Result<Fixture> {
    let domain_id = create_ready_domain("consent").await?;
    let client = create_browser_client(&domain_id, json!({})).await?;
    let (user_id, username) = create_browser_user(&domain_id).await?;
    Ok(Fixture {
        domain_id,
        client,
        user_id,
        username,
    })
}

/// Run an authorization request in a fresh browser (no SSO session) up to
/// the point after login; returns that response.
async fn after_login(f: &Fixture, scope: &str) -> Result<BrowserResponse> {
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (mut params, _) = AuthorizeParams::new(&f.client.client_id);
    params.scope = scope.to_string();
    let rsp = browser.authorize(&params).await?;
    assert!(rsp.is_login(), "{}: {}", rsp.status, rsp.body);
    browser.login(&rsp.csrf()?, &f.username, PASSWORD).await
}

/// Approve `scope` once and ask the server to remember it.
async fn remember(f: &Fixture, scope: &str) -> Result<()> {
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (mut params, _) = AuthorizeParams::new(&f.client.client_id);
    params.scope = scope.to_string();
    let rsp = browser
        .complete(&params, &f.username, PASSWORD, true)
        .await?;
    assert!(rsp.location_param("code").is_some(), "{}", rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_remembered_consent_is_skipped_next_time() -> Result<()> {
    let f = fixture().await?;
    remember(&f, "openid").await?;

    let rsp = after_login(&f, "openid").await?;
    assert!(!rsp.is_consent(), "consent asked again: {}", rsp.body);
    assert!(rsp.location_param("code").is_some(), "{:?}", rsp.location());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_consent_not_remembered_without_opt_in() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser
        .complete(&params, &f.username, PASSWORD, false)
        .await?;
    assert!(rsp.location_param("code").is_some());

    let rsp = after_login(&f, "openid").await?;
    assert!(rsp.is_consent(), "{}: {}", rsp.status, rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_wider_scope_asks_for_consent_again() -> Result<()> {
    let f = fixture().await?;
    remember(&f, "openid").await?;

    let rsp = after_login(&f, "openid profile").await?;
    assert!(rsp.is_consent(), "{}: {}", rsp.status, rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_consent_is_per_user() -> Result<()> {
    let f = fixture().await?;
    remember(&f, "openid").await?;

    let (_, other_name) = create_browser_user(&f.domain_id).await?;
    let other = Fixture {
        domain_id: f.domain_id.clone(),
        client: BrowserClient {
            client_id: f.client.client_id.clone(),
            provider_id: f.client.provider_id.clone(),
            client_secret: None,
        },
        user_id: String::new(),
        username: other_name,
    };
    let rsp = after_login(&other, "openid").await?;
    assert!(rsp.is_consent(), "{}: {}", rsp.status, rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_user_lists_and_withdraws_own_consent() -> Result<()> {
    let f = fixture().await?;
    remember(&f, "openid").await?;
    let token = user_token(&f.domain_id, &f.username, PASSWORD, None).await?;

    let (status, body) = consents_call(Method::GET, &f.user_id, None, Some(&token)).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let consent = body["consents"]
        .as_array()
        .and_then(|l| {
            l.iter()
                .find(|c| c["client_id"] == f.client.client_id.as_str())
        })
        .ok_or_else(|| eyre!("consent missing in {body}"))?;
    assert_eq!(consent["scopes"], json!(["openid"]));

    let (status, body) = consents_call(
        Method::DELETE,
        &f.user_id,
        Some(&f.client.client_id),
        Some(&token),
    )
    .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (_, body) = consents_call(Method::GET, &f.user_id, None, Some(&token)).await?;
    assert!(
        body["consents"].as_array().is_some_and(|l| l
            .iter()
            .all(|c| c["client_id"] != f.client.client_id.as_str())),
        "{body}"
    );

    // Withdrawn: consent is asked again.
    let rsp = after_login(&f, "openid").await?;
    assert!(rsp.is_consent(), "{}: {}", rsp.status, rsp.body);

    // Nothing left to withdraw.
    let (status, _) = consents_call(
        Method::DELETE,
        &f.user_id,
        Some(&f.client.client_id),
        Some(&token),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_consents_of_another_user_are_denied() -> Result<()> {
    let f = fixture().await?;
    remember(&f, "openid").await?;
    let (_, other_name) = create_browser_user(&f.domain_id).await?;
    let other = user_token(&f.domain_id, &other_name, PASSWORD, None).await?;

    let (status, _) = consents_call(Method::GET, &f.user_id, None, Some(&other)).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = consents_call(
        Method::DELETE,
        &f.user_id,
        Some(&f.client.client_id),
        Some(&other),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = consents_call(Method::GET, &f.user_id, None, None).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) =
        consents_call(Method::DELETE, &f.user_id, Some(&f.client.client_id), None).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Still there for the owner.
    let token = user_token(&f.domain_id, &f.username, PASSWORD, None).await?;
    let (_, body) = consents_call(Method::GET, &f.user_id, None, Some(&token)).await?;
    assert!(
        body["consents"].as_array().is_some_and(|l| l
            .iter()
            .any(|c| c["client_id"] == f.client.client_id.as_str())),
        "{body}"
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_admin_can_list_and_withdraw_consent() -> Result<()> {
    let f = fixture().await?;
    remember(&f, "openid").await?;
    let mut admin = TestClient::new()?;
    admin.auth_admin_system().await?;
    let token = {
        use secrecy::ExposeSecret;
        admin
            .token
            .as_ref()
            .ok_or_else(|| eyre!("admin has no token"))?
            .expose_secret()
            .to_string()
    };

    let (status, body) = consents_call(Method::GET, &f.user_id, None, Some(&token)).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = consents_call(
        Method::DELETE,
        &f.user_id,
        Some(&f.client.client_id),
        Some(&token),
    )
    .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_delegated_token_cannot_manage_consents() -> Result<()> {
    let f = fixture().await?;
    remember(&f, "openid").await?;

    // The user holds a role on a project and delegates it through an
    // application credential.
    let (user_id, username, project_id) = project_role_user(&f.domain_id, "member").await?;
    let project_scoped = project_token(&f.domain_id, &username, &project_id).await?;
    let delegated = app_cred_token(&user_id, &project_scoped).await?;

    let (status, body) = consents_call(Method::GET, &user_id, None, Some(&delegated)).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = consents_call(
        Method::DELETE,
        &user_id,
        Some(&f.client.client_id),
        Some(&delegated),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    Ok(())
}
