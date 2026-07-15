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
//! Live-server walk through the RFC 8628 §3.3 device-grant browser
//! verification flow (`GET/POST /device`, `POST /device/login`,
//! `POST /device/consent`, ADR 0026 §7.C). `device.rs` (login/consent HTML
//! rendering) has no coverage anywhere else in the repo -- this is the only
//! place the consent dialog's content (client identity + requested scopes,
//! the actual security-relevant thing the user reads before authorizing) is
//! ever asserted on.

use eyre::Result;
use reqwest::StatusCode;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v4::oauth2_client::GrantType;

use test_api::oauth2::*;

#[tokio::test]
#[traced_test]
async fn test_device_browser_full_flow_grants_and_polls_succeed() -> Result<()> {
    let provider_id = format!("device-browser-test-{}", Uuid::new_v4().simple());
    let (client_id, _secret) = register_client(
        "default",
        &provider_id,
        vec![GrantType::DeviceCode],
        vec!["openid".to_string()],
        false,
    )
    .await?;

    let username = format!("device-browser-user-{}", Uuid::new_v4().simple());
    let password = "S3cur3P@ssw0rd!";
    create_test_user("default", &username, password).await?;

    let start = start_device_authorization("default", &client_id, Some("openid")).await?;

    // No pre-consent poll here (unlike other tests): the RFC 8628 §3.5
    // `interval` slow-down check compares against the *previous* poll
    // regardless of the grant's terminal state, so an early poll here would
    // start that clock and could make the post-consent poll below spuriously
    // get `slow_down` instead of the access token. `authorization_pending`
    // is covered independently by `token_device_grant.rs`.
    let session = DeviceBrowserSession::new("default")?;

    let (status, entry_html) = session.get_entry().await?;
    assert_eq!(status, StatusCode::OK);
    assert!(entry_html.contains("user_code"));

    let (status, login_html) = session.submit_user_code(&start.user_code).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        login_html.contains(&client_id),
        "login page must display the requesting client's identity: {login_html}"
    );
    let login_csrf = extract_hidden_value(&login_html, "csrf_token")
        .expect("login form must carry a csrf_token");

    let (status, consent_html) = session
        .submit_login(&login_csrf, &username, password)
        .await?;
    assert_eq!(status, StatusCode::OK);
    // Consent dialog security check: the user must be shown which client is
    // asking and exactly which scopes it is requesting before approving.
    assert!(
        consent_html.contains(&client_id),
        "consent page must display the requesting client's identity: {consent_html}"
    );
    assert!(
        consent_html.contains("openid"),
        "consent page must display the requested scope(s): {consent_html}"
    );
    let consent_csrf = extract_hidden_value(&consent_html, "csrf_token")
        .expect("consent form must carry a csrf_token");

    let (status, result_html) = session.submit_consent(&consent_csrf, "allow").await?;
    assert_eq!(status, StatusCode::OK);
    assert!(result_html.contains("Device connected"));

    let (status, body) = poll_device_token("default", &client_id, &start.device_code).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(body["access_token"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(body["id_token"].as_str().is_some_and(|s| !s.is_empty()));

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_device_browser_deny_consent_polls_access_denied() -> Result<()> {
    let provider_id = format!("device-browser-deny-test-{}", Uuid::new_v4().simple());
    let (client_id, _secret) = register_client(
        "default",
        &provider_id,
        vec![GrantType::DeviceCode],
        vec!["openid".to_string()],
        false,
    )
    .await?;

    let username = format!("device-browser-deny-user-{}", Uuid::new_v4().simple());
    let password = "S3cur3P@ssw0rd!";
    create_test_user("default", &username, password).await?;

    let start = start_device_authorization("default", &client_id, Some("openid")).await?;

    let session = DeviceBrowserSession::new("default")?;
    session.get_entry().await?;
    let (_, login_html) = session.submit_user_code(&start.user_code).await?;
    let login_csrf = extract_hidden_value(&login_html, "csrf_token")
        .expect("login form must carry a csrf_token");
    let (_, consent_html) = session
        .submit_login(&login_csrf, &username, password)
        .await?;
    let consent_csrf = extract_hidden_value(&consent_html, "csrf_token")
        .expect("consent form must carry a csrf_token");

    let (status, result_html) = session.submit_consent(&consent_csrf, "deny").await?;
    assert_eq!(status, StatusCode::OK);
    assert!(result_html.contains("Request denied"));

    let (status, body) = poll_device_token("default", &client_id, &start.device_code).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "access_denied");

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_device_browser_wrong_user_code_shows_error_not_500() -> Result<()> {
    let session = DeviceBrowserSession::new("default")?;
    let (status, html) = session.submit_user_code("ZZZZ-ZZZZ").await?;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("invalid or expired code"));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_device_browser_wrong_password_rejected_without_consuming_code() -> Result<()> {
    let provider_id = format!("device-browser-badpw-test-{}", Uuid::new_v4().simple());
    let (client_id, _secret) = register_client(
        "default",
        &provider_id,
        vec![GrantType::DeviceCode],
        vec!["openid".to_string()],
        false,
    )
    .await?;

    let username = format!("device-browser-badpw-user-{}", Uuid::new_v4().simple());
    create_test_user("default", &username, "S3cur3P@ssw0rd!").await?;

    let start = start_device_authorization("default", &client_id, Some("openid")).await?;

    let session = DeviceBrowserSession::new("default")?;
    session.get_entry().await?;
    let (_, login_html) = session.submit_user_code(&start.user_code).await?;
    let login_csrf = extract_hidden_value(&login_html, "csrf_token")
        .expect("login form must carry a csrf_token");

    let (status, retry_html) = session
        .submit_login(&login_csrf, &username, "totally-wrong-password")
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(retry_html.contains("invalid username or password"));

    // The device_code must still be usable -- a failed login attempt must
    // not have consumed/invalidated the grant.
    let (status, body) = poll_device_token("default", &client_id, &start.device_code).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "authorization_pending");

    Ok(())
}
