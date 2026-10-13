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
//! Live-server TOTP second factor on the OP login page (ADR 0026 §8): the
//! `authorization_code` flow (`POST /authorize/mfa`) and the device flow
//! (`POST /device/mfa`).

use eyre::{Result, eyre};
use reqwest::StatusCode;
use serde_json::json;
use tracing_test::traced_test;

use openstack_keystone_api_types::v4::oauth2_client::GrantType;
use test_api::oauth2::{
    DeviceBrowserSession, extract_hidden_value, poll_device_token, register_client,
    start_device_authorization,
};
use test_api::oauth2_browser::*;

struct Fixture {
    domain_id: String,
    client: BrowserClient,
    username: String,
    seed: String,
}

async fn fixture() -> Result<Fixture> {
    let domain_id = create_ready_domain("mfa").await?;
    let client = create_browser_client(&domain_id, json!({})).await?;
    let (user_id, username) = create_browser_user(&domain_id).await?;
    let seed = enroll_totp(&user_id).await?;
    Ok(Fixture {
        domain_id,
        client,
        username,
        seed,
    })
}

/// Authorize + password login; returns the browser and the MFA page.
async fn to_mfa(
    f: &Fixture,
) -> Result<(AuthorizeBrowser, AuthorizeParams, String, BrowserResponse)> {
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, verifier) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params).await?;
    let rsp = browser.login(&rsp.csrf()?, &f.username, PASSWORD).await?;
    Ok((browser, params, verifier, rsp))
}

#[tokio::test]
#[traced_test]
async fn test_totp_user_gets_mfa_step_and_amr_otp() -> Result<()> {
    let f = fixture().await?;
    let (browser, params, verifier, rsp) = to_mfa(&f).await?;
    assert!(rsp.is_mfa(), "{}: {}", rsp.status, rsp.body);
    assert!(rsp.location_param("code").is_none());

    let rsp = browser.mfa(&rsp.csrf()?, &totp_now(&f.seed)?).await?;
    assert!(rsp.is_consent(), "{}: {}", rsp.status, rsp.body);
    let rsp = browser.consent(&rsp.csrf()?, "allow", false).await?;
    let code = rsp
        .location_param("code")
        .ok_or_else(|| eyre!("no code: {:?}", rsp.location()))?;

    let (status, body) = exchange_code(&f.domain_id, &f.client.client_id, &code, &verifier).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let claims = jwt_claims(body["id_token"].as_str().unwrap_or_default())?;
    let amr = claims["amr"].as_array().cloned().unwrap_or_default();
    assert!(
        amr.iter().any(|v| v == "otp"),
        "amr must contain otp: {claims}"
    );
    assert!(
        amr.iter().any(|v| v == "pwd"),
        "amr must contain pwd: {claims}"
    );
    assert_eq!(
        Some(claims["nonce"].as_str()),
        Some(params.nonce.as_deref())
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_wrong_totp_code_is_rejected_and_form_rerendered() -> Result<()> {
    let f = fixture().await?;
    let (browser, _, _, rsp) = to_mfa(&f).await?;
    let rsp = browser.mfa(&rsp.csrf()?, &totp_wrong(&f.seed)?).await?;
    assert!(rsp.location_param("code").is_none());
    assert!(!rsp.is_consent(), "{}", rsp.body);
    assert!(rsp.is_mfa(), "{}: {}", rsp.status, rsp.body);

    // The right code still works afterwards (within the attempt budget).
    let rsp = browser.mfa(&rsp.csrf()?, &totp_now(&f.seed)?).await?;
    assert!(rsp.is_consent(), "{}: {}", rsp.status, rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_totp_attempts_are_capped() -> Result<()> {
    let f = fixture().await?;
    let (browser, _, _, mut rsp) = to_mfa(&f).await?;
    let wrong = totp_wrong(&f.seed)?;
    // Default `mfa_max_attempts` is 5: burn well past it.
    for _ in 0..8 {
        if !rsp.is_mfa() {
            break;
        }
        rsp = browser.mfa(&rsp.csrf()?, &wrong).await?;
    }
    assert!(!rsp.is_mfa(), "form must stop being offered: {}", rsp.body);
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST, "{}", rsp.body);

    // The pending sign-in is discarded: even the right code is refused now.
    let csrf = extract_hidden_value(&rsp.body, "csrf_token").unwrap_or_default();
    let rsp = browser.mfa(&csrf, &totp_now(&f.seed)?).await?;
    assert!(rsp.location_param("code").is_none());
    assert!(!rsp.is_consent(), "{}", rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_mfa_without_password_step_is_rejected() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params).await?;
    // Skip the password step and go straight to the second factor.
    let rsp = browser.mfa(&rsp.csrf()?, &totp_now(&f.seed)?).await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST, "{}", rsp.body);
    assert!(rsp.location_param("code").is_none());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_user_without_totp_skips_mfa() -> Result<()> {
    let f = fixture().await?;
    let (_id, plain) = create_browser_user(&f.domain_id).await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params).await?;
    let rsp = browser.login(&rsp.csrf()?, &plain, PASSWORD).await?;
    assert!(rsp.is_consent(), "{}: {}", rsp.status, rsp.body);
    Ok(())
}

// ---- device flow -----------------------------------------------------------

#[tokio::test]
#[traced_test]
async fn test_device_flow_totp_step() -> Result<()> {
    let f = fixture().await?;
    let (client_id, _) = register_client(
        &f.domain_id,
        &format!("device-mfa-{}", uuid::Uuid::new_v4().simple()),
        vec![GrantType::DeviceCode],
        vec!["openid".to_string()],
        false,
    )
    .await?;

    let start = start_device_authorization(&f.domain_id, &client_id, Some("openid")).await?;
    let session = DeviceBrowserSession::new(&f.domain_id)?;
    let (_, login_html) = session.submit_user_code(&start.user_code).await?;
    let csrf = extract_hidden_value(&login_html, "csrf_token")
        .ok_or_else(|| eyre!("no csrf in login page"))?;
    let (status, mfa_html) = session.submit_login(&csrf, &f.username, PASSWORD).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(mfa_html.contains("name=\"passcode\""), "{mfa_html}");

    // Wrong code first: refused, no grant.
    let csrf = extract_hidden_value(&mfa_html, "csrf_token").unwrap_or_default();
    let (_, again) = session.submit_mfa(&csrf, &totp_wrong(&f.seed)?).await?;
    assert!(again.contains("name=\"passcode\""), "{again}");
    assert!(!again.contains("name=\"decision\""));

    let csrf = extract_hidden_value(&again, "csrf_token").unwrap_or_default();
    let (status, consent_html) = session.submit_mfa(&csrf, &totp_now(&f.seed)?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(consent_html.contains("name=\"decision\""), "{consent_html}");
    let csrf = extract_hidden_value(&consent_html, "csrf_token").unwrap_or_default();
    session.submit_consent(&csrf, "allow").await?;

    let (status, body) = poll_device_token(&f.domain_id, &client_id, &start.device_code).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    if let Some(id) = body["id_token"].as_str() {
        let claims = jwt_claims(id)?;
        assert!(
            claims["amr"]
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v == "otp")),
            "{claims}"
        );
    }
    Ok(())
}
