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
//! Device authorization grant (RFC 8628 §3.3) verification pages in a real
//! browser: code entry, login, consent and the result page.

use eyre::Result;
use serde_json::json;
use thirtyfour::prelude::*;
use tracing_test::traced_test;

use test_api::browser::*;
use test_api::oauth2::{
    DeviceAuthorizationResponse, poll_device_token, start_device_authorization,
};
use test_api::oauth2_browser::*;

struct Fixture {
    domain_id: String,
    client: BrowserClient,
    username: String,
    start: DeviceAuthorizationResponse,
}

async fn fixture() -> Result<Fixture> {
    let domain_id = create_ready_domain("brwdev").await?;
    let client = create_browser_client(
        &domain_id,
        json!({
            "grant_types": ["device_code"],
            "allowed_scopes": ["openid"],
            "redirect_uris": [],
            "post_logout_redirect_uris": [],
        }),
    )
    .await?;
    let (_, username) = create_browser_user(&domain_id).await?;
    let start = start_device_authorization(&domain_id, &client.client_id, Some("openid")).await?;
    Ok(Fixture {
        domain_id,
        client,
        username,
        start,
    })
}

/// Code entry, login and consent page up to the decision.
async fn reach_consent(driver: &WebDriver, f: &Fixture) -> Result<()> {
    let device_url = base_url()?.join(&format!("v4/oauth2/{}/device", f.domain_id))?;
    driver.goto(device_url.as_str()).await?;
    wait_for(driver, By::Id("user_code"))
        .await?
        .send_keys(&f.start.user_code)
        .await?;
    driver
        .find(By::Css("button[type=submit]"))
        .await?
        .click()
        .await?;
    sign_in(driver, &f.username, PASSWORD).await?;
    // Consent must name the requested scope before the user decides.
    wait_for(driver, By::Css("button[name=decision][value=allow]")).await?;
    let html = driver.source().await?;
    assert!(html.contains("openid"), "{html}");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_browser_device_flow_allow() -> Result<()> {
    let f = fixture().await?;
    let driver = driver().await?;
    let res: Result<()> = async {
        reach_consent(&driver, &f).await?;
        allow_consent(&driver).await?;
        wait_for_text(&driver, "Device connected").await?;

        let (status, body) =
            poll_device_token(&f.domain_id, &f.client.client_id, &f.start.device_code).await?;
        assert!(status.is_success(), "{status}: {body}");
        assert!(body["access_token"].as_str().is_some_and(|s| !s.is_empty()));
        Ok(())
    }
    .await;
    driver.quit().await?;
    res
}

#[tokio::test]
#[traced_test]
async fn test_browser_device_flow_deny() -> Result<()> {
    let f = fixture().await?;
    let driver = driver().await?;
    let res: Result<()> = async {
        reach_consent(&driver, &f).await?;
        wait_for(&driver, By::Css("button[name=decision][value=deny]"))
            .await?
            .click()
            .await?;
        wait_for_text(&driver, "Request denied").await?;

        let (status, body) =
            poll_device_token(&f.domain_id, &f.client.client_id, &f.start.device_code).await?;
        assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "access_denied");
        Ok(())
    }
    .await;
    driver.quit().await?;
    res
}

#[tokio::test]
#[traced_test]
async fn test_browser_device_verification_uri_complete_prefills_code() -> Result<()> {
    let f = fixture().await?;
    let driver = driver().await?;
    let res: Result<()> = async {
        driver.goto(&f.start.verification_uri_complete).await?;
        let value = wait_for(&driver, By::Id("user_code"))
            .await?
            .value()
            .await?
            .unwrap_or_default();
        assert_eq!(
            value.replace('-', "").to_uppercase(),
            f.start.user_code.replace('-', "").to_uppercase()
        );
        Ok(())
    }
    .await;
    driver.quit().await?;
    res
}
