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
//! Passkey (WebAuthn) second factor in a real browser, using a virtual
//! CTAP2 authenticator.

use eyre::{Result, eyre};
use serde_json::json;
use thirtyfour::prelude::*;
use tracing_test::traced_test;
use url::Url;

use test_api::browser::*;
use test_api::oauth2_browser::*;

#[tokio::test]
#[traced_test]
async fn test_browser_passkey_second_factor() -> Result<()> {
    let domain_id = create_ready_domain("pk").await?;
    let callback = Callback::start().await?;
    let client = create_browser_client(
        &domain_id,
        json!({"redirect_uris": [callback.redirect_uri.clone()]}),
    )
    .await?;
    let (user_id, username) = create_browser_user(&domain_id).await?;
    let token = user_token(&domain_id, &username, PASSWORD, None).await?;
    let (mut params, verifier) = AuthorizeParams::new(&client.client_id);
    params.redirect_uri = callback.redirect_uri.clone();

    let mut authorize = base_url()?.join(&format!("v4/oauth2/{domain_id}/authorize"))?;
    authorize.query_pairs_mut().extend_pairs(params.pairs());

    let driver = driver().await?;
    let res: Result<()> = async {
        let auth_id = add_virtual_authenticator(&driver).await?;

        // Register on the Keystone origin (the WebAuthn relying party), on
        // an HTML page: browsers render JSON and empty-404 responses in
        // viewer/error pages that forbid fetch and WebAuthn.
        driver.goto(authorize.as_str()).await?;
        register_passkey(&driver, &user_id, &token).await?;
        assert_eq!(authenticator_credentials(&driver, &auth_id).await?.len(), 1);

        // Fresh login: password, then the passkey answers the MFA prompt.
        driver.delete_all_cookies().await?;
        driver.goto(authorize.as_str()).await?;
        sign_in(&driver, &username, PASSWORD).await?;
        wait_for(&driver, By::Css("#passkey-form button[type=submit]"))
            .await?
            .click()
            .await?;
        // Consent may or may not be asked, depending on remembered state.
        let url: Url = loop_until_redirect_or_consent(&driver, &callback).await?;
        let code = query_param(&url, "code").ok_or_else(|| eyre!("no code in {url}"))?;

        let (status, tokens) = exchange_code_for(
            &domain_id,
            &client.client_id,
            &code,
            &verifier,
            &callback.redirect_uri,
        )
        .await?;
        assert!(status.is_success(), "{status}: {tokens}");
        let claims = jwt_claims(tokens["id_token"].as_str().unwrap_or_default())?;
        let amr: Vec<&str> = claims["amr"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        assert!(amr.contains(&"hwk") && amr.contains(&"mfa"), "{claims}");
        Ok(())
    }
    .await;
    driver.quit().await?;
    res
}

async fn loop_until_redirect_or_consent(driver: &WebDriver, callback: &Callback) -> Result<Url> {
    for _ in 0..60 {
        if driver
            .current_url()
            .await?
            .as_str()
            .starts_with(&callback.redirect_uri)
        {
            break;
        }
        if let Ok(btn) = driver
            .find(By::Css("button[name=decision][value=allow]"))
            .await
        {
            btn.click().await?;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    callback.wait_for_redirect(driver).await
}
