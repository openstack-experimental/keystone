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
//! Happy-path OAuth2 sign-in in a real browser: login, consent, redirect,
//! SSO resume, RP-initiated logout and branded UI assets.

use eyre::Result;
use serde_json::json;
use thirtyfour::prelude::*;
use tracing_test::traced_test;
use url::Url;

use test_api::browser::*;
use test_api::oauth2_browser::*;

/// Authorize URL for `params` on `domain_id`.
fn authorize_url(domain_id: &str, params: &AuthorizeParams) -> Result<Url> {
    let mut url = base_url()?.join(&format!("v4/oauth2/{domain_id}/authorize"))?;
    url.query_pairs_mut().extend_pairs(params.pairs());
    Ok(url)
}

#[tokio::test]
#[traced_test]
async fn test_browser_login_consent_redirect_and_token() -> Result<()> {
    let domain_id = create_ready_domain("brw").await?;
    let callback = Callback::start().await?;
    let client = create_browser_client(
        &domain_id,
        json!({"redirect_uris": [callback.redirect_uri.clone()]}),
    )
    .await?;
    let (_uid, username) = create_browser_user(&domain_id).await?;
    let (mut params, verifier) = AuthorizeParams::new(&client.client_id);
    params.redirect_uri = callback.redirect_uri.clone();

    let driver = driver().await?;
    let res: Result<()> = async {
        driver
            .goto(authorize_url(&domain_id, &params)?.as_str())
            .await?;
        sign_in(&driver, &username, PASSWORD).await?;
        allow_consent(&driver).await?;

        let url = callback.wait_for_redirect(&driver).await?;
        assert_eq!(query_param(&url, "state"), Some(params.state.clone()));
        let code = query_param(&url, "code").ok_or_else(|| eyre::eyre!("no code in {url}"))?;

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
        assert_eq!(claims["nonce"].as_str(), params.nonce.as_deref());
        Ok(())
    }
    .await;
    driver.quit().await?;
    res
}

#[tokio::test]
#[traced_test]
async fn test_browser_wrong_password_shows_error_and_stays() -> Result<()> {
    let domain_id = create_ready_domain("brw").await?;
    let client = create_browser_client(&domain_id, json!({})).await?;
    let (_uid, username) = create_browser_user(&domain_id).await?;
    let (params, _) = AuthorizeParams::new(&client.client_id);

    let driver = driver().await?;
    let res: Result<()> = async {
        driver
            .goto(authorize_url(&domain_id, &params)?.as_str())
            .await?;
        sign_in(&driver, &username, "definitely-wrong").await?;
        // Still the login form, no redirect to the RP.
        wait_for(&driver, By::Id("password")).await?;
        let url = driver.current_url().await?;
        assert!(
            url.as_str().contains("/authorize") || url.as_str().contains("/login"),
            "{url}"
        );
        assert!(!url.as_str().starts_with(REDIRECT_URI), "{url}");
        Ok(())
    }
    .await;
    driver.quit().await?;
    res
}

#[tokio::test]
#[traced_test]
async fn test_browser_sso_resume_and_logout() -> Result<()> {
    let domain_id = create_ready_domain("brw").await?;
    let callback = Callback::start().await?;
    let client = create_browser_client(
        &domain_id,
        json!({
            "redirect_uris": [callback.redirect_uri.clone()],
            "post_logout_redirect_uris": [format!("{}/bye", callback.redirect_uri.trim_end_matches("/cb"))],
        }),
    )
    .await?;
    let (_uid, username) = create_browser_user(&domain_id).await?;
    let bye = format!("{}/bye", callback.redirect_uri.trim_end_matches("/cb"));

    let driver = driver().await?;
    let res: Result<()> = async {
        // First sign-in, consent remembered.
        let (mut params, verifier) = AuthorizeParams::new(&client.client_id);
        params.redirect_uri = callback.redirect_uri.clone();
        driver
            .goto(authorize_url(&domain_id, &params)?.as_str())
            .await?;
        sign_in(&driver, &username, PASSWORD).await?;
        let remember = wait_for(&driver, By::Css("input[name=remember]")).await?;
        // Pre-checked by default; make sure it stays on.
        if !remember.is_selected().await? {
            remember.click().await?;
        }
        allow_consent(&driver).await?;
        let url = callback.wait_for_redirect(&driver).await?;
        let code = query_param(&url, "code").ok_or_else(|| eyre::eyre!("no code in {url}"))?;
        let (status, tokens) = exchange_code_for(
            &domain_id,
            &client.client_id,
            &code,
            &verifier,
            &callback.redirect_uri,
        )
        .await?;
        assert!(status.is_success(), "{status}: {tokens}");
        let id_token = tokens["id_token"].as_str().unwrap_or_default().to_string();

        // Second request resumes through the SSO cookie: straight to the RP.
        let (mut params, _) = AuthorizeParams::new(&client.client_id);
        params.redirect_uri = callback.redirect_uri.clone();
        driver
            .goto(authorize_url(&domain_id, &params)?.as_str())
            .await?;
        let url = callback.wait_for_redirect(&driver).await?;
        assert!(query_param(&url, "code").is_some(), "{url}");

        // RP-initiated logout lands on the registered post-logout URI.
        let mut logout = base_url()?.join(&format!("v4/oauth2/{domain_id}/logout"))?;
        logout
            .query_pairs_mut()
            .append_pair("id_token_hint", &id_token)
            .append_pair("client_id", &client.client_id)
            .append_pair("post_logout_redirect_uri", &bye);
        driver.goto(logout.as_str()).await?;
        // Logout may show a confirmation page first.
        for _ in 0..40 {
            if driver.current_url().await?.as_str().starts_with(&bye) {
                break;
            }
            if let Ok(btn) = driver.find(By::Css("button[type=submit]")).await {
                btn.click().await?;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        assert!(driver.current_url().await?.as_str().starts_with(&bye));

        // Session is gone: authorizing asks for credentials again.
        let (mut params, _) = AuthorizeParams::new(&client.client_id);
        params.redirect_uri = callback.redirect_uri.clone();
        driver
            .goto(authorize_url(&domain_id, &params)?.as_str())
            .await?;
        wait_for(&driver, By::Id("password")).await?;
        Ok(())
    }
    .await;
    driver.quit().await?;
    res
}

#[tokio::test]
#[traced_test]
async fn test_browser_branding_and_assets_render() -> Result<()> {
    let domain_id = create_ready_domain("brw").await?;
    let client = create_browser_client(&domain_id, json!({})).await?;
    let (params, _) = AuthorizeParams::new(&client.client_id);

    let driver = driver().await?;
    let res: Result<()> = async {
        driver.goto(authorize_url(&domain_id, &params)?.as_str()).await?;
        wait_for(&driver, By::Id("password")).await?;
        let html = driver.source().await?;
        // Fixture template override and product name from the API config.
        assert!(html.contains("login-override"), "{html}");
        assert!(html.contains("Fixture Cloud"), "{html}");
        // The stylesheet is served and applied (fixture sets a body rule).
        let loaded: bool = driver
            .execute(
                "return Array.from(document.styleSheets).some(s => (s.href || '').includes('style.css'));",
                vec![],
            )
            .await?
            .convert()?;
        assert!(loaded, "style.css not applied");
        Ok(())
    }
    .await;
    driver.quit().await?;
    res
}
