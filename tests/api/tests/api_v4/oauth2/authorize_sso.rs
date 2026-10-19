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
//! Live-server OP single-sign-on session (ADR 0041): resume without
//! credentials, `prompt` / `max_age` handling, cookie attributes and
//! session revocation.

use eyre::{Result, eyre};
use reqwest::StatusCode;
use serde_json::json;
use tracing_test::traced_test;

use test_api::oauth2_browser::*;

const SSO_COOKIE: &str = "keystone_oauth2_sso";

struct Fixture {
    domain_id: String,
    client: BrowserClient,
    user_id: String,
    username: String,
}

async fn fixture() -> Result<Fixture> {
    let domain_id = create_ready_domain("sso").await?;
    let client = create_browser_client(&domain_id, json!({})).await?;
    let (user_id, username) = create_browser_user(&domain_id).await?;
    Ok(Fixture {
        domain_id,
        client,
        user_id,
        username,
    })
}

/// Sign in once, remembering consent, so later requests need neither
/// credentials nor consent while the SSO session lives.
async fn signed_in(f: &Fixture) -> Result<AuthorizeBrowser> {
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser
        .complete(&params, &f.username, PASSWORD, true)
        .await?;
    assert!(rsp.location_param("code").is_some(), "{}", rsp.body);
    Ok(browser)
}

#[tokio::test]
#[traced_test]
async fn test_sso_cookie_is_httponly_samesite_lax() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params).await?;
    let login = browser.login(&rsp.csrf()?, &f.username, PASSWORD).await?;
    let mut cookies = login.set_cookies();
    if login.is_consent() {
        cookies.extend(
            browser
                .consent(&login.csrf()?, "allow", false)
                .await?
                .set_cookies(),
        );
    }
    let sso = cookies
        .iter()
        .find(|c| c.starts_with(&format!("{SSO_COOKIE}=")))
        .ok_or_else(|| eyre!("no {SSO_COOKIE} cookie in {cookies:?}"))?
        .to_ascii_lowercase();
    assert!(sso.contains("httponly"), "{sso}");
    assert!(sso.contains("samesite=lax"), "{sso}");
    assert!(sso.contains("path=/"), "{sso}");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_sso_second_authorize_resumes_without_credentials() -> Result<()> {
    let f = fixture().await?;
    let browser = signed_in(&f).await?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params).await?;
    assert_eq!(rsp.status, StatusCode::SEE_OTHER, "{}", rsp.body);
    assert!(rsp.location_param("code").is_some(), "{:?}", rsp.location());
    assert_eq!(rsp.location_param("state"), Some(params.state));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_sso_resume_without_remembered_consent_asks_only_consent() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser
        .complete(&params, &f.username, PASSWORD, false)
        .await?;
    assert!(rsp.location_param("code").is_some());

    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params).await?;
    assert!(!rsp.is_login(), "credentials asked again: {}", rsp.body);
    assert!(rsp.is_consent(), "{}: {}", rsp.status, rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_sso_prompt_login_forces_reauthentication() -> Result<()> {
    let f = fixture().await?;
    let browser = signed_in(&f).await?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params.with("prompt", "login")).await?;
    assert!(rsp.is_login(), "{}: {}", rsp.status, rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_sso_max_age_zero_forces_reauthentication() -> Result<()> {
    let f = fixture().await?;
    let browser = signed_in(&f).await?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params.with("max_age", "0")).await?;
    assert!(rsp.is_login(), "{}: {}", rsp.status, rsp.body);

    // A generous max_age keeps the session usable.
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params.with("max_age", "3600")).await?;
    assert!(rsp.location_param("code").is_some(), "{}", rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_sso_max_age_invalid_is_rejected() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params.with("max_age", "soon")).await?;
    assert!(rsp.location_param("code").is_none());
    assert!(!rsp.is_login(), "{}", rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_sso_prompt_none_without_session_is_login_required() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params.with("prompt", "none")).await?;
    assert_eq!(rsp.status, StatusCode::SEE_OTHER, "{}", rsp.body);
    assert_eq!(
        rsp.location_param("error").as_deref(),
        Some("login_required")
    );
    assert!(
        rsp.set_cookies()
            .iter()
            .all(|c| !c.starts_with(SSO_COOKIE) || c.contains("Max-Age=0"))
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_sso_prompt_none_with_session() -> Result<()> {
    let f = fixture().await?;
    // Remembered consent -> silent success.
    let browser = signed_in(&f).await?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params.with("prompt", "none")).await?;
    assert!(rsp.location_param("code").is_some(), "{:?}", rsp.location());

    // Session but no remembered consent (fresh user: consent is remembered
    // per user and client) -> consent_required, no UI.
    let (_id, fresh) = create_browser_user(&f.domain_id).await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    browser.complete(&params, &fresh, PASSWORD, false).await?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params.with("prompt", "none")).await?;
    assert_eq!(
        rsp.location_param("error").as_deref(),
        Some("consent_required"),
        "{:?}",
        rsp.location()
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_sso_prompt_none_combined_with_other_value_is_rejected() -> Result<()> {
    let f = fixture().await?;
    let browser = signed_in(&f).await?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser
        .authorize(&params.with("prompt", "none login"))
        .await?;
    assert!(rsp.location_param("code").is_none());
    Ok(())
}

// ---- session revocation ----------------------------------------------------

/// After `mutate`, the SSO session must no longer resume silently.
async fn assert_session_ends<F, Fut>(
    f: &Fixture,
    browser: &AuthorizeBrowser,
    mutate: F,
) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    mutate().await?;
    eventually(|| async {
        let (params, _) = AuthorizeParams::new(&f.client.client_id);
        let rsp = browser.authorize(&params.with("prompt", "none")).await?;
        Ok(rsp.location_param("code").is_none().then_some(()))
    })
    .await
}

#[tokio::test]
#[traced_test]
async fn test_sso_ends_when_user_disabled() -> Result<()> {
    let f = fixture().await?;
    let browser = signed_in(&f).await?;
    assert_session_ends(&f, &browser, || {
        patch_user(&f.user_id, json!({"enabled": false}))
    })
    .await
}

#[tokio::test]
#[traced_test]
async fn test_sso_ends_when_user_deleted() -> Result<()> {
    let f = fixture().await?;
    let browser = signed_in(&f).await?;
    assert_session_ends(&f, &browser, || delete_user(&f.user_id)).await
}

#[tokio::test]
#[traced_test]
async fn test_sso_ends_when_password_changed() -> Result<()> {
    let f = fixture().await?;
    let browser = signed_in(&f).await?;
    assert_session_ends(&f, &browser, || {
        change_password(&f.user_id, PASSWORD, "N3w-S3cur3-P@ssw0rd!")
    })
    .await
}

#[tokio::test]
#[traced_test]
async fn test_sso_ends_when_domain_disabled() -> Result<()> {
    let f = fixture().await?;
    let browser = signed_in(&f).await?;
    assert_session_ends(&f, &browser, || {
        patch_domain(&f.domain_id, json!({"enabled": false}))
    })
    .await
}

#[tokio::test]
#[traced_test]
async fn test_sso_ends_when_domain_deleted() -> Result<()> {
    let f = fixture().await?;
    let browser = signed_in(&f).await?;
    assert_session_ends(&f, &browser, || delete_domain(&f.domain_id)).await
}

#[tokio::test]
#[traced_test]
async fn test_sso_session_does_not_resume_on_other_domain() -> Result<()> {
    let f = fixture().await?;
    let browser = signed_in(&f).await?;

    // The cookie jar of `browser` is host-wide, so replay the same cookie
    // against another domain's endpoint: it must not be honoured there.
    let other_domain = create_ready_domain("sso-other").await?;
    let other_client = create_browser_client(&other_domain, json!({})).await?;
    let cookie = browser.cookie_value(SSO_COOKIE).await?;
    let foreign = AuthorizeBrowser::with_cookie(&other_domain, SSO_COOKIE, &cookie)?;
    let (params, _) = AuthorizeParams::new(&other_client.client_id);
    let rsp = foreign.authorize(&params).await?;
    assert!(rsp.is_login(), "{}: {}", rsp.status, rsp.body);
    assert!(rsp.location_param("code").is_none());
    Ok(())
}
