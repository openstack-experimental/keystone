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
//! Live-server RP-initiated logout: `id_token_hint`, the
//! `post_logout_redirect_uri` allowlist, SSO cookie removal and the
//! confirmation page shown when no hint is sent.

use eyre::{Result, eyre};
use reqwest::StatusCode;
use serde_json::json;
use tracing_test::traced_test;

use test_api::oauth2_browser::*;

const SSO_COOKIE: &str = "keystone_oauth2_sso";

struct Fixture {
    domain_id: String,
    client: BrowserClient,
    browser: AuthorizeBrowser,
    id_token: String,
}

/// Sign a user in through the browser and redeem the code, keeping the
/// browser (and its SSO cookie) plus the issued `id_token`.
async fn fixture() -> Result<Fixture> {
    let domain_id = create_ready_domain("logout").await?;
    let client = create_browser_client(&domain_id, json!({})).await?;
    let (_, username) = create_browser_user(&domain_id).await?;
    let browser = AuthorizeBrowser::new(&domain_id)?;
    let (params, verifier) = AuthorizeParams::new(&client.client_id);
    let code = browser.obtain_code(&params, &username, PASSWORD).await?;
    let (status, body) = exchange_code(&domain_id, &client.client_id, &code, &verifier).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id_token = body["id_token"]
        .as_str()
        .ok_or_else(|| eyre!("no id_token in {body}"))?
        .to_string();
    Ok(Fixture {
        domain_id,
        client,
        browser,
        id_token,
    })
}

fn assert_sso_cookie_cleared(rsp: &BrowserResponse) -> Result<()> {
    let cookie = rsp
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with(&format!("{SSO_COOKIE}=")))
        .ok_or_else(|| eyre!("no {SSO_COOKIE} cookie cleared: {:?}", rsp.set_cookies()))?;
    assert!(cookie.contains("Max-Age=0"), "{cookie}");
    Ok(())
}

/// After logout the next authorization request must ask for credentials.
async fn assert_session_ended(f: &Fixture) -> Result<()> {
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = f.browser.authorize(&params).await?;
    assert!(
        rsp.is_login(),
        "session survived: {}: {}",
        rsp.status,
        rsp.body
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_logout_with_id_token_hint_redirects_and_clears_session() -> Result<()> {
    let f = fixture().await?;
    let rsp = f
        .browser
        .logout(&[
            ("id_token_hint", f.id_token.as_str()),
            ("post_logout_redirect_uri", POST_LOGOUT_URI),
            ("state", "bye-state"),
        ])
        .await?;
    assert_eq!(rsp.status, StatusCode::SEE_OTHER, "{}", rsp.body);
    let location = rsp.location().ok_or_else(|| eyre!("no Location"))?;
    assert!(location.starts_with(POST_LOGOUT_URI), "{location}");
    assert_eq!(rsp.location_param("state").as_deref(), Some("bye-state"));
    assert_sso_cookie_cleared(&rsp)?;
    assert_session_ended(&f).await
}

#[tokio::test]
#[traced_test]
async fn test_logout_unregistered_redirect_uri_is_rejected() -> Result<()> {
    let f = fixture().await?;
    let rsp = f
        .browser
        .logout(&[
            ("id_token_hint", f.id_token.as_str()),
            ("post_logout_redirect_uri", "https://evil.example.com/bye"),
        ])
        .await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST, "{}", rsp.body);
    assert!(
        rsp.location().is_none(),
        "redirected to {:?}",
        rsp.location()
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_logout_with_garbage_hint_is_rejected_and_keeps_session() -> Result<()> {
    let f = fixture().await?;
    let rsp = f
        .browser
        .logout(&[
            ("id_token_hint", "not.a.jwt"),
            ("post_logout_redirect_uri", POST_LOGOUT_URI),
        ])
        .await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST, "{}", rsp.body);
    assert!(rsp.location().is_none());

    // The bad request must not have ended the session.
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = f.browser.authorize(&params).await?;
    assert!(!rsp.is_login(), "session ended by a rejected logout");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_logout_with_tampered_hint_is_rejected() -> Result<()> {
    let f = fixture().await?;
    let mut tampered = f.id_token.clone();
    // Flip the last signature character.
    let last = tampered.pop().ok_or_else(|| eyre!("empty token"))?;
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    let rsp = f
        .browser
        .logout(&[("id_token_hint", tampered.as_str())])
        .await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST, "{}", rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_logout_hint_from_other_domain_is_rejected() -> Result<()> {
    let f = fixture().await?;
    let other = fixture().await?;
    let rsp = f
        .browser
        .logout(&[("id_token_hint", other.id_token.as_str())])
        .await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST, "{}", rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_logout_without_hint_asks_confirmation_then_ends_session() -> Result<()> {
    let f = fixture().await?;
    let rsp = f
        .browser
        .logout(&[
            ("client_id", f.client.client_id.as_str()),
            ("post_logout_redirect_uri", POST_LOGOUT_URI),
            ("state", "s1"),
        ])
        .await?;
    assert_eq!(rsp.status, StatusCode::OK, "{}", rsp.body);
    assert!(rsp.body.contains("<form"), "{}", rsp.body);
    assert!(rsp.location().is_none());

    // Nothing happened yet: a link on another site cannot sign the user out.
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = f.browser.authorize(&params).await?;
    assert!(!rsp.is_login(), "GET without hint ended the session");

    let rsp = f
        .browser
        .post(
            "logout",
            &[
                ("client_id", f.client.client_id.as_str()),
                ("post_logout_redirect_uri", POST_LOGOUT_URI),
                ("state", "s1"),
            ],
        )
        .await?;
    assert_eq!(rsp.status, StatusCode::SEE_OTHER, "{}", rsp.body);
    let location = rsp.location().ok_or_else(|| eyre!("no Location"))?;
    assert!(location.starts_with(POST_LOGOUT_URI), "{location}");
    assert_eq!(rsp.location_param("state").as_deref(), Some("s1"));
    assert_sso_cookie_cleared(&rsp)?;
    assert_session_ended(&f).await
}

#[tokio::test]
#[traced_test]
async fn test_confirmed_logout_with_unregistered_redirect_uri_is_rejected() -> Result<()> {
    let f = fixture().await?;
    let rsp = f
        .browser
        .post(
            "logout",
            &[
                ("client_id", f.client.client_id.as_str()),
                ("post_logout_redirect_uri", "https://evil.example.com/bye"),
            ],
        )
        .await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST, "{}", rsp.body);
    assert!(rsp.location().is_none());
    Ok(())
}
