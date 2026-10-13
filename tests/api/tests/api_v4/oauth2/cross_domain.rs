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
//! Live-server cross-domain isolation: a session or grant minted for
//! domain A is never honoured on domain B's OAuth2 endpoints.

use eyre::Result;
use serde_json::json;
use tracing_test::traced_test;

use test_api::oauth2_browser::*;

const SESSION_COOKIE: &str = "keystone_oauth2_session";

struct Side {
    domain_id: String,
    client: BrowserClient,
    user_id: String,
    username: String,
}

async fn side(prefix: &str) -> Result<Side> {
    let domain_id = create_ready_domain(prefix).await?;
    let client = create_browser_client(&domain_id, json!({})).await?;
    let (user_id, username) = create_browser_user(&domain_id).await?;
    Ok(Side {
        domain_id,
        client,
        user_id,
        username,
    })
}

fn assert_no_code(rsp: &BrowserResponse) {
    assert!(
        rsp.location_param("code").is_none(),
        "code issued across domains: {} {:?}",
        rsp.status,
        rsp.location()
    );
}

#[tokio::test]
#[traced_test]
async fn test_user_of_other_domain_cannot_log_in() -> Result<()> {
    let a = side("xdom-a").await?;
    let b = side("xdom-b").await?;

    let browser = AuthorizeBrowser::new(&b.domain_id)?;
    let (params, _) = AuthorizeParams::new(&b.client.client_id);
    let rsp = browser.authorize(&params).await?;
    assert!(rsp.is_login());
    // Right name and password, but the user lives in domain A.
    let rsp = browser.login(&rsp.csrf()?, &a.username, PASSWORD).await?;
    assert_no_code(&rsp);
    assert!(rsp.is_login(), "{}: {}", rsp.status, rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_consent_session_of_other_domain_is_rejected() -> Result<()> {
    let a = side("xdom-a").await?;
    let b = side("xdom-b").await?;

    // Authenticate on A, stop at the consent screen.
    let browser_a = AuthorizeBrowser::new(&a.domain_id)?;
    let (params, _) = AuthorizeParams::new(&a.client.client_id);
    let rsp = browser_a.authorize(&params).await?;
    let rsp = browser_a.login(&rsp.csrf()?, &a.username, PASSWORD).await?;
    assert!(rsp.is_consent(), "{}: {}", rsp.status, rsp.body);
    let csrf = rsp.csrf()?;
    let session = browser_a.cookie_value(SESSION_COOKIE).await?;

    // Replay session + CSRF token on domain B.
    let foreign = AuthorizeBrowser::with_cookie(&b.domain_id, SESSION_COOKIE, &session)?;
    let rsp = foreign.consent(&csrf, "allow", false).await?;
    assert_no_code(&rsp);
    assert!(rsp.status.is_client_error(), "{}: {}", rsp.status, rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_mfa_session_of_other_domain_is_rejected() -> Result<()> {
    let a = side("xdom-a").await?;
    let b = side("xdom-b").await?;
    let seed = enroll_totp(&a.user_id).await?;

    let browser_a = AuthorizeBrowser::new(&a.domain_id)?;
    let (params, _) = AuthorizeParams::new(&a.client.client_id);
    let rsp = browser_a.authorize(&params).await?;
    let rsp = browser_a.login(&rsp.csrf()?, &a.username, PASSWORD).await?;
    assert!(rsp.is_mfa(), "{}: {}", rsp.status, rsp.body);
    let csrf = rsp.csrf()?;
    let session = browser_a.cookie_value(SESSION_COOKIE).await?;

    let foreign = AuthorizeBrowser::with_cookie(&b.domain_id, SESSION_COOKIE, &session)?;
    let rsp = foreign.mfa(&csrf, &totp_now(&seed)?).await?;
    assert_no_code(&rsp);
    assert!(rsp.status.is_client_error(), "{}: {}", rsp.status, rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authorization_code_of_other_domain_is_not_redeemable() -> Result<()> {
    let a = side("xdom-a").await?;
    let b = side("xdom-b").await?;

    let browser = AuthorizeBrowser::new(&a.domain_id)?;
    let (params, verifier) = AuthorizeParams::new(&a.client.client_id);
    let code = browser.obtain_code(&params, &a.username, PASSWORD).await?;

    // Redeem A's code on B's token endpoint, with B's client.
    let (status, body) = exchange_code(&b.domain_id, &b.client.client_id, &code, &verifier).await?;
    assert!(status.is_client_error(), "{status}: {body}");
    Ok(())
}
