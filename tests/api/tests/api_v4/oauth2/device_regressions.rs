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
//! Live-server regressions for the device grant: poll rate limiting
//! (#1270) and a client disabled after approval but before the device
//! code is redeemed (#1271).

use eyre::Result;
use reqwest::StatusCode;
use serde_json::json;
use tracing_test::traced_test;

use test_api::oauth2::{
    DeviceBrowserSession, extract_hidden_value, poll_device_token, start_device_authorization,
};
use test_api::oauth2_browser::*;

struct Fixture {
    domain_id: String,
    client: BrowserClient,
    username: String,
}

async fn fixture() -> Result<Fixture> {
    let domain_id = create_ready_domain("devreg").await?;
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
    Ok(Fixture {
        domain_id,
        client,
        username,
    })
}

#[tokio::test]
#[traced_test]
async fn test_device_poll_flood_is_rate_limited() -> Result<()> {
    let f = fixture().await?;
    let start =
        start_device_authorization(&f.domain_id, &f.client.client_id, Some("openid")).await?;

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..40 {
        let (d, c, dc) = (
            f.domain_id.clone(),
            f.client.client_id.clone(),
            start.device_code.clone(),
        );
        set.spawn(async move { poll_device_token(&d, &c, &dc).await });
    }
    let mut limited = 0;
    while let Some(poll) = set.join_next().await {
        let (status, body) = poll??;
        assert_ne!(status, StatusCode::OK, "{body}");
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited += 1;
        }
    }
    assert!(limited > 0, "40 concurrent polls were never rate limited");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_disabled_after_consent_gets_no_token() -> Result<()> {
    let f = fixture().await?;
    let start =
        start_device_authorization(&f.domain_id, &f.client.client_id, Some("openid")).await?;

    let session = DeviceBrowserSession::new(&f.domain_id)?;
    let (_, html) = session.submit_user_code(&start.user_code).await?;
    let csrf = extract_hidden_value(&html, "csrf_token").ok_or_else(|| eyre::eyre!("{html}"))?;
    let (_, html) = session.submit_login(&csrf, &f.username, PASSWORD).await?;
    let csrf = extract_hidden_value(&html, "csrf_token").ok_or_else(|| eyre::eyre!("{html}"))?;
    let (status, html) = session.submit_consent(&csrf, "allow").await?;
    assert_eq!(status, StatusCode::OK, "{html}");

    set_client_enabled(&f.domain_id, &f.client.provider_id, false).await?;

    let (status, body) =
        poll_device_token(&f.domain_id, &f.client.client_id, &start.device_code).await?;
    assert!(status.is_client_error(), "{status}: {body}");
    assert!(body["access_token"].is_null(), "{body}");
    Ok(())
}
