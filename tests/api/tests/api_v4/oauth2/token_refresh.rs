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
//! Live-server `refresh_token` grant: rotation, predecessor invalidation,
//! reuse detection (family collapse) and client binding (ADR 0026 §9).
//!
//! `tools/start-api.sh` sets `refresh_token_reuse_grace_minutes = 0`, so a
//! replayed predecessor is a breach immediately instead of a tolerated
//! multi-device race.

use eyre::{Result, eyre};
use reqwest::StatusCode;
use serde_json::json;
use tracing_test::traced_test;

use test_api::oauth2::post_token_form;
use test_api::oauth2_browser::*;

struct Fixture {
    domain_id: String,
    client: BrowserClient,
    refresh_token: String,
}

fn client_json() -> serde_json::Value {
    json!({ "grant_types": ["authorization_code", "refresh_token"] })
}

async fn fixture() -> Result<Fixture> {
    let domain_id = create_ready_domain("refresh").await?;
    let client = create_browser_client(&domain_id, client_json()).await?;
    let (_id, username) = create_browser_user(&domain_id).await?;
    let browser = AuthorizeBrowser::new(&domain_id)?;
    let (params, verifier) = AuthorizeParams::new(&client.client_id);
    let code = browser.obtain_code(&params, &username, PASSWORD).await?;
    let (status, body) = exchange_code(&domain_id, &client.client_id, &code, &verifier).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let refresh_token = body["refresh_token"]
        .as_str()
        .ok_or_else(|| eyre!("no refresh_token in {body}"))?
        .to_string();
    Ok(Fixture {
        domain_id,
        client,
        refresh_token,
    })
}

#[tokio::test]
#[traced_test]
async fn test_refresh_rotates_and_chains() -> Result<()> {
    let f = fixture().await?;
    let (status, first) = refresh(&f.domain_id, &f.client.client_id, &f.refresh_token).await?;
    assert_eq!(status, StatusCode::OK, "{first}");
    let second_rt = first["refresh_token"]
        .as_str()
        .ok_or_else(|| eyre!("no rotated refresh_token in {first}"))?;
    assert_ne!(second_rt, f.refresh_token, "refresh token must rotate");
    assert!(first["access_token"].as_str().is_some());

    // The rotated token works again.
    let (status, second) = refresh(&f.domain_id, &f.client.client_id, second_rt).await?;
    assert_eq!(status, StatusCode::OK, "{second}");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_refresh_predecessor_reuse_collapses_family() -> Result<()> {
    let f = fixture().await?;
    let (status, first) = refresh(&f.domain_id, &f.client.client_id, &f.refresh_token).await?;
    assert_eq!(status, StatusCode::OK, "{first}");
    let child = first["refresh_token"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    // Replay of the already-spent predecessor.
    let (status, replay) = refresh(&f.domain_id, &f.client.client_id, &f.refresh_token).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{replay}");
    assert_eq!(replay["error"], "invalid_grant");

    // The breach revoked the whole family, including the live child.
    let (status, body) = refresh(&f.domain_id, &f.client.client_id, &child).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_refresh_token_is_bound_to_its_client() -> Result<()> {
    let f = fixture().await?;
    let other = create_browser_client(&f.domain_id, client_json()).await?;
    let (status, body) = refresh(&f.domain_id, &other.client_id, &f.refresh_token).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_refresh_token_is_bound_to_its_domain() -> Result<()> {
    let f = fixture().await?;
    let other_domain = create_ready_domain("refresh-other").await?;
    let (status, body) = refresh(&other_domain, &f.client.client_id, &f.refresh_token).await?;
    assert!(status.is_client_error(), "{status}: {body}");
    assert!(body["access_token"].is_null());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_refresh_with_garbage_token_is_invalid_grant() -> Result<()> {
    let f = fixture().await?;
    let (status, body) = refresh(&f.domain_id, &f.client.client_id, "not-a-refresh-token").await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_refresh_requires_refresh_grant_on_client() -> Result<()> {
    let domain_id = create_ready_domain("refresh-nogrant").await?;
    let client = create_browser_client(&domain_id, json!({})).await?;
    let (status, body) = refresh(&domain_id, &client.client_id, "whatever").await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "unauthorized_client");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_refresh_missing_token_is_invalid_request() -> Result<()> {
    let f = fixture().await?;
    let (status, body) = post_token_form(
        &f.domain_id,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", &f.client.client_id),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");
    Ok(())
}
