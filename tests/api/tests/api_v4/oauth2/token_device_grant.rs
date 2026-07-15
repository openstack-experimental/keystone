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
//! Live-server `POST /v4/oauth2/{domain_id}/token` with
//! `grant_type=urn:ietf:params:oauth:grant-type:device_code` (RFC 8628 §3.4,
//! §3.5). Complements `device_browser.rs`'s happy-path/deny coverage with
//! the wire-level error states that RFC 8628 mandates exact error codes for.

use eyre::Result;
use reqwest::StatusCode;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v4::oauth2_client::GrantType;

use test_api::oauth2::*;

#[tokio::test]
#[traced_test]
async fn test_unknown_device_code_is_invalid_grant() -> Result<()> {
    let provider_id = format!("device-token-unknown-test-{}", Uuid::new_v4().simple());
    let (client_id, _secret) = register_client(
        "default",
        &provider_id,
        vec![GrantType::DeviceCode],
        vec!["openid".to_string()],
        false,
    )
    .await?;

    let (status, body) = poll_device_token("default", &client_id, "no-such-device-code").await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_device_code_polled_by_wrong_client_is_invalid_grant() -> Result<()> {
    let provider_a = format!("device-token-owner-test-{}", Uuid::new_v4().simple());
    let (client_a, _) = register_client(
        "default",
        &provider_a,
        vec![GrantType::DeviceCode],
        vec!["openid".to_string()],
        false,
    )
    .await?;
    let provider_b = format!("device-token-other-test-{}", Uuid::new_v4().simple());
    let (client_b, _) = register_client(
        "default",
        &provider_b,
        vec![GrantType::DeviceCode],
        vec!["openid".to_string()],
        false,
    )
    .await?;

    let start = start_device_authorization("default", &client_a, Some("openid")).await?;

    // client_b never received this device_code -- must not be able to
    // redeem a grant issued to a different client (RFC 8628 device_code
    // binding).
    let (status, body) = poll_device_token("default", &client_b, &start.device_code).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_slow_down_when_polling_faster_than_interval() -> Result<()> {
    let provider_id = format!("device-token-slowdown-test-{}", Uuid::new_v4().simple());
    let (client_id, _secret) = register_client(
        "default",
        &provider_id,
        vec![GrantType::DeviceCode],
        vec!["openid".to_string()],
        false,
    )
    .await?;

    let start = start_device_authorization("default", &client_id, Some("openid")).await?;

    let (status1, body1) = poll_device_token("default", &client_id, &start.device_code).await?;
    assert_eq!(status1, StatusCode::BAD_REQUEST);
    assert_eq!(body1["error"], "authorization_pending");

    // Second poll, immediately after the first, faster than `interval`
    // allows -- RFC 8628 §3.5 requires `slow_down`, not another
    // `authorization_pending`.
    let (status2, body2) = poll_device_token("default", &client_id, &start.device_code).await?;
    assert_eq!(status2, StatusCode::BAD_REQUEST);
    assert_eq!(body2["error"], "slow_down");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_missing_device_code_is_invalid_request() -> Result<()> {
    let (status, body) = post_token_form(
        "default",
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", "irrelevant"),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    Ok(())
}
