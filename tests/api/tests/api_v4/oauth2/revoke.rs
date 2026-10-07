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
//! Live-server `POST /v4/oauth2/{domain_id}/revoke` (RFC 7009).
//!
//! Obtains real tokens through the device grant (the only browser-less
//! token flow with a refresh token available to the live-test crate), then
//! revokes them. Uses a freshly created domain: `default` is seeded
//! directly in the DB and never gets OAuth2 signing keys provisioned.

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use eyre::{Result, eyre};
use reqwest::StatusCode;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v4::oauth2_client::GrantType;

use test_api::oauth2::*;

/// Create a domain, wait for async signing-key provisioning, register a
/// public device+refresh client and run the device flow to completion.
/// Returns `(domain_id, client_id, token response body)`.
pub(super) async fn device_tokens() -> Result<(String, String, serde_json::Value)> {
    let domain_id = create_test_domain(&format!("revoke-{}", Uuid::new_v4().simple())).await?;
    let mut provisioned = false;
    for _ in 0..40 {
        let (status, _) = get_well_known(&domain_id).await?;
        if status == StatusCode::OK {
            provisioned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    if !provisioned {
        return Err(eyre!(
            "signing keys for domain {domain_id} never provisioned"
        ));
    }

    let provider_id = format!("revoke-test-{}", Uuid::new_v4().simple());
    let (client_id, _) = register_client(
        &domain_id,
        &provider_id,
        vec![GrantType::DeviceCode, GrantType::RefreshToken],
        vec!["openid".to_string()],
        false,
    )
    .await?;
    let username = format!("revoke-user-{}", Uuid::new_v4().simple());
    let password = "S3cur3P@ssw0rd!";
    create_test_user(&domain_id, &username, password).await?;

    let start = start_device_authorization(&domain_id, &client_id, Some("openid")).await?;
    let session = DeviceBrowserSession::new(&domain_id)?;
    let (_, login_html) = session.submit_user_code(&start.user_code).await?;
    let login_csrf =
        extract_hidden_value(&login_html, "csrf_token").ok_or_else(|| eyre!("no login csrf"))?;
    let (_, consent_html) = session
        .submit_login(&login_csrf, &username, password)
        .await?;
    let consent_csrf = extract_hidden_value(&consent_html, "csrf_token")
        .ok_or_else(|| eyre!("no consent csrf"))?;
    let (status, _) = session.submit_consent(&consent_csrf, "allow").await?;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = poll_device_token(&domain_id, &client_id, &start.device_code).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok((domain_id, client_id, body))
}

fn jti_of(jwt: &str) -> Result<String> {
    let payload = jwt.split('.').nth(1).ok_or_else(|| eyre!("not a JWT"))?;
    let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
    claims["jti"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| eyre!("no jti"))
}

#[tokio::test]
#[traced_test]
async fn test_revoke_refresh_token_blocks_refresh() -> Result<()> {
    let (domain_id, client_id, tokens) = device_tokens().await?;
    let refresh = tokens["refresh_token"]
        .as_str()
        .ok_or_else(|| eyre!("no refresh_token in {tokens}"))?;

    let (status, body) = post_revoke_form(
        &domain_id,
        &[
            ("token", refresh),
            ("token_type_hint", "refresh_token"),
            ("client_id", &client_id),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty());

    let (status, body) = post_token_form(
        &domain_id,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", refresh),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_revoke_access_token_lists_jti_and_ends_session() -> Result<()> {
    let (domain_id, client_id, tokens) = device_tokens().await?;
    let access = tokens["access_token"]
        .as_str()
        .ok_or_else(|| eyre!("no access_token in {tokens}"))?;
    let jti = jti_of(access)?;

    let (status, _) = post_revoke_form(
        &domain_id,
        &[
            ("token", access),
            ("token_type_hint", "access_token"),
            ("client_id", &client_id),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);

    let (status, list) = get_jwks_revocation(&domain_id).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(list.revoked_jtis.contains(&jti), "{list:?}");

    // The access token's `sid` ends the refresh family that minted it too.
    let refresh = tokens["refresh_token"]
        .as_str()
        .ok_or_else(|| eyre!("no refresh_token in {tokens}"))?;
    let (status, body) = post_token_form(
        &domain_id,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", refresh),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_revoke_unknown_token_is_200_and_bad_client_is_401() -> Result<()> {
    let (domain_id, client_id, _tokens) = device_tokens().await?;

    let (status, body) = post_revoke_form(
        &domain_id,
        &[("token", "no-such-token"), ("client_id", &client_id)],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty());

    let (status, _) = post_revoke_form(
        &domain_id,
        &[("token", "no-such-token"), ("client_id", "unknown-client")],
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    Ok(())
}
