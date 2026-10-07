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
//! Live-server `POST /v4/oauth2/{domain_id}/introspect` (RFC 7662).
//!
//! Mints tokens through the device grant, introspects them with a separate
//! confidential client, revokes them through RFC 7009 and introspects again.

use eyre::{Result, eyre};
use reqwest::StatusCode;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v4::oauth2_client::GrantType;

use test_api::oauth2::*;

use super::revoke::device_tokens;

/// Register a confidential client in `domain_id` to act as the introspecting
/// resource server. Returns `(client_id, client_secret)`.
async fn introspector(domain_id: &str) -> Result<(String, String)> {
    let (client_id, secret) = register_client(
        domain_id,
        &format!("introspect-rs-{}", Uuid::new_v4().simple()),
        vec![GrantType::DeviceCode, GrantType::RefreshToken],
        vec!["openid".to_string()],
        true,
    )
    .await?;
    Ok((
        client_id,
        secret.ok_or_else(|| eyre!("confidential client returned no secret"))?,
    ))
}

#[tokio::test]
#[traced_test]
async fn test_introspect_access_token_active_then_revoked() -> Result<()> {
    let (domain_id, client_id, tokens) = device_tokens().await?;
    let (rs_id, rs_secret) = introspector(&domain_id).await?;
    let access = tokens["access_token"]
        .as_str()
        .ok_or_else(|| eyre!("no access_token in {tokens}"))?;

    let (status, body) = post_introspect_form(
        &domain_id,
        &rs_id,
        &rs_secret,
        &[("token", access), ("token_type_hint", "access_token")],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active"], true, "{body}");
    assert_eq!(body["client_id"], client_id.as_str());
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["jti"].is_string(), "{body}");

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

    let (status, body) =
        post_introspect_form(&domain_id, &rs_id, &rs_secret, &[("token", access)]).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({"active": false}));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_introspect_refresh_token_active_then_revoked() -> Result<()> {
    let (domain_id, client_id, tokens) = device_tokens().await?;
    let (rs_id, rs_secret) = introspector(&domain_id).await?;
    let refresh = tokens["refresh_token"]
        .as_str()
        .ok_or_else(|| eyre!("no refresh_token in {tokens}"))?;

    let (status, body) = post_introspect_form(
        &domain_id,
        &rs_id,
        &rs_secret,
        &[("token", refresh), ("token_type_hint", "refresh_token")],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active"], true, "{body}");
    assert_eq!(body["client_id"], client_id.as_str());

    let (status, _) =
        post_revoke_form(&domain_id, &[("token", refresh), ("client_id", &client_id)]).await?;
    assert_eq!(status, StatusCode::OK);

    let (status, body) =
        post_introspect_form(&domain_id, &rs_id, &rs_secret, &[("token", refresh)]).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({"active": false}));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_introspect_unknown_token_inactive_and_public_client_rejected() -> Result<()> {
    let (domain_id, public_id, _tokens) = device_tokens().await?;
    let (rs_id, rs_secret) = introspector(&domain_id).await?;

    let (status, body) =
        post_introspect_form(&domain_id, &rs_id, &rs_secret, &[("token", "nope")]).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({"active": false}));

    // A public client cannot introspect: it has no secret to authenticate.
    let (status, _) =
        post_introspect_form(&domain_id, &public_id, "", &[("token", "nope")]).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    Ok(())
}
