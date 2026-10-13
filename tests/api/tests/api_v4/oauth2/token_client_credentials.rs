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
//! Live-server `client_credentials` grant (RFC 6749 §4.4, ADR 0026 §5).

use eyre::{Result, eyre};
use reqwest::StatusCode;
use serde_json::json;
use tracing_test::traced_test;

use test_api::oauth2::{post_introspect_form, post_token_form};
use test_api::oauth2_browser::*;

struct Cc {
    domain_id: String,
    client: BrowserClient,
    secret: String,
}

/// A confidential `client_credentials` client with a bound mapping ruleset.
async fn fixture(bind_ruleset: bool) -> Result<Cc> {
    let domain_id = create_ready_domain("cc").await?;
    let client = create_browser_client(
        &domain_id,
        json!({
            "confidential": true,
            "grant_types": ["client_credentials"],
            "allowed_scopes": ["openid", "profile"],
            "token_endpoint_auth_method": "client_secret_basic",
            "require_pkce": false,
        }),
    )
    .await?;
    if bind_ruleset {
        bind_client_credentials_ruleset(&domain_id, &client.provider_id).await?;
    }
    let secret = client
        .client_secret
        .clone()
        .ok_or_else(|| eyre!("confidential client returned no secret"))?;
    Ok(Cc {
        domain_id,
        client,
        secret,
    })
}

#[tokio::test]
#[traced_test]
async fn test_client_credentials_success_and_no_store() -> Result<()> {
    let cc = fixture(true).await?;
    let (status, headers, body) =
        client_credentials_token(&cc.domain_id, &cc.client.client_id, &cc.secret, None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["expires_in"].as_i64().is_some_and(|e| e > 0));
    let access = body["access_token"]
        .as_str()
        .ok_or_else(|| eyre!("no access_token in {body}"))?;
    // RFC 6749 §5.1 / #1269: token responses must not be cached.
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["pragma"], "no-cache");

    let claims = jwt_claims(access)?;
    assert!(claims["jti"].as_str().is_some());

    let (status, intro) = post_introspect_form(
        &cc.domain_id,
        &cc.client.client_id,
        &cc.secret,
        &[("token", access)],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(intro["active"], true, "{intro}");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_credentials_accepts_body_credentials() -> Result<()> {
    let cc = fixture(true).await?;
    let (status, body) = post_token_form(
        &cc.domain_id,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &cc.client.client_id),
            ("client_secret", &cc.secret),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_credentials_wrong_secret_is_invalid_client() -> Result<()> {
    let cc = fixture(true).await?;
    let (status, headers, body) =
        client_credentials_token(&cc.domain_id, &cc.client.client_id, "not-the-secret", None)
            .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    assert_eq!(headers["cache-control"], "no-store");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_credentials_unknown_client_is_invalid_client() -> Result<()> {
    let cc = fixture(true).await?;
    let (status, _, body) =
        client_credentials_token(&cc.domain_id, "no-such-client", "whatever", None).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_credentials_other_domain_is_invalid_client() -> Result<()> {
    let cc = fixture(true).await?;
    let other = create_ready_domain("cc-other").await?;
    let (status, _, body) =
        client_credentials_token(&other, &cc.client.client_id, &cc.secret, None).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_credentials_scope_subset_and_excess() -> Result<()> {
    let cc = fixture(true).await?;
    let (status, _, body) = client_credentials_token(
        &cc.domain_id,
        &cc.client.client_id,
        &cc.secret,
        Some("openid"),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, _, body) = client_credentials_token(
        &cc.domain_id,
        &cc.client.client_id,
        &cc.secret,
        Some("openid email"),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_scope");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_credentials_requires_grant_type() -> Result<()> {
    let domain_id = create_ready_domain("cc-nogrant").await?;
    let client = create_browser_client(
        &domain_id,
        json!({
            "confidential": true,
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "client_secret_basic",
            "require_pkce": false,
        }),
    )
    .await?;
    let secret = client.client_secret.clone().unwrap_or_default();
    let (status, _, body) =
        client_credentials_token(&domain_id, &client.client_id, &secret, None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "unauthorized_client");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_credentials_without_mapping_ruleset_is_rejected() -> Result<()> {
    let cc = fixture(false).await?;
    let (status, _, body) =
        client_credentials_token(&cc.domain_id, &cc.client.client_id, &cc.secret, None).await?;
    assert!(status.is_client_error(), "{status}: {body}");
    assert!(body["access_token"].is_null());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_credentials_is_rate_limited_per_client() -> Result<()> {
    let cc = fixture(true).await?;
    // Argon2 verification makes sequential requests slower than the
    // replenish rate, so fire a concurrent burst well above the limit.
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..40 {
        let (domain_id, client_id) = (cc.domain_id.clone(), cc.client.client_id.clone());
        set.spawn(async move {
            client_credentials_token(&domain_id, &client_id, "bad-secret", None).await
        });
    }
    let mut limited = None;
    while let Some(res) = set.join_next().await {
        let (status, headers, _) = res??;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = Some(headers);
        }
    }
    let headers = limited.ok_or_else(|| eyre!("no 429 after 40 concurrent requests"))?;
    assert!(headers.contains_key("retry-after"));

    // Another client of the same domain is unaffected (per-client key).
    let other = fixture(true).await?;
    let (status, _, body) = client_credentials_token(
        &other.domain_id,
        &other.client.client_id,
        &other.secret,
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_token_unsupported_grant_type() -> Result<()> {
    let cc = fixture(true).await?;
    let (status, body) = post_token_form(
        &cc.domain_id,
        &[
            ("grant_type", "password"),
            ("client_id", &cc.client.client_id),
            ("client_secret", &cc.secret),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "unsupported_grant_type");
    Ok(())
}
