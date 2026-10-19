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
//! Live-server RFC 8693 token exchange: trade a delegated Keystone token
//! (application credential) for an OAuth2 access token.

use eyre::{Result, eyre};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tracing_test::traced_test;

use test_api::oauth2_browser::*;

const GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

struct Fixture {
    domain_id: String,
    client: BrowserClient,
    /// A delegated (application credential) token of a user in the domain.
    subject_token: String,
}

async fn exchange_client(domain_id: &str, grants: Value) -> Result<BrowserClient> {
    create_browser_client(
        domain_id,
        json!({
            "confidential": true,
            "grant_types": grants,
            "token_endpoint_auth_method": "client_secret_basic",
            "require_pkce": false,
            "redirect_uris": [],
            "post_logout_redirect_uris": [],
        }),
    )
    .await
}

async fn delegated_token(domain_id: &str) -> Result<String> {
    let (user_id, username, project_id) = project_role_user(domain_id, "member").await?;
    let scoped = project_token(domain_id, &username, &project_id).await?;
    app_cred_token(&user_id, &scoped).await
}

async fn fixture() -> Result<Fixture> {
    let domain_id = create_ready_domain("xchg").await?;
    let client = exchange_client(&domain_id, json!([GRANT])).await?;
    let subject_token = delegated_token(&domain_id).await?;
    Ok(Fixture {
        domain_id,
        client,
        subject_token,
    })
}

async fn exchange(
    domain_id: &str,
    client: &BrowserClient,
    secret: Option<&str>,
    form: &[(&str, &str)],
) -> Result<(StatusCode, Value)> {
    let secret = secret
        .or(client.client_secret.as_deref())
        .unwrap_or_default();
    let mut all = vec![("grant_type", GRANT)];
    all.extend_from_slice(form);
    let rsp = test_api::common::http_client()
        .post(base_url()?.join(&format!("v4/oauth2/{domain_id}/token"))?)
        .basic_auth(&client.client_id, Some(secret))
        .form(&all)
        .send()
        .await?;
    let status = rsp.status();
    Ok((status, rsp.json().await.unwrap_or(Value::Null)))
}

#[tokio::test]
#[traced_test]
async fn test_token_exchange_success() -> Result<()> {
    let f = fixture().await?;
    let (status, body) = exchange(
        &f.domain_id,
        &f.client,
        None,
        &[
            ("subject_token", &f.subject_token),
            ("subject_token_type", SUBJECT_TOKEN_TYPE),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["expires_in"].as_i64().is_some_and(|e| e > 0), "{body}");
    let access = body["access_token"]
        .as_str()
        .ok_or_else(|| eyre!("no access_token in {body}"))?;
    let claims = jwt_claims(access)?;
    assert!(
        claims["iss"]
            .as_str()
            .is_some_and(|i| i.ends_with(&format!("/v4/oauth2/{}", f.domain_id))),
        "{claims}"
    );
    assert!(claims["sub"].is_string(), "{claims}");
    assert!(claims["exp"].is_i64(), "{claims}");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_token_exchange_requires_subject_token() -> Result<()> {
    let f = fixture().await?;
    let (status, body) = exchange(&f.domain_id, &f.client, None, &[]).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_token_exchange_rejects_garbage_subject_token() -> Result<()> {
    let f = fixture().await?;
    let (status, body) = exchange(
        &f.domain_id,
        &f.client,
        None,
        &[("subject_token", "not-a-token")],
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_token_exchange_rejects_non_delegated_subject_token() -> Result<()> {
    let f = fixture().await?;
    // A plain password-scoped token carries no exchangeable delegation.
    let (_, username, project_id) = project_role_user(&f.domain_id, "member").await?;
    let plain = project_token(&f.domain_id, &username, &project_id).await?;
    let (status, body) =
        exchange(&f.domain_id, &f.client, None, &[("subject_token", &plain)]).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_token_exchange_wrong_secret_is_invalid_client() -> Result<()> {
    let f = fixture().await?;
    let (status, body) = exchange(
        &f.domain_id,
        &f.client,
        Some("wrong-secret"),
        &[("subject_token", &f.subject_token)],
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_token_exchange_requires_grant_on_client() -> Result<()> {
    let f = fixture().await?;
    let client = exchange_client(&f.domain_id, json!(["client_credentials"])).await?;
    let (status, body) = exchange(
        &f.domain_id,
        &client,
        None,
        &[("subject_token", &f.subject_token)],
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "unauthorized_client");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_token_exchange_subject_token_of_other_domain_is_rejected() -> Result<()> {
    let f = fixture().await?;
    let other_domain = create_ready_domain("xchg-other").await?;
    let foreign_subject = delegated_token(&other_domain).await?;
    let (status, body) = exchange(
        &f.domain_id,
        &f.client,
        None,
        &[("subject_token", &foreign_subject)],
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_token_exchange_unknown_audience_is_invalid_target() -> Result<()> {
    let f = fixture().await?;
    let (status, body) = exchange(
        &f.domain_id,
        &f.client,
        None,
        &[
            ("subject_token", &f.subject_token),
            ("audience", "no-such-service-type"),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_target");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_token_exchange_grant_is_admin_only_for_clients() -> Result<()> {
    // Enabling the grant on a client is a system-admin operation.
    let domain_id = create_ready_domain("xchg-gate").await?;
    let manager = project_role_token(&domain_id, "manager").await?;
    let rsp = test_api::common::http_client()
        .post(base_url()?.join(&format!("v4/oauth2/{domain_id}/clients"))?)
        .header("x-auth-token", manager)
        .json(&json!({"oauth2_client": {
            "provider_id": "gate-client",
            "name": "gate",
            "confidential": true,
            "grant_types": [GRANT],
            "allowed_scopes": ["openid"],
            "token_endpoint_auth_method": "client_secret_basic",
            "require_pkce": false,
        }}))
        .send()
        .await?;
    assert!(
        rsp.status() == StatusCode::FORBIDDEN || rsp.status() == StatusCode::UNAUTHORIZED,
        "{}",
        rsp.status()
    );
    Ok(())
}
