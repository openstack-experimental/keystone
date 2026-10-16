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
//! Live-server signing-key management: rotate / ensure / emergency
//! staging, JWKS publication and authorization.

use eyre::{Result, eyre};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use tracing_test::traced_test;

use test_api::common::TestClient;
use test_api::oauth2::get_well_known;
use test_api::oauth2_browser::*;

struct Fixture {
    domain_id: String,
    client: BrowserClient,
    username: String,
}

async fn fixture() -> Result<Fixture> {
    let domain_id = create_ready_domain("keyrot").await?;
    let client = create_browser_client(&domain_id, json!({})).await?;
    let (_, username) = create_browser_user(&domain_id).await?;
    Ok(Fixture {
        domain_id,
        client,
        username,
    })
}

async fn issue_id_token(f: &Fixture) -> Result<String> {
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, verifier) = AuthorizeParams::new(&f.client.client_id);
    let code = browser.obtain_code(&params, &f.username, PASSWORD).await?;
    let (status, body) = exchange_code(&f.domain_id, &f.client.client_id, &code, &verifier).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["id_token"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| eyre!("no id_token in {body}"))
}

async fn jwks_kids(domain_id: &str) -> Result<Vec<String>> {
    let (_, doc) = get_well_known(domain_id).await?;
    let uri = doc["jwks_uri"]
        .as_str()
        .ok_or_else(|| eyre!("no jwks_uri in {doc}"))?;
    let jwks: Value = reqwest::get(uri).await?.json().await?;
    Ok(jwks["keys"]
        .as_array()
        .ok_or_else(|| eyre!("no keys in {jwks}"))?
        .iter()
        .filter_map(|k| k["kid"].as_str().map(str::to_string))
        .collect())
}

/// `POST /v4/oauth2/{domain}/{action}` with `token` (none: unauthenticated).
async fn key_call(
    domain_id: &str,
    action: &str,
    token: Option<&str>,
    body: Value,
) -> Result<(StatusCode, Value)> {
    let mut rb = test_api::common::http_client()
        .post(base_url()?.join(&format!("v4/oauth2/{domain_id}/{action}"))?)
        .json(&body);
    if let Some(t) = token {
        rb = rb.header("x-auth-token", t);
    }
    let rsp = rb.send().await?;
    let status = rsp.status();
    Ok((status, rsp.json().await.unwrap_or(Value::Null)))
}

async fn admin_token() -> Result<String> {
    use secrecy::ExposeSecret;
    let mut admin = TestClient::new()?;
    admin.auth_admin_system().await?;
    Ok(admin
        .token
        .as_ref()
        .ok_or_else(|| eyre!("admin has no token"))?
        .expose_secret()
        .to_string())
}

#[tokio::test]
#[traced_test]
async fn test_rotation_publishes_new_key_and_keeps_old_tokens_verifiable() -> Result<()> {
    let f = fixture().await?;
    let admin = admin_token().await?;

    let old_token = issue_id_token(&f).await?;
    let old_kid = jwt_header(&old_token)?["kid"]
        .as_str()
        .ok_or_else(|| eyre!("no kid in old token header"))?
        .to_string();
    assert!(jwks_kids(&f.domain_id).await?.contains(&old_kid));

    let (status, body) =
        key_call(&f.domain_id, "rotate-signing-key", Some(&admin), json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new_kid = body["kid"]
        .as_str()
        .ok_or_else(|| eyre!("no kid in {body}"))?
        .to_string();
    assert_ne!(new_kid, old_kid);

    // JWKS publishes the new key and still carries the old one so tokens
    // issued before the rotation keep verifying.
    let kids = eventually(|| async {
        let kids = jwks_kids(&f.domain_id).await?;
        if kids.contains(&new_kid) {
            Ok(Some(kids))
        } else {
            Ok(None)
        }
    })
    .await?;
    assert!(
        kids.contains(&old_kid),
        "old key dropped at rotation: {kids:?}"
    );

    // New tokens are signed with the new key.
    let new_token = issue_id_token(&f).await?;
    assert_eq!(jwt_header(&new_token)?["kid"], new_kid.as_str());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_ensure_signing_key_is_idempotent() -> Result<()> {
    let f = fixture().await?;
    let admin = admin_token().await?;
    let (status, first) =
        key_call(&f.domain_id, "ensure-signing-key", Some(&admin), json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (status, second) =
        key_call(&f.domain_id, "ensure-signing-key", Some(&admin), json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(first["kid"], second["kid"]);
    assert!(
        jwks_kids(&f.domain_id)
            .await?
            .contains(&first["kid"].as_str().unwrap_or_default().to_string())
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_emergency_rotation_is_staged_and_needs_second_operator() -> Result<()> {
    let f = fixture().await?;
    let admin = admin_token().await?;
    let kids_before = jwks_kids(&f.domain_id).await?;

    let (status, body) = key_call(
        &f.domain_id,
        "rotate-signing-key",
        Some(&admin),
        json!({"emergency": true}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["kid"].is_null(), "{body}");
    let rotation_id = body["pending_rotation_id"]
        .as_str()
        .ok_or_else(|| eyre!("no pending_rotation_id in {body}"))?;
    assert!(body["expires_at"].is_i64(), "{body}");

    // Staging alone changes nothing in the JWKS.
    assert_eq!(jwks_kids(&f.domain_id).await?, kids_before);

    // The operator who staged it cannot also confirm it.
    let (status, body) = key_call(
        &f.domain_id,
        "confirm-rotate-signing-key",
        Some(&admin),
        json!({"rotation_id": rotation_id}),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(jwks_kids(&f.domain_id).await?, kids_before);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_key_management_requires_system_admin() -> Result<()> {
    let f = fixture().await?;
    let manager = project_role_token(&f.domain_id, "manager").await?;
    let kids_before = jwks_kids(&f.domain_id).await?;

    for action in ["rotate-signing-key", "ensure-signing-key"] {
        let (status, body) = key_call(&f.domain_id, action, Some(&manager), json!({})).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{action}: {body}");
        let (status, body) = key_call(&f.domain_id, action, None, json!({})).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{action}: {body}");
    }
    let (status, body) = key_call(
        &f.domain_id,
        "confirm-rotate-signing-key",
        Some(&manager),
        json!({"rotation_id": "x"}),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = key_call(
        &f.domain_id,
        "confirm-rotate-signing-key",
        None,
        json!({"rotation_id": "x"}),
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    assert_eq!(jwks_kids(&f.domain_id).await?, kids_before);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_confirm_unknown_rotation_is_not_found() -> Result<()> {
    let f = fixture().await?;
    let admin = admin_token().await?;
    let (status, body) = key_call(
        &f.domain_id,
        "confirm-rotate-signing-key",
        Some(&admin),
        json!({"rotation_id": "does-not-exist"}),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    Ok(())
}
