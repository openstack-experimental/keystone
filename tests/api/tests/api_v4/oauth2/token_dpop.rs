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
//! Live-server DPoP flow at `/token` and the domain settings that switch it
//! on (RFC 9449, ADR 0043).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use eyre::{Result, eyre};
use reqwest::StatusCode;
use reqwest::header::HeaderMap;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing_test::traced_test;

use test_api::common::TestClient;
use test_api::oauth2::{get_well_known, post_introspect_form};
use test_api::oauth2_browser::*;

/// Fixed proof key of these tests.
const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0mBL+Hphh8GGUGdi
gmBwdXtr0cZMOm/ZXd7WQelR3umhRANCAASxIa1qgs06aj9LNbZGgn5Mf+pjqf/q
u9kjxPUBs14LLJlWTBwQxPJ6GLO+UoZswTJWTmawRuC2EyKWhJaSPxwA
-----END PRIVATE KEY-----
";
const KEY_X: &str = "sSGtaoLNOmo_SzW2RoJ-TH_qY6n_6rvZI8T1AbNeCyw";
const KEY_Y: &str = "mVZMHBDE8noYs75ShmzBMlZOZrBG4LYTIpaElpI_HAA";

/// RFC 7638 thumbprint of the proof key.
fn jkt() -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{KEY_X}","y":"{KEY_Y}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

/// A fresh `POST {htu}` proof.
fn proof(htu: &str, nonce: Option<&str>) -> Result<String> {
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {"kty": "EC", "crv": "P-256", "x": KEY_X, "y": KEY_Y},
    });
    let mut claims = json!({
        "jti": uuid::Uuid::new_v4().to_string(),
        "htm": "POST",
        "htu": htu,
        "iat": chrono::Utc::now().timestamp(),
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = nonce.into();
    }
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    openstack_keystone_jwt_crypto::install();
    let signature = jsonwebtoken::crypto::sign(
        message.as_bytes(),
        &jsonwebtoken::EncodingKey::from_ec_pem(KEY_PEM.as_bytes())?,
        jsonwebtoken::Algorithm::ES256,
    )?;
    Ok(format!("{message}.{signature}"))
}

fn token_url(domain_id: &str) -> Result<String> {
    let base = std::env::var("KEYSTONE_URL")?.parse::<url::Url>()?;
    Ok(base
        .join(&format!("v4/oauth2/{domain_id}/token"))?
        .to_string())
}

/// `client_credentials` with an optional `DPoP` header.
async fn token(
    domain_id: &str,
    client_id: &str,
    secret: &str,
    proof: Option<&str>,
) -> Result<(StatusCode, HeaderMap, Value)> {
    let mut req = test_api::common::http_client()
        .post(token_url(domain_id)?)
        .basic_auth(client_id, Some(secret))
        .form(&[("grant_type", "client_credentials")]);
    if let Some(proof) = proof {
        req = req.header("DPoP", proof);
    }
    let rsp = req.send().await?;
    let status = rsp.status();
    let headers = rsp.headers().clone();
    Ok((status, headers, rsp.json().await?))
}

/// `PUT /v4/oauth2/{domain_id}/settings` as SystemAdmin.
async fn set_dpop(domain_id: &str, mode: &str) -> Result<Value> {
    let mut admin = TestClient::new()?;
    admin.auth_admin_system().await?;
    let rsp = admin
        .client
        .put(
            admin
                .base_url
                .join(&format!("v4/oauth2/{domain_id}/settings"))?,
        )
        .json(&json!({"settings": {"dpop": mode}}))
        .send()
        .await?;
    let status = rsp.status();
    let body: Value = rsp.json().await?;
    if status != StatusCode::OK {
        return Err(eyre!("settings update failed with {status}: {body}"));
    }
    Ok(body)
}

struct Cc {
    domain_id: String,
    client_id: String,
    secret: String,
}

async fn fixture() -> Result<Cc> {
    let domain_id = create_ready_domain("dpop").await?;
    let client = create_browser_client(
        &domain_id,
        json!({
            "confidential": true,
            "grant_types": ["client_credentials"],
            "allowed_scopes": ["openid"],
            "token_endpoint_auth_method": "client_secret_basic",
            "require_pkce": false,
        }),
    )
    .await?;
    bind_client_credentials_ruleset(&domain_id, &client.provider_id).await?;
    let secret = client
        .client_secret
        .clone()
        .ok_or_else(|| eyre!("confidential client returned no secret"))?;
    Ok(Cc {
        domain_id,
        client_id: client.client_id,
        secret,
    })
}

#[tokio::test]
#[traced_test]
async fn test_dpop_disabled_ignores_the_proof() -> Result<()> {
    let cc = fixture().await?;
    let p = proof(&token_url(&cc.domain_id)?, None)?;
    let (status, _, body) = token(&cc.domain_id, &cc.client_id, &cc.secret, Some(&p)).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_optional_dpop_binds_the_token_after_the_nonce_round_trip() -> Result<()> {
    let cc = fixture().await?;
    let settings = set_dpop(&cc.domain_id, "optional").await?;
    assert_eq!(settings["settings"]["dpop"], "optional", "{settings}");
    let url = token_url(&cc.domain_id)?;

    // Without a proof the token stays a bearer token.
    let (status, _, body) = token(&cc.domain_id, &cc.client_id, &cc.secret, None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "Bearer");

    // A proof without a nonce is answered with a challenge.
    let first = proof(&url, None)?;
    let (status, headers, body) =
        token(&cc.domain_id, &cc.client_id, &cc.secret, Some(&first)).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "use_dpop_nonce");
    let nonce = headers
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| eyre!("no DPoP-Nonce header"))?
        .to_string();

    // With the nonce the token is bound to the proof key.
    let second = proof(&url, Some(&nonce))?;
    let (status, _, body) = token(&cc.domain_id, &cc.client_id, &cc.secret, Some(&second)).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "DPoP");
    let access = body["access_token"]
        .as_str()
        .ok_or_else(|| eyre!("no access_token in {body}"))?;
    assert_eq!(jwt_claims(access)?["cnf"]["jkt"], jkt());

    // The same proof is not accepted twice.
    let (status, _, body) = token(&cc.domain_id, &cc.client_id, &cc.secret, Some(&second)).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_dpop_proof");

    // Introspection reports the binding.
    let (status, intro) = post_introspect_form(
        &cc.domain_id,
        &cc.client_id,
        &cc.secret,
        &[("token", access)],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(intro["active"], true, "{intro}");
    assert_eq!(intro["token_type"], "DPoP");
    assert_eq!(intro["cnf"]["jkt"], jkt());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_required_dpop_rejects_a_request_without_a_proof() -> Result<()> {
    let cc = fixture().await?;
    set_dpop(&cc.domain_id, "required").await?;

    let (status, _, body) = token(&cc.domain_id, &cc.client_id, &cc.secret, None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_dpop_proof");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_discovery_follows_the_domain_mode() -> Result<()> {
    let cc = fixture().await?;
    let (_, doc) = get_well_known(&cc.domain_id).await?;
    assert_eq!(doc["dpop_required"], false, "{doc}");
    assert!(doc.get("dpop_signing_alg_values_supported").is_none());

    set_dpop(&cc.domain_id, "required").await?;
    let (_, doc) = get_well_known(&cc.domain_id).await?;
    assert_eq!(doc["dpop_required"], true, "{doc}");
    assert_eq!(
        doc["dpop_signing_alg_values_supported"],
        json!(["ES256", "RS256"])
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_settings_show_reports_the_stored_mode() -> Result<()> {
    let cc = fixture().await?;
    set_dpop(&cc.domain_id, "optional").await?;

    let mut admin = TestClient::new()?;
    admin.auth_admin_system().await?;
    let rsp = admin
        .client
        .get(
            admin
                .base_url
                .join(&format!("v4/oauth2/{}/settings", cc.domain_id))?,
        )
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::OK);
    let body: Value = rsp.json().await?;
    assert_eq!(body["settings"]["domain_id"], cc.domain_id.as_str());
    assert_eq!(body["settings"]["dpop"], "optional");
    Ok(())
}
