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
//! Live-server `authorization_code` + PKCE browser flow (ADR 0026 §10 Phase
//! 4): `GET /authorize` -> `POST /authorize/login` -> `POST
//! /authorize/consent` -> code -> `POST /token`, driven by a cookie-jar
//! client with redirects disabled.

use eyre::{Result, eyre};
use reqwest::StatusCode;
use serde_json::json;
use tracing_test::traced_test;

use test_api::oauth2::{call_userinfo, get_well_known};
use test_api::oauth2_browser::*;

struct Fixture {
    domain_id: String,
    client: BrowserClient,
    username: String,
}

async fn fixture() -> Result<Fixture> {
    let domain_id = create_ready_domain("authz-browser").await?;
    let client = create_browser_client(&domain_id, json!({})).await?;
    let (_id, username) = create_browser_user(&domain_id).await?;
    Ok(Fixture {
        domain_id,
        client,
        username,
    })
}

#[tokio::test]
#[traced_test]
async fn test_authorization_code_pkce_full_flow() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, verifier) = AuthorizeParams::new(&f.client.client_id);

    // 1. /authorize without a session renders the login form.
    let rsp = browser.authorize(&params).await?;
    assert!(rsp.is_login(), "{}: {}", rsp.status, rsp.body);
    // 2. login renders the consent dialog showing the client.
    let rsp = browser.login(&rsp.csrf()?, &f.username, PASSWORD).await?;
    assert!(rsp.is_consent(), "{}: {}", rsp.status, rsp.body);
    assert!(rsp.body.contains("browser test client"));
    // 3. consent redirects to the RP with code + state.
    let rsp = browser.consent(&rsp.csrf()?, "allow", false).await?;
    assert_eq!(rsp.status, StatusCode::SEE_OTHER, "{}", rsp.body);
    let location = rsp.location().ok_or_else(|| eyre!("no Location"))?;
    assert!(location.starts_with(REDIRECT_URI), "{location}");
    assert_eq!(rsp.location_param("state"), Some(params.state.clone()));
    let code = rsp
        .location_param("code")
        .ok_or_else(|| eyre!("no code in {location}"))?;

    // 4. code -> tokens.
    let (status, body) = exchange_code(&f.domain_id, &f.client.client_id, &code, &verifier).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["access_token"].as_str().is_some());
    let id_token = body["id_token"]
        .as_str()
        .ok_or_else(|| eyre!("no id_token in {body}"))?;
    let claims = jwt_claims(id_token)?;
    assert_eq!(
        Some(claims["nonce"].as_str()),
        Some(params.nonce.as_deref())
    );
    assert_eq!(claims["aud"], f.client.client_id.as_str());
    assert!(
        claims["auth_time"].as_i64().is_some_and(|t| t > 0),
        "{claims}"
    );
    assert!(
        claims["amr"].as_array().is_some_and(|a| !a.is_empty()),
        "amr missing: {claims}"
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authorize_rejects_plain_pkce_method() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (mut params, _) = AuthorizeParams::new(&f.client.client_id);
    params.code_challenge_method = "plain".to_string();

    let rsp = browser.authorize(&params).await?;
    assert_eq!(rsp.status, StatusCode::SEE_OTHER, "{}", rsp.body);
    assert_eq!(
        rsp.location_param("error").as_deref(),
        Some("invalid_request")
    );
    assert_eq!(rsp.location_param("state"), Some(params.state));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authorize_without_code_challenge_is_rejected() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (mut params, _) = AuthorizeParams::new(&f.client.client_id);
    params.code_challenge = None;
    // PKCE is mandatory for every client.
    let rsp = browser.authorize(&params).await?;
    assert_eq!(rsp.status, StatusCode::SEE_OTHER, "{}", rsp.body);
    assert_eq!(
        rsp.location_param("error").as_deref(),
        Some("invalid_request")
    );
    assert!(rsp.location_param("code").is_none());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authorize_unregistered_redirect_uri_renders_error_not_redirect() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (mut params, _) = AuthorizeParams::new(&f.client.client_id);
    params.redirect_uri = "https://evil.example.com/callback".to_string();

    let rsp = browser.authorize(&params).await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST, "{}", rsp.body);
    assert!(rsp.location().is_none(), "must never redirect to {rsp:?}");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authorize_unknown_client_is_bad_request() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, _) = AuthorizeParams::new("no-such-client");
    let rsp = browser.authorize(&params).await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST, "{}", rsp.body);
    assert!(rsp.location().is_none());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authorize_client_from_other_domain_is_rejected() -> Result<()> {
    let f = fixture().await?;
    let other = create_ready_domain("authz-other").await?;
    let browser = AuthorizeBrowser::new(&other)?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params).await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST, "{}", rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authorize_wrong_password_rerenders_login() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params).await?;
    let rsp = browser
        .login(&rsp.csrf()?, &f.username, "definitely-wrong")
        .await?;
    assert!(rsp.location_param("code").is_none());
    assert!(
        rsp.is_login() || rsp.status == StatusCode::UNAUTHORIZED,
        "{}: {}",
        rsp.status,
        rsp.body
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authorize_login_with_bad_csrf_is_rejected() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    browser.authorize(&params).await?;
    let rsp = browser.login("forged-csrf", &f.username, PASSWORD).await?;
    assert!(rsp.location_param("code").is_none());
    assert!(!rsp.is_consent(), "{}: {}", rsp.status, rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authorize_consent_deny_redirects_access_denied() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = browser.authorize(&params).await?;
    let rsp = browser.login(&rsp.csrf()?, &f.username, PASSWORD).await?;
    let rsp = browser.consent(&rsp.csrf()?, "deny", false).await?;
    assert_eq!(rsp.status, StatusCode::SEE_OTHER, "{}", rsp.body);
    assert_eq!(
        rsp.location_param("error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(rsp.location_param("state"), Some(params.state));
    assert!(rsp.location_param("code").is_none());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authorization_code_cannot_be_reused() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, verifier) = AuthorizeParams::new(&f.client.client_id);
    let code = browser.obtain_code(&params, &f.username, PASSWORD).await?;

    let (status, body) = exchange_code(&f.domain_id, &f.client.client_id, &code, &verifier).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = exchange_code(&f.domain_id, &f.client.client_id, &code, &verifier).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authorization_code_with_wrong_verifier_is_invalid_grant() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, _verifier) = AuthorizeParams::new(&f.client.client_id);
    let code = browser.obtain_code(&params, &f.username, PASSWORD).await?;
    let (wrong, _) = pkce();
    let (status, body) = exchange_code(&f.domain_id, &f.client.client_id, &code, &wrong).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authorization_code_with_wrong_redirect_uri_is_invalid_grant() -> Result<()> {
    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, verifier) = AuthorizeParams::new(&f.client.client_id);
    let code = browser.obtain_code(&params, &f.username, PASSWORD).await?;
    let (status, body) = test_api::oauth2::post_token_form(
        &f.domain_id,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", &f.client.client_id),
            ("code", &code),
            ("redirect_uri", "https://rp.example.com/other"),
            ("code_verifier", &verifier),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_authorization_code_cannot_be_redeemed_by_other_client() -> Result<()> {
    let f = fixture().await?;
    let other = create_browser_client(&f.domain_id, json!({})).await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (params, verifier) = AuthorizeParams::new(&f.client.client_id);
    let code = browser.obtain_code(&params, &f.username, PASSWORD).await?;
    let (status, body) = exchange_code(&f.domain_id, &other.client_id, &code, &verifier).await?;
    assert!(status.is_client_error(), "{status}: {body}");
    Ok(())
}

/// Conformance gate: validate the ID token with a standard RP library
/// (signature via the live JWKS, nonce, `at_hash`) and call `/userinfo`.
#[tokio::test]
#[traced_test]
async fn test_authorization_code_flow_id_token_interop() -> Result<()> {
    use openidconnect::core::{
        CoreIdToken, CoreIdTokenVerifier, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
    };
    use openidconnect::{AccessToken, AccessTokenHash, ClientId, IssuerUrl, Nonce};

    let f = fixture().await?;
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let (mut params, verifier) = AuthorizeParams::new(&f.client.client_id);
    params.scope = "openid profile".to_string();
    let code = browser.obtain_code(&params, &f.username, PASSWORD).await?;
    let (status, body) = exchange_code(&f.domain_id, &f.client.client_id, &code, &verifier).await?;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, doc) = get_well_known(&f.domain_id).await?;
    let issuer = IssuerUrl::new(
        doc["issuer"]
            .as_str()
            .ok_or_else(|| eyre!("no issuer"))?
            .to_string(),
    )?;
    let jwks_uri = doc["jwks_uri"]
        .as_str()
        .ok_or_else(|| eyre!("no jwks_uri"))?;
    let jwks_raw: serde_json::Value = reqwest::get(jwks_uri).await?.json().await?;
    let jwks: CoreJsonWebKeySet = serde_json::from_value(jwks_raw.clone())?;

    let id_token: CoreIdToken = serde_json::from_value(body["id_token"].clone())?;
    // The OP signs with ES256; the library default allows RS256 only.
    let verifier = CoreIdTokenVerifier::new_public_client(
        ClientId::new(f.client.client_id.clone()),
        issuer,
        jwks,
    )
    .set_allowed_algs([CoreJwsSigningAlgorithm::EcdsaP256Sha256]);
    let nonce = Nonce::new(params.nonce.clone().ok_or_else(|| eyre!("no nonce"))?);
    let claims = id_token.claims(&verifier, &nonce).map_err(|e| {
        let k = &jwks_raw["keys"][0];
        let jwt_check = jsonwebtoken::DecodingKey::from_ec_components(
            k["x"].as_str().unwrap_or_default(),
            k["y"].as_str().unwrap_or_default(),
        )
        .map(|key| {
            let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
            v.set_audience(&[f.client.client_id.as_str()]);
            jsonwebtoken::decode::<serde_json::Value>(
                body["id_token"].as_str().unwrap_or_default(),
                &key,
                &v,
            )
            .map(|_| "ok".to_string())
            .unwrap_or_else(|e| e.to_string())
        });
        eyre!("id_token verification failed: {e:?}; jsonwebtoken says {jwt_check:?}")
    })?;

    let access = body["access_token"]
        .as_str()
        .ok_or_else(|| eyre!("no access_token"))?;
    if let Some(expected) = claims.access_token_hash() {
        let actual = AccessTokenHash::from_token(
            &AccessToken::new(access.to_string()),
            id_token.signing_alg()?,
            id_token.signing_key(&verifier)?,
        )?;
        assert_eq!(&actual, expected, "at_hash mismatch");
    }

    let (status, _, info) = call_userinfo(&f.domain_id, false, Some(access)).await?;
    assert_eq!(status, StatusCode::OK, "{info}");
    assert_eq!(info["sub"].as_str(), Some(claims.subject().as_str()));
    assert_eq!(info["preferred_username"], f.username.as_str());
    Ok(())
}
