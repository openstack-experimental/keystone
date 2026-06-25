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

//! OIDC utilities replacing the openidconnect crate.
//!
//! Covers discovery, PKCE, authorization URL building, token exchange, and JWT
//! verification using reqwest + jsonwebtoken directly.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, Header, TokenData, Validation, decode, decode_header, jwk::JwkSet,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

use super::error::OidcError;

/// Subset of the OIDC Provider Metadata we actually use.
#[derive(Debug, Deserialize)]
pub(super) struct OidcProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// Fetch and parse OIDC discovery metadata from `{issuer_url}/.well-known/openid-configuration`.
pub(super) async fn discover(
    issuer_url: &str,
    client: &reqwest::Client,
) -> Result<OidcProviderMetadata, OidcError> {
    let base = issuer_url.trim_end_matches('/');
    let url = format!("{base}/.well-known/openid-configuration");
    let metadata = client
        .get(&url)
        .send()
        .await
        .map_err(OidcError::from)?
        .error_for_status()
        .map_err(OidcError::from)?
        .json::<OidcProviderMetadata>()
        .await
        .map_err(OidcError::from)?;
    Ok(metadata)
}

/// PKCE S256 challenge/verifier pair.
pub(super) struct PkceChallenge {
    /// Random verifier sent at token exchange time.
    pub verifier: String,
    /// SHA-256 hash of the verifier, sent at authorization time.
    pub challenge: String,
}

/// Generate a fresh PKCE S256 challenge/verifier pair.
pub(super) fn generate_pkce() -> PkceChallenge {
    let verifier = generate_random_token();
    let hash = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hash);
    PkceChallenge {
        verifier,
        challenge,
    }
}

/// Generate a cryptographically random base64url-encoded token (32 bytes).
pub(super) fn generate_random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Build an OIDC authorization URL.
///
/// Adds `openid` scope automatically; caller provides any additional scopes.
pub(super) fn build_auth_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    extra_scopes: &[String],
    state: &str,
    nonce: &str,
    pkce_challenge: &str,
) -> Result<String, OidcError> {
    let mut url = Url::parse(authorization_endpoint)?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", client_id);
        q.append_pair("redirect_uri", redirect_uri);

        let mut scopes: Vec<&str> = vec!["openid"];
        for s in extra_scopes {
            scopes.push(s.as_str());
        }
        q.append_pair("scope", &scopes.join(" "));

        q.append_pair("state", state);
        q.append_pair("nonce", nonce);
        q.append_pair("code_challenge", pkce_challenge);
        q.append_pair("code_challenge_method", "S256");
    }
    Ok(url.to_string())
}

/// Response body from the token endpoint.
#[derive(Debug, Deserialize)]
pub(super) struct TokenExchangeResponse {
    pub id_token: Option<String>,
    #[allow(dead_code)]
    pub access_token: String,
    #[allow(dead_code)]
    pub token_type: String,
    #[allow(dead_code)]
    pub expires_in: Option<u64>,
}

/// Exchange an authorization code for tokens at the token endpoint.
pub(super) async fn exchange_code(
    token_endpoint: &str,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    http_client: &reqwest::Client,
) -> Result<TokenExchangeResponse, OidcError> {
    let mut params: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];
    if let Some(secret) = client_secret {
        params.push(("client_secret", secret));
    }

    let response = http_client
        .post(token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(OidcError::from)?
        .error_for_status()
        .map_err(OidcError::from)?
        .json::<TokenExchangeResponse>()
        .await
        .map_err(OidcError::from)?;
    Ok(response)
}

/// Fetch a JWKS from the given URI.
pub(super) async fn fetch_jwks(
    jwks_uri: &str,
    client: &reqwest::Client,
) -> Result<JwkSet, OidcError> {
    let jwks = client
        .get(jwks_uri)
        .send()
        .await
        .map_err(OidcError::from)?
        .error_for_status()
        .map_err(OidcError::from)?
        .json::<JwkSet>()
        .await
        .map_err(OidcError::from)?;
    Ok(jwks)
}

/// Algorithms that are safe to use with JWKS (asymmetric only).
fn is_asymmetric(alg: Algorithm) -> bool {
    matches!(
        alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::EdDSA
    )
}

/// Decode and verify a JWT using JWKS.
///
/// - `issuer`: validates the `iss` claim when `Some`.
/// - `expected_nonce`: validates the `nonce` claim when `Some` (OIDC flows).
/// - `audiences`: validates the `aud` claim when non-empty.
///
/// Returns the decoded claims as a `serde_json::Value`.
pub(super) fn verify_jwt(
    token: &str,
    jwks: &JwkSet,
    issuer: Option<&str>,
    expected_nonce: Option<&str>,
    audiences: &[&str],
) -> Result<serde_json::Value, OidcError> {
    let header: Header = decode_header(token)?;

    if !is_asymmetric(header.alg) {
        return Err(OidcError::UnsupportedAlgorithm(format!("{:?}", header.alg)));
    }

    // Find the right JWK: by kid if present, otherwise try all keys.
    let decoding_key = if let Some(kid) = &header.kid {
        let jwk = jwks
            .find(kid)
            .ok_or_else(|| OidcError::JwkNotFound(kid.clone()))?;
        DecodingKey::from_jwk(jwk)?
    } else {
        // No kid — try all keys, return first that verifies.
        let mut last_err: Option<jsonwebtoken::errors::Error> = None;
        for jwk in &jwks.keys {
            match DecodingKey::from_jwk(jwk) {
                Ok(key) => {
                    let mut val = build_validation(header.alg, issuer, audiences);
                    val.validate_exp = true;
                    match decode::<serde_json::Value>(token, &key, &val) {
                        Ok(data) => {
                            check_nonce(&data, expected_nonce)?;
                            return Ok(data.claims);
                        }
                        Err(e) => last_err = Some(e),
                    }
                }
                Err(e) => last_err = Some(e),
            }
        }
        return Err(last_err
            .map(OidcError::from)
            .unwrap_or(OidcError::NoJwksKeys));
    };

    let validation = build_validation(header.alg, issuer, audiences);
    let data: TokenData<serde_json::Value> = decode(token, &decoding_key, &validation)?;
    check_nonce(&data, expected_nonce)?;
    Ok(data.claims)
}

fn build_validation(alg: Algorithm, issuer: Option<&str>, audiences: &[&str]) -> Validation {
    let mut val = Validation::new(alg);
    if let Some(iss) = issuer {
        val.set_issuer(&[iss]);
    }
    if audiences.is_empty() {
        val.validate_aud = false;
    } else {
        val.set_audience(audiences);
    }
    val
}

fn check_nonce(
    data: &TokenData<serde_json::Value>,
    expected_nonce: Option<&str>,
) -> Result<(), OidcError> {
    if let Some(expected) = expected_nonce {
        let actual = data
            .claims
            .get("nonce")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if actual != expected {
            return Err(OidcError::NonceMismatch);
        }
    }
    Ok(())
}

/// Build a `reqwest::Client` with redirect following disabled (SSRF guard).
pub(super) fn build_http_client() -> Result<reqwest::Client, OidcError> {
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(OidcError::from)
}
