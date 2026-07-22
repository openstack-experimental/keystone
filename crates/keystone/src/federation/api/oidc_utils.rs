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
use secrecy::SecretString;
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

/// Fetch and parse OIDC discovery metadata from
/// `{issuer_url}/.well-known/openid-configuration`.
///
/// Validates per RFC 8414 §3 that the returned `issuer` matches the URL used
/// for discovery.
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

    // RFC 8414 §3: issuer in the document MUST match the URL used for discovery.
    let returned_issuer = metadata.issuer.trim_end_matches('/');
    if returned_issuer != base {
        return Err(OidcError::IssuerMismatch {
            expected: base.to_string(),
            actual: returned_issuer.to_string(),
        });
    }

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
///
/// `id_token` and `access_token` are OAuth/OIDC bearer tokens: wrapped in
/// [`SecretString`] so this `Debug`-deriving struct can never leak them through
/// tracing/logs. They are consumed only at the JWT-verification boundary.
#[derive(Debug, Deserialize)]
pub(super) struct TokenExchangeResponse {
    pub id_token: Option<SecretString>,
    #[allow(dead_code)]
    pub access_token: Option<SecretString>,
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
                    let val = build_validation(header.alg, issuer, audiences);
                    match decode::<serde_json::Value>(token, &key, &val) {
                        Ok(data) => {
                            check_nonce(&data, expected_nonce)?;
                            check_iat(&data)?;
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
    check_iat(&data)?;
    Ok(data.claims)
}

/// Validate the `iat` (issued-at) claim is not suspiciously far in the future.
///
/// jsonwebtoken does not check `iat` freshness. OIDC Core §3.2.1.1 requires
/// the RP to reject tokens whose `iat` is more than a reasonable window in the
/// future (we use 1 hour + leeway).
fn check_iat(data: &TokenData<serde_json::Value>) -> Result<(), OidcError> {
    let iat = data.claims.get("iat").and_then(|v| v.as_u64()).unwrap_or(0);
    let now = chrono::Utc::now().timestamp() as u64;
    if iat > now + IAT_FUTURE_MAX_SECS {
        return Err(OidcError::IatInFuture { iat, now });
    }
    Ok(())
}

/// Maximum allowed `iat` skew (seconds). OIDC Core §3.2.1.1 requires
/// rejecting tokens whose `iat` is more than 1 hour in the future.
const IAT_FUTURE_MAX_SECS: u64 = 3600;

fn build_validation(alg: Algorithm, issuer: Option<&str>, audiences: &[&str]) -> Validation {
    let mut val = Validation::new(alg);
    // Enforce not-before claim per RFC 7519 §4.1.5 (not enabled by default in
    // jsonwebtoken).
    val.validate_nbf = true;
    // OIDC spec recommends 60s clock skew tolerance for exp/nbf/iat validation.
    val.leeway = 60;
    // OIDC Core §3.1.3.7 and §3.1.2: `sub` and `aud` are REQUIRED ID token
    // claims. `exp` is added by default by `Validation::new(alg)`.
    val.required_spec_claims
        .extend(["sub", "aud"].map(String::from));
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

/// Build a `reqwest::Client` with redirect following disabled (SSRF guard)
/// and a reasonable default timeout to prevent resource exhaustion.
pub(super) fn build_http_client() -> Result<reqwest::Client, OidcError> {
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(OidcError::from)
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;
    use chrono::{TimeDelta, Utc};
    use httpmock::prelude::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header as JwtHeader, encode, jwk::JwkSet};
    use serde_json::json;

    // RSA-2048 test key pair (PKCS#8 PEM + corresponding JWK n/e).
    // Generated offline with openssl and verified against jsonwebtoken.
    const TEST_RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCV6tfl03xepqw6\n\
7fphuiONQC1PI1r3po83jDOoX3fhdp7zUQa6m8pueK5tJK+y/iwwK0ok9bRQl5OF\n\
R08myyW6fPbz9sw2JUNyLfSmAht4dzj+m0FOITMbURCu0mpgDI8ciqcQVuKK4EDT\n\
FBa8p+/9pf5ROQKgewbJnTjAJcDcOOkLjmPyUfEknbCsRuTLesVRb++PLV/vCz7u\n\
3nvMG1/9NYPH2BxM7oBxcdX3tQRNtcjcdAkks5zZUQjLLny4UgicIKw8Jxn+bf16\n\
FZEPkS4vfKtAYTscmjZrsT0nZtvTEFATNd39TMEj6U47Dae/AibVSU4/zbNFO3G8\n\
hr1ySf1PAgMBAAECgf8qnnxQS7K6UjX5pzwVNvIA4JMdXiiasKKxC3/c7CqaQ3QJ\n\
DVUxt8MNpM9/xe4tEPibY7MiJA0Caoa+ldx41YCrZxQi8bEcXiZAMwk9fc2mxuil\n\
6tKJgAMj3Vmn57fkQQMY/acrjDJpSKyzVR8hn0co8UCUSGfojNgoP/vFwLz2wXIL\n\
mcy5banAlgUwJOAcgTfR/dI7wtSKaHqqt12lCkpyV4LVBIppn+/lAbiTU0eqzCoz\n\
DxA2HlSWmvpZp6rNRFlk3086VTes+TX+TnPn/nemJTeJnxJ1mFRa2m97Vp60BiOR\n\
XU8+B/H/y09TVPELfh2Drbp5xbRDoult/x7zxGkCgYEA0nXoELcW09K5BOi0rKBl\n\
qip2c8JQKOz/GLCM6fe8ZrOODcS9M5GwsM5EFl4Z2rKT+d0Cj959MrxaFBvs7oT8\n\
UyuVMavNgbXQFohHMWbexrcMf61EbfQC9TWPMJw405HqjyUjNo/amfPrCDX6U1S8\n\
AxcJ5hj8zxIUKYkbl25eth0CgYEAtltAeGPbjzNQK5Tfxe0qOaq7bbhySqlFJGqT\n\
5cNPLR7IDKe+JDBNYxyJYnyFZKYxpGgu42nrz/sv+xgetaHIeak4GayTb5sxpcp3\n\
Nd9oAMNHNnX6N5LlxkXnxQOSgtT3BGrvIMxk/HrHQCCFsBwkWtOv5XWRVWo8jMGd\n\
lZW0dVsCgYAVwBO0rodQauWuKTKK6KS5GlxViE5qfFu8vHpDr9OrtYDH0X5QNw1Q\n\
qHCG80CuxmfemcWrAq5jsO2KSHyLBflhyw5HLN83OYgA3CKna184oDBNfaWly2MG\n\
3nsm5e5Fhz37fzYNbH6GDJxMo+9z7zzjAN2IBysRZ2foBwBv/PsSzQKBgQCvY5rh\n\
b+HHnGnaUOjdHBtFtaFpiUJb7uwyd1NiZHQtiHKOQXPOqKp1zgeRMwS1ZmdOomme\n\
jsygkA546Zz3wu/nm8r6XpK7gD/DHrWDmikUur0uc1BCzUW0ap3dTm9G6H/gvtzZ\n\
5dynPYuQcPdEB/0rYnjGMEqlJXWxR7NCIOedCwKBgQCemeC5iU+EdVONhRj5XRMK\n\
1kMeZZVAywqI9sOJXFIC7FWbMw796lCD62SNYeER6dDGj3+2pkMHgZrncOzRSX2G\n\
aAmc9ACPh/hdBmHlSF++nRg+5t+4okyZHe3dgCYUM7n5tq5OFvyrfZ1lmGQlHcyD\n\
w61t8gqclj1jTxn4LURp0Q==\n\
-----END PRIVATE KEY-----\n";

    // Base64urlUInt-encoded RSA modulus (n) for the key above — 256 raw bytes, no
    // leading zero.
    const TEST_JWK_N: &str = "lerX5dN8XqasOu36YbojjUAtTyNa96aPN4wzqF934Xae81EGupvKbniubSSvsv4s\
MCtKJPW0UJeThUdPJsslunz28_bMNiVDci30pgIbeHc4_ptBTiEzG1EQrtJqYAyP\
HIqnEFbiiuBA0xQWvKfv_aX-UTkCoHsGyZ04wCXA3DjpC45j8lHxJJ2wrEbky3rF\
UW_vjy1f7ws-7t57zBtf_TWDx9gcTO6AcXHV97UETbXI3HQJJLOc2VEIyy58uFII\
nCCsPCcZ_m39ehWRD5EuL3yrQGE7HJo2a7E9J2bb0xBQEzXd_UzBI-lOOw2nvwIm\
1UlOP82zRTtxvIa9ckn9Tw";

    const TEST_JWK_E: &str = "AQAB";
    const TEST_KID: &str = "test-kid";

    fn rsa_encoding_key() -> EncodingKey {
        EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes())
            .expect("hard-coded test RSA private key must parse")
    }

    fn rsa_jwk(kid: &str) -> jsonwebtoken::jwk::Jwk {
        serde_json::from_value(json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": TEST_JWK_N,
            "e": TEST_JWK_E,
        }))
        .expect("hard-coded test JWK must deserialize")
    }

    fn make_jwt(claims: &serde_json::Value, kid: Option<&str>) -> String {
        let mut header = JwtHeader::new(Algorithm::RS256);
        header.kid = kid.map(str::to_owned);
        encode(&header, claims, &rsa_encoding_key()).expect("test JWT must encode")
    }

    fn valid_claims(iss: &str, aud: &str, nonce: Option<&str>) -> serde_json::Value {
        let exp = (Utc::now() + TimeDelta::hours(1)).timestamp();
        let mut c = json!({
            "sub": "user123",
            "iss": iss,
            "aud": aud,
            "exp": exp,
            "iat": Utc::now().timestamp(),
        });
        if let Some(n) = nonce {
            c["nonce"] = json!(n);
        }
        c
    }

    // ── PKCE ─────────────────────────────────────────────────────────────────

    #[test]
    fn pkce_challenge_is_sha256_of_verifier() {
        let pkce = generate_pkce();
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce.verifier.as_bytes()));
        assert_eq!(pkce.challenge, expected);
    }

    #[test]
    fn pkce_verifier_is_base64url_no_padding() {
        let pkce = generate_pkce();
        assert!(
            !pkce.verifier.contains('+'),
            "must not use + (standard base64)"
        );
        assert!(
            !pkce.verifier.contains('/'),
            "must not use / (standard base64)"
        );
        assert!(!pkce.verifier.contains('='), "must not have padding");
        // 32 raw bytes → 43 base64url chars; RFC 7636 requires 43–128 chars.
        assert!(
            (43..=128).contains(&pkce.verifier.len()),
            "verifier length {} out of RFC 7636 range",
            pkce.verifier.len()
        );
    }

    #[test]
    fn pkce_pairs_are_unique() {
        let p1 = generate_pkce();
        let p2 = generate_pkce();
        assert_ne!(p1.verifier, p2.verifier);
        assert_ne!(p1.challenge, p2.challenge);
    }

    // ── Random token ─────────────────────────────────────────────────────────

    #[test]
    fn random_token_is_base64url_no_padding() {
        let t = generate_random_token();
        assert!(!t.contains('+'));
        assert!(!t.contains('/'));
        assert!(!t.contains('='));
    }

    #[test]
    fn random_tokens_are_unique() {
        let t1 = generate_random_token();
        let t2 = generate_random_token();
        assert_ne!(t1, t2);
    }

    // ── build_auth_url ────────────────────────────────────────────────────────

    #[test]
    fn auth_url_contains_required_params() {
        let url = build_auth_url(
            "https://idp.example.com/authorize",
            "my-client",
            "https://app.example.com/callback",
            &[],
            "state123",
            "nonce456",
            "challenge789",
        )
        .unwrap();

        assert!(url.contains("response_type=code"), "missing response_type");
        assert!(url.contains("client_id=my-client"), "missing client_id");
        assert!(url.contains("state=state123"), "missing state");
        assert!(url.contains("nonce=nonce456"), "missing nonce");
        assert!(
            url.contains("code_challenge=challenge789"),
            "missing code_challenge"
        );
        assert!(
            url.contains("code_challenge_method=S256"),
            "missing code_challenge_method"
        );
    }

    #[test]
    fn auth_url_always_includes_openid_scope() {
        let url = build_auth_url(
            "https://idp.example.com/auth",
            "cid",
            "https://app.example.com/cb",
            &[],
            "s",
            "n",
            "c",
        )
        .unwrap();

        let parsed = Url::parse(&url).unwrap();
        let scope: String = parsed
            .query_pairs()
            .find(|(k, _)| k == "scope")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        assert!(
            scope.split_whitespace().any(|s| s == "openid"),
            "openid scope missing from '{scope}'"
        );
    }

    #[test]
    fn auth_url_includes_extra_scopes() {
        let extra = vec!["profile".to_string(), "email".to_string()];
        let url = build_auth_url(
            "https://idp.example.com/auth",
            "cid",
            "https://app.example.com/cb",
            &extra,
            "s",
            "n",
            "c",
        )
        .unwrap();

        let parsed = Url::parse(&url).unwrap();
        let scope: String = parsed
            .query_pairs()
            .find(|(k, _)| k == "scope")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        let scopes: Vec<&str> = scope.split_whitespace().collect();
        assert!(scopes.contains(&"openid"));
        assert!(scopes.contains(&"profile"));
        assert!(scopes.contains(&"email"));
    }

    #[test]
    fn auth_url_rejects_invalid_endpoint() {
        let result = build_auth_url("not-a-url", "cid", "https://cb", &[], "s", "n", "c");
        assert!(matches!(result, Err(OidcError::UrlParse { .. })));
    }

    // ── discover ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn discover_success() {
        let server = MockServer::start();
        let base_url = server.base_url();
        server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(json!({
                "issuer": base_url,
                "authorization_endpoint": format!("{base_url}/auth"),
                "token_endpoint": format!("{base_url}/token"),
                "jwks_uri": format!("{base_url}/jwks"),
            }));
        });

        let client = reqwest::Client::new();
        let metadata = discover(&base_url, &client).await.unwrap();
        assert_eq!(metadata.issuer, base_url);
        assert!(metadata.authorization_endpoint.ends_with("/auth"));
    }

    #[tokio::test]
    async fn discover_strips_trailing_slash() {
        let server = MockServer::start();
        let base_url = server.base_url();
        server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(json!({
                "issuer": base_url,
                "authorization_endpoint": format!("{base_url}/auth"),
                "token_endpoint": format!("{base_url}/token"),
                "jwks_uri": format!("{base_url}/jwks"),
            }));
        });

        let client = reqwest::Client::new();
        let url_with_slash = format!("{base_url}/");
        // Should succeed even though trailing slash was appended by caller.
        discover(&url_with_slash, &client).await.unwrap();
    }

    #[tokio::test]
    async fn discover_returns_error_on_http_failure() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(404);
        });

        let client = reqwest::Client::new();
        let result = discover(&server.base_url(), &client).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn discover_rejects_issuer_mismatch() {
        // RFC 8414 §3: returned issuer must equal the URL used for discovery.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(json!({
                "issuer": "https://attacker.example.com",
                "authorization_endpoint": "https://attacker.example.com/auth",
                "token_endpoint": "https://attacker.example.com/token",
                "jwks_uri": "https://attacker.example.com/jwks",
            }));
        });

        let client = reqwest::Client::new();
        let result = discover(&server.base_url(), &client).await;
        assert!(
            matches!(result, Err(OidcError::IssuerMismatch { .. })),
            "expected IssuerMismatch, got {result:?}"
        );
    }

    // ── fetch_jwks ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn fetch_jwks_parses_key_set() {
        let server = MockServer::start();
        let jwk_val = json!({
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
            "n": TEST_JWK_N, "e": TEST_JWK_E,
        });
        server.mock(|when, then| {
            when.method(GET).path("/jwks.json");
            then.status(200).json_body(json!({"keys": [jwk_val]}));
        });

        let client = reqwest::Client::new();
        let jwks = fetch_jwks(&format!("{}/jwks.json", server.base_url()), &client)
            .await
            .unwrap();
        assert_eq!(jwks.keys.len(), 1);
    }

    #[tokio::test]
    async fn fetch_jwks_returns_error_on_http_failure() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/jwks.json");
            then.status(500);
        });

        let client = reqwest::Client::new();
        let result = fetch_jwks(&format!("{}/jwks.json", server.base_url()), &client).await;
        assert!(result.is_err());
    }

    // ── exchange_code ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn exchange_code_success() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200).json_body(json!({
                "access_token": "at-value",
                "token_type": "Bearer",
                "id_token": "id.token.value",
                "expires_in": 3600,
            }));
        });

        let client = reqwest::Client::new();
        let resp = exchange_code(
            &format!("{}/token", server.base_url()),
            "client-id",
            None,
            "auth-code",
            "https://app.example.com/cb",
            "pkce-verifier",
            &client,
        )
        .await
        .unwrap();

        assert_eq!(
            resp.access_token.as_ref().map(|s| s.expose_secret()),
            Some("at-value")
        );
        assert_eq!(
            resp.id_token.as_ref().map(|s| s.expose_secret()),
            Some("id.token.value")
        );
    }

    #[test]
    fn token_exchange_response_debug_never_leaks_tokens() {
        let resp: TokenExchangeResponse = serde_json::from_value(json!({
            "id_token": "id.token.LEAKME",
            "access_token": "access.token.LEAKME",
            "token_type": "Bearer",
        }))
        .unwrap();
        // The Debug-derived struct must never render the bearer tokens.
        let dbg = format!("{resp:?}");
        assert!(
            !dbg.contains("LEAKME"),
            "Debug leaked OIDC bearer tokens: {dbg}"
        );
        // ...but the values remain retrievable at the exposure boundary.
        assert_eq!(
            resp.id_token.as_ref().map(|s| s.expose_secret()),
            Some("id.token.LEAKME")
        );
    }

    #[tokio::test]
    async fn exchange_code_passes_client_secret() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST)
                .path("/token")
                .body_includes("client_secret=s3cr3t");
            then.status(200).json_body(json!({
                "access_token": "at",
                "token_type": "Bearer",
            }));
        });

        let client = reqwest::Client::new();
        exchange_code(
            &format!("{}/token", server.base_url()),
            "cid",
            Some("s3cr3t"),
            "code",
            "https://cb",
            "verifier",
            &client,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn exchange_code_returns_error_on_http_failure() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(400);
        });

        let client = reqwest::Client::new();
        let result = exchange_code(
            &format!("{}/token", server.base_url()),
            "cid",
            None,
            "code",
            "https://cb",
            "v",
            &client,
        )
        .await;
        assert!(result.is_err());
    }

    // ── verify_jwt ────────────────────────────────────────────────────────────

    #[test]
    fn verify_jwt_rejects_symmetric_hs256() {
        let key = EncodingKey::from_secret(b"symmetric-secret");
        let exp = (Utc::now() + TimeDelta::hours(1)).timestamp();
        let claims = json!({"sub": "user", "exp": exp});
        let token = encode(&JwtHeader::default(), &claims, &key).unwrap();

        let jwks: JwkSet = serde_json::from_value(json!({"keys": []})).unwrap();
        let result = verify_jwt(&token, &jwks, None, None, &[]);
        assert!(
            matches!(result, Err(OidcError::UnsupportedAlgorithm(_))),
            "expected UnsupportedAlgorithm, got {result:?}"
        );
    }

    #[test]
    fn verify_jwt_valid_rs256_with_kid() {
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let claims = valid_claims("https://iss.example.com", "my-client", None);
        let token = make_jwt(&claims, Some(TEST_KID));

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://iss.example.com"),
            None,
            &["my-client"],
        );
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(result.unwrap()["sub"], "user123");
    }

    #[test]
    fn verify_jwt_rejects_wrong_issuer() {
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let claims = valid_claims("https://iss.example.com", "my-client", None);
        let token = make_jwt(&claims, Some(TEST_KID));

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://other-issuer.example.com"),
            None,
            &["my-client"],
        );
        assert!(matches!(result, Err(OidcError::JwtDecode { .. })));
    }

    #[test]
    fn verify_jwt_rejects_nonce_mismatch() {
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let claims = valid_claims(
            "https://iss.example.com",
            "my-client",
            Some("correct-nonce"),
        );
        let token = make_jwt(&claims, Some(TEST_KID));

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://iss.example.com"),
            Some("wrong-nonce"),
            &["my-client"],
        );
        assert!(matches!(result, Err(OidcError::NonceMismatch)));
    }

    #[test]
    fn verify_jwt_accepts_correct_nonce() {
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let claims = valid_claims("https://iss.example.com", "my-client", Some("my-nonce"));
        let token = make_jwt(&claims, Some(TEST_KID));

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://iss.example.com"),
            Some("my-nonce"),
            &["my-client"],
        );
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn verify_jwt_rejects_unknown_kid() {
        let jwks = JwkSet {
            keys: vec![rsa_jwk("other-kid")],
        };
        let claims = valid_claims("https://iss.example.com", "my-client", None);
        let token = make_jwt(&claims, Some(TEST_KID)); // signed with TEST_KID

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://iss.example.com"),
            None,
            &["my-client"],
        );
        assert!(
            matches!(result, Err(OidcError::JwkNotFound(_))),
            "expected JwkNotFound, got {result:?}"
        );
    }

    #[test]
    fn verify_jwt_falls_back_to_kidless_key_scan() {
        // Token has no kid in header; verify_jwt should try all JWKS keys.
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let claims = valid_claims("https://iss.example.com", "my-client", None);
        let token = make_jwt(&claims, None); // no kid in header

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://iss.example.com"),
            None,
            &["my-client"],
        );
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn verify_jwt_empty_jwks_returns_no_keys_error() {
        // No kid in header, empty JWKS → NoJwksKeys.
        let jwks: JwkSet = serde_json::from_value(json!({"keys": []})).unwrap();
        let claims = valid_claims("https://iss.example.com", "my-client", None);
        let token = make_jwt(&claims, None);

        let result = verify_jwt(&token, &jwks, None, None, &[]);
        assert!(
            matches!(result, Err(OidcError::NoJwksKeys)),
            "expected NoJwksKeys, got {result:?}"
        );
    }

    #[test]
    fn verify_jwt_rejects_expired_token() {
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let exp = (Utc::now() - TimeDelta::hours(1)).timestamp();
        let claims = json!({
            "sub": "user",
            "iss": "https://iss.example.com",
            "aud": "my-client",
            "exp": exp,
            "iat": exp - 3600,
        });
        let token = make_jwt(&claims, Some(TEST_KID));

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://iss.example.com"),
            None,
            &["my-client"],
        );
        assert!(matches!(result, Err(OidcError::JwtDecode { .. })));
    }

    #[test]
    fn verify_jwt_accepts_aud_as_json_array() {
        // OIDC Core §3.1.3.7: real IdPs (Keycloak, Auth0) emit `aud` as a JSON array.
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let exp = (Utc::now() + TimeDelta::hours(1)).timestamp();
        let claims = json!({
            "sub": "user123",
            "iss": "https://iss.example.com",
            "aud": ["my-client", "other-client"],
            "exp": exp,
            "iat": Utc::now().timestamp(),
        });
        let token = make_jwt(&claims, Some(TEST_KID));

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://iss.example.com"),
            None,
            &["my-client"],
        );
        assert!(
            result.is_ok(),
            "aud array containing my-client must validate, got {result:?}"
        );
    }

    #[test]
    fn verify_jwt_rejects_aud_when_none_match() {
        // RFC 7519 §4.1.3: when audience is validated, at least one value must match.
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let exp = (Utc::now() + TimeDelta::hours(1)).timestamp();
        let claims = json!({
            "sub": "user123",
            "iss": "https://iss.example.com",
            "aud": "some-other-client",
            "exp": exp,
            "iat": Utc::now().timestamp(),
        });
        let token = make_jwt(&claims, Some(TEST_KID));

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://iss.example.com"),
            None,
            &["my-client"],
        );
        assert!(
            matches!(result, Err(OidcError::JwtDecode { .. })),
            "aud not in expected audiences must be rejected, got {result:?}"
        );
    }

    #[test]
    fn verify_jwt_selects_correct_kid_from_multi_key_jwks() {
        // RFC 7517 §3: key rotation — JWKS contains multiple keys, verify_jwt must
        // select the one matching the token's kid.
        let jwks = JwkSet {
            keys: vec![rsa_jwk("old-key"), rsa_jwk(TEST_KID), rsa_jwk("unused-key")],
        };
        let claims = valid_claims("https://iss.example.com", "my-client", None);
        let token = make_jwt(&claims, Some(TEST_KID));

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://iss.example.com"),
            None,
            &["my-client"],
        );
        assert!(
            result.is_ok(),
            "must find and verify using the key matching kid from multi-key JWKS, got {result:?}"
        );
    }

    #[test]
    fn verify_jwt_rejects_alg_none() {
        // CVE-2015-9235: algorithm confusion — alg none tokens must be rejected.
        // jsonwebtoken's decode_header fails on `alg: "none"` with a JSON parse error
        // since it doesn't support the `none` variant, producing `JwtDecode`.
        let exp = (Utc::now() + TimeDelta::hours(1)).timestamp();
        let header_b64 = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\",\"typ\":\"JWT\"}");
        let claims_b64 =
            URL_SAFE_NO_PAD.encode(json!({"sub": "attack", "exp": exp}).to_string().as_bytes());
        let token = format!("{header_b64}.{claims_b64}.");

        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let result = verify_jwt(&token, &jwks, None, None, &[]);
        assert!(
            matches!(result, Err(OidcError::JwtDecode { .. })),
            "alg none must be rejected, got {result:?}"
        );
    }

    #[test]
    fn verify_jwt_rejects_missing_nonce_when_expected() {
        // OIDC Core §3.1.3.6: nonce is REQUIRED in ID tokens for authorization code
        // flows. When caller expects a nonce but token lacks the claim,
        // verification must fail.
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let claims = valid_claims("https://iss.example.com", "my-client", None);
        let token = make_jwt(&claims, Some(TEST_KID));

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://iss.example.com"),
            Some("expected-nonce"),
            &["my-client"],
        );
        assert!(
            matches!(result, Err(OidcError::NonceMismatch)),
            "missing nonce claim with expected nonce must fail, got {result:?}"
        );
    }

    #[test]
    fn verify_jwt_rejects_future_nbf() {
        // RFC 7519 §4.1.5: nbf (not-before) — token with nbf in the future must be
        // rejected.
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let nbf_future = (Utc::now() + TimeDelta::hours(1)).timestamp();
        let claims = json!({
            "sub": "user",
            "iss": "https://iss.example.com",
            "aud": "my-client",
            "exp": nbf_future + 3600,
            "iat": Utc::now().timestamp(),
            "nbf": nbf_future,
        });
        let token = make_jwt(&claims, Some(TEST_KID));

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://iss.example.com"),
            None,
            &["my-client"],
        );
        assert!(
            matches!(result, Err(OidcError::JwtDecode { .. })),
            "nbf in the future must cause rejection, got {result:?}"
        );
    }

    #[test]
    fn verify_jwt_does_not_panic_on_malformed_token() {
        // Malformed JWT (bad base64, wrong segments) must produce JwtDecode, not a
        // panic.
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let result = verify_jwt("not-a-jwt-at-all", &jwks, None, None, &[]);
        assert!(
            matches!(result, Err(OidcError::JwtDecode { .. })),
            "malformed JWT must produce JwtDecode, got {result:?}"
        );
    }

    #[test]
    fn verify_jwt_rejects_tampered_signature() {
        // A validly-signed token whose signature is then altered must be rejected:
        // signature validation must be enforced (token tampering).
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let claims = valid_claims("https://iss.example.com", "my-client", None);
        let token = make_jwt(&claims, Some(TEST_KID));

        // Sanity: the untampered token verifies.
        assert!(
            verify_jwt(
                &token,
                &jwks,
                Some("https://iss.example.com"),
                None,
                &["my-client"],
            )
            .is_ok(),
            "the freshly signed token must verify before tampering"
        );

        // Flip the final character of the signature segment.
        let (rest, sig) = token.rsplit_once('.').expect("token has a signature");
        let last = sig.chars().next_back().expect("signature is non-empty");
        let replacement = if last == 'A' { 'B' } else { 'A' };
        let tampered = format!("{rest}.{}{replacement}", &sig[..sig.len() - 1]);

        let result = verify_jwt(
            &tampered,
            &jwks,
            Some("https://iss.example.com"),
            None,
            &["my-client"],
        );
        assert!(
            matches!(result, Err(OidcError::JwtDecode { .. })),
            "a tampered signature must be rejected, got {result:?}"
        );
    }

    #[test]
    fn verify_jwt_rejects_tampered_payload() {
        // Altering the claims after signing (keeping the original signature) must be
        // rejected — the signature no longer matches the payload.
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let claims = valid_claims("https://iss.example.com", "my-client", None);
        let token = make_jwt(&claims, Some(TEST_KID));

        let mut parts = token.split('.');
        let header = parts.next().expect("header segment");
        let _original_payload = parts.next().expect("payload segment");
        let signature = parts.next().expect("signature segment");

        // Re-encode a different set of claims (e.g. impersonating another subject)
        // while keeping the original header and signature.
        let evil_claims = valid_claims("https://iss.example.com", "my-client", None);
        let mut evil_claims = evil_claims;
        evil_claims["sub"] = json!("attacker");
        let evil_payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&evil_claims).expect("claims serialize"));
        let tampered = format!("{header}.{evil_payload}.{signature}");

        let result = verify_jwt(
            &tampered,
            &jwks,
            Some("https://iss.example.com"),
            None,
            &["my-client"],
        );
        assert!(
            matches!(result, Err(OidcError::JwtDecode { .. })),
            "a tampered payload must be rejected, got {result:?}"
        );
    }

    #[tokio::test]
    async fn token_exchange_response_id_token_only() {
        // TokenExchangeResponse with only id_token verifies access_token optionality.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200).json_body(json!({
                "id_token": "id.token.value",
                "token_type": "Bearer",
            }));
        });

        let client = reqwest::Client::new();
        let resp = exchange_code(
            &format!("{}/token", server.base_url()),
            "cid",
            None,
            "code",
            "https://cb",
            "verifier",
            &client,
        )
        .await
        .unwrap();

        assert!(
            resp.access_token.is_none(),
            "access_token must be absent in id-token-only response"
        );
        assert_eq!(
            resp.id_token.as_ref().map(|s| s.expose_secret()),
            Some("id.token.value")
        );
    }

    // ── iat validation ────────────────────────────────────────────────────────

    #[test]
    fn verify_jwt_rejects_iat_too_far_in_future() {
        // OIDC Core §3.2.1.1: iat MUST NOT be more than 1 hour in the future.
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let iat_future = (Utc::now() + TimeDelta::hours(2)).timestamp() as u64;
        let claims = json!({
            "sub": "user",
            "iss": "https://iss.example.com",
            "aud": "my-client",
            "exp": iat_future + 3600,
            "iat": iat_future,
        });
        let token = make_jwt(&claims, Some(TEST_KID));

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://iss.example.com"),
            None,
            &["my-client"],
        );
        assert!(
            matches!(result, Err(OidcError::IatInFuture { .. })),
            "iat more than 1 hour in future must be rejected, got {result:?}"
        );
    }

    #[test]
    fn verify_jwt_accepts_iat_within_future_window() {
        // iat within 1 hour of now must be accepted.
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let iat_slightly_future = (Utc::now() + TimeDelta::minutes(30)).timestamp() as u64;
        let claims = json!({
            "sub": "user",
            "iss": "https://iss.example.com",
            "aud": "my-client",
            "exp": iat_slightly_future + 3600,
            "iat": iat_slightly_future,
        });
        let token = make_jwt(&claims, Some(TEST_KID));

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://iss.example.com"),
            None,
            &["my-client"],
        );
        assert!(
            result.is_ok(),
            "iat within 1 hour must be accepted, got {result:?}"
        );
    }

    // ── required claims ───────────────────────────────────────────────────────

    #[test]
    fn verify_jwt_rejects_missing_sub() {
        // OIDC Core §3.1.2: sub is REQUIRED.
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let exp = (Utc::now() + TimeDelta::hours(1)).timestamp();
        let claims = json!({
            "iss": "https://iss.example.com",
            "aud": "my-client",
            "exp": exp,
            "iat": Utc::now().timestamp(),
        });
        let token = make_jwt(&claims, Some(TEST_KID));

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://iss.example.com"),
            None,
            &["my-client"],
        );
        assert!(
            matches!(result, Err(OidcError::JwtDecode { .. })),
            "missing sub must be rejected, got {result:?}"
        );
    }

    #[test]
    fn verify_jwt_rejects_missing_aud() {
        // OIDC Core §3.1.3.7: aud is REQUIRED.
        let jwks = JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        };
        let exp = (Utc::now() + TimeDelta::hours(1)).timestamp();
        let claims = json!({
            "sub": "user",
            "iss": "https://iss.example.com",
            "exp": exp,
            "iat": Utc::now().timestamp(),
        });
        let token = make_jwt(&claims, Some(TEST_KID));

        let result = verify_jwt(
            &token,
            &jwks,
            Some("https://iss.example.com"),
            None,
            &["my-client"],
        );
        assert!(
            matches!(result, Err(OidcError::JwtDecode { .. })),
            "missing aud must be rejected, got {result:?}"
        );
    }
}
