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

use thiserror::Error;
use tracing::{Level, error, instrument};

use crate::api::error::KeystoneApiError;

#[derive(Error, Debug)]
pub enum OidcError {
    /// OIDC Discovery error.
    #[error("discovery error for {url}: {msg}")]
    Discovery {
        /// IdP URL.
        url: String,
        /// Error message.
        msg: String,
    },

    #[error("client without discovery is not supported")]
    ClientWithoutDiscoveryNotSupported,

    #[error(
        "federated authentication requires mapping being specified in the payload or default set on the identity provider"
    )]
    MappingRequired,

    #[error("`bearer` authorization token is missing.")]
    BearerJwtTokenMissing,

    /// IdP is disabled.
    #[error("identity provider is disabled")]
    IdentityProviderDisabled,

    /// Redirect URI is not in the allowed list for the identity provider.
    #[error("redirect URI not allowed by identity provider")]
    RedirectUriNotAllowed,

    #[error("request token error")]
    RequestToken { msg: String },

    /// JWT decode or signature verification failed.
    #[error("JWT decode/verification error")]
    JwtDecode {
        #[from]
        source: jsonwebtoken::errors::Error,
    },

    /// HTTP request to IdP failed.
    #[error("HTTP request error")]
    HttpRequest {
        #[from]
        source: reqwest::Error,
    },

    #[error("transparent")]
    UrlParse {
        #[from]
        source: url::ParseError,
    },

    /// No JWK matched the key ID from the JWT header.
    #[error("no matching JWK found for kid `{0}`")]
    JwkNotFound(String),

    /// JWT nonce claim does not match the expected value.
    #[error("nonce mismatch in ID token")]
    NonceMismatch,

    /// JWKS is empty or all keys failed to load.
    #[error("JWKS contains no usable keys")]
    NoJwksKeys,

    /// The JWT was signed with an algorithm that is not permitted (e.g.
    /// symmetric HS256).
    #[error("unsupported JWT signing algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("server did not returned an ID token")]
    NoToken,

    #[error("identity Provider client_id is missing")]
    ClientIdRequired,

    /// Authentication expired.
    #[error("authentication expired")]
    AuthStateExpired,

    /// No JWT issuer can be identified for the mapping.
    #[error("no jwt issuer can be determined")]
    NoJwtIssuer,

    /// Issuer in discovery document does not match the requested issuer URL
    /// (RFC 8414 §3).
    #[error("issuer mismatch: expected `{expected}`, got `{actual}`")]
    IssuerMismatch {
        /// Issuer URL the caller expected.
        expected: String,
        /// Issuer URL returned by the discovery document.
        actual: String,
    },

    /// Flattened claims map exceeds 64 KiB limit (ADR-0020 §9).
    #[error("claims map size exceeds 64 KiB limit")]
    ClaimsMapTooLarge,

    /// The `iat` claim is too far in the future, indicating clock skew or a
    /// forged token.
    #[error("iat {iat} is in the future (current time: {now})")]
    IatInFuture {
        /// The `iat` claim value (Unix timestamp).
        iat: u64,
        /// Current time (Unix timestamp).
        now: u64,
    },
}

impl OidcError {
    pub fn discovery<U: AsRef<str>, T: std::error::Error>(url: U, fail: &T) -> Self {
        Self::Discovery {
            url: url.as_ref().to_string(),
            msg: fail.to_string(),
        }
    }
    pub fn request_token<T: std::error::Error>(fail: &T) -> Self {
        Self::RequestToken {
            msg: fail.to_string(),
        }
    }
}

/// Convert OIDC error into the [HTTP](KeystoneApiError) with the expected
/// message.
impl From<OidcError> for KeystoneApiError {
    #[instrument(level = Level::ERROR)]
    fn from(value: OidcError) -> Self {
        error!("Federation error: {:#?}", value);
        match value {
            e @ OidcError::Discovery { .. } => {
                KeystoneApiError::InternalError(e.to_string())
            }
            e @ OidcError::ClientWithoutDiscoveryNotSupported => {
                KeystoneApiError::InternalError(e.to_string())
            }
            OidcError::IdentityProviderDisabled => {
                KeystoneApiError::BadRequest("Federated Identity Provider is disabled.".to_string())
            }
            OidcError::MappingRequired => {
                KeystoneApiError::BadRequest("Federated authentication requires mapping being specified in the payload or default set on the identity provider.".to_string())
            }
            OidcError::BearerJwtTokenMissing => {
                KeystoneApiError::BadRequest("`bearer` token is missing in the `Authorization` header.".to_string())
            }
            OidcError::RequestToken { msg } => {
                KeystoneApiError::BadRequest(format!("Error exchanging authorization code for the authorization token: {msg}"))
            }
            OidcError::JwtDecode { source } => {
                KeystoneApiError::BadRequest(format!("JWT verification error: {source}"))
            }
            OidcError::HttpRequest { source } => {
                KeystoneApiError::InternalError(format!("HTTP request error: {source}"))
            }
            OidcError::UrlParse { source } => {
                KeystoneApiError::BadRequest(format!("URL parse error: {source}"))
            }
            OidcError::NonceMismatch => {
                KeystoneApiError::BadRequest("Nonce mismatch in ID token.".to_string())
            }
            OidcError::JwkNotFound(kid) => {
                KeystoneApiError::BadRequest(format!("No matching JWK for kid `{kid}`"))
            }
            OidcError::NoJwksKeys => {
                KeystoneApiError::InternalError("JWKS contains no usable keys.".to_string())
            }
            OidcError::UnsupportedAlgorithm(alg) => {
                KeystoneApiError::BadRequest(format!("Unsupported JWT algorithm: {alg}"))
            }
            e @ OidcError::NoToken => {
                KeystoneApiError::InternalError(format!("Error in OIDC logic: {e}"))
            }
            OidcError::ClientIdRequired => {
                KeystoneApiError::BadRequest("Identity Provider must set `client_id`.".to_string())
            }
            OidcError::ClaimsMapTooLarge => {
                KeystoneApiError::BadRequest("Federated claims map is too large.".to_string())
            }
            OidcError::RedirectUriNotAllowed => {
                KeystoneApiError::BadRequest("Redirect URI not allowed.".to_string())
            }
            OidcError::AuthStateExpired => {
                KeystoneApiError::BadRequest("Authentication has expired. Please start again.".to_string())
            }
            OidcError::IssuerMismatch { expected, actual } => {
                KeystoneApiError::BadRequest(format!(
                    "OIDC issuer mismatch: expected `{expected}`, got `{actual}`"
                ))
            }
            OidcError::NoJwtIssuer => {
                // Not exposing info about mapping and idp existence.
                KeystoneApiError::unauthorized(value, Some("mapping error"))
            }
            OidcError::IatInFuture { iat, now } => {
                KeystoneApiError::BadRequest(format!(
                    "ID token iat ({iat}) is in the future (current: {now})"
                ))
            }
        }
    }
}
