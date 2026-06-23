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

use openstack_keystone_core_types::mapping::error::MappingProviderError;

use crate::api::error::KeystoneApiError;

#[derive(Error, Debug)]
pub enum OidcError {
    #[error("discovery error for {url}: {msg}")]
    Discovery { url: String, msg: String },

    #[error("client without discovery is not supported")]
    ClientWithoutDiscoveryNotSupported,

    #[error("mapping id or mapping name with idp id must be specified")]
    MappingIdOrNameWithIdp,

    #[error(
        "federated authentication requires mapping being specified in the payload or default set on the identity provider"
    )]
    MappingRequired,

    #[error("JWT login requires `openstack-mapping` header to be present.")]
    MappingRequiredJwt,

    #[error("`bearer` authorization token is missing.")]
    BearerJwtTokenMissing,

    #[error("identity provider is disabled")]
    IdentityProviderDisabled,

    #[error("mapping is disabled")]
    MappingDisabled,

    #[error("request token error")]
    RequestToken { msg: String },

    #[error("claim verification error")]
    ClaimVerification {
        #[from]
        source: openidconnect::ClaimsVerificationError,
    },

    #[error(transparent)]
    OpenIdConnectReqwest {
        #[from]
        source: openidconnect::reqwest::Error,
    },

    #[error(transparent)]
    OpenIdConnectConfiguration {
        #[from]
        source: openidconnect::ConfigurationError,
    },

    #[error(transparent)]
    UrlParse {
        #[from]
        source: url::ParseError,
    },

    #[error("server did not return an ID token")]
    NoToken,

    #[error("identity Provider client_id is missing")]
    ClientIdRequired,

    #[error("authentication expired")]
    AuthStateExpired,

    #[error("no jwt issuer can be determined")]
    NoJwtIssuer,

    #[error("mapping engine error: {0}")]
    MappingEngine(String),

    #[error("redirect URI is not allowed")]
    RedirectUriNotAllowed,
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

impl From<OidcError> for KeystoneApiError {
    #[instrument(level = Level::ERROR)]
    fn from(value: OidcError) -> Self {
        error!("Federation error: {:#?}", value);
        match value {
            e @ OidcError::Discovery { .. } => KeystoneApiError::InternalError(e.to_string()),
            e @ OidcError::ClientWithoutDiscoveryNotSupported => {
                KeystoneApiError::InternalError(e.to_string())
            }
            OidcError::IdentityProviderDisabled => {
                KeystoneApiError::BadRequest("Federated Identity Provider is disabled.".to_string())
            }
            OidcError::MappingDisabled => {
                KeystoneApiError::BadRequest("Federated Identity Provider mapping is disabled.".to_string())
            }
            OidcError::MappingRequired => {
                KeystoneApiError::BadRequest("Federated authentication requires mapping being specified in the payload or default set on the identity provider.".to_string())
            }
            OidcError::MappingIdOrNameWithIdp => KeystoneApiError::BadRequest(
                "Federated authentication requires mapping being specified in the payload either with ID or name with identity provider id.".to_string(),
            ),
            OidcError::MappingRequiredJwt => KeystoneApiError::BadRequest(
                "JWT authentication requires `openstack-mapping` header to be provided.".to_string(),
            ),
            OidcError::BearerJwtTokenMissing => KeystoneApiError::BadRequest(
                "`bearer` token is missing in the `Authorization` header.".to_string(),
            ),
            OidcError::RequestToken { msg } => KeystoneApiError::BadRequest(format!(
                "Error exchanging authorization code for the authorization token: {msg}"
            )),
            OidcError::ClaimVerification { source } => {
                KeystoneApiError::BadRequest(format!("Error in claims verification: {source}"))
            }
            OidcError::OpenIdConnectReqwest { source } => {
                KeystoneApiError::InternalError(format!("Error in OpenIDConnect logic: {source}"))
            }
            OidcError::OpenIdConnectConfiguration { source } => {
                KeystoneApiError::InternalError(format!("Error in OpenIDConnect logic: {source}"))
            }
            OidcError::UrlParse { source } => {
                KeystoneApiError::BadRequest(format!("Error in OpenIDConnect logic: {source}"))
            }
            e @ OidcError::NoToken => {
                KeystoneApiError::InternalError(format!("Error in OpenIDConnect logic: {e}"))
            }
            OidcError::ClientIdRequired => {
                KeystoneApiError::BadRequest("Identity Provider must set `client_id`.".to_string())
            }
            OidcError::AuthStateExpired => KeystoneApiError::BadRequest(
                "Authentication has expired. Please start again.".to_string(),
            ),
            OidcError::RedirectUriNotAllowed => KeystoneApiError::BadRequest(
                "redirect_uri is not allowed for this identity provider.".to_string(),
            ),
            OidcError::NoJwtIssuer => KeystoneApiError::unauthorized(value, Some("no jwt issuer")),
            OidcError::MappingEngine(_msg) => KeystoneApiError::UnauthorizedNoContext,
        }
    }
}

impl From<MappingProviderError> for OidcError {
    fn from(value: MappingProviderError) -> Self {
        Self::MappingEngine(value.to_string())
    }
}
