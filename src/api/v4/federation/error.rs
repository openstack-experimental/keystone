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
use crate::api::v4::federation::types::*;

#[derive(Error, Debug)]
pub enum OidcError {
    #[error("discovery error: {msg}")]
    Discovery { msg: String },

    #[error("client without discovery is not supported")]
    ClientWithoutDiscoveryNotSupported,

    #[error(
        "federated authentication requires mapping being specified in the payload or default set on the identity provider"
    )]
    MappingRequired,

    #[error("JWT login requires `openstack-mapping` header to be present.")]
    MappingRequiredJwt,

    #[error("`bearer` authorization token is missing.")]
    BearerJwtTokenMissing,

    #[error("mapping id or mapping name with idp id must be specified")]
    MappingIdOrNameWithIdp,

    #[error("groups claim must be an array of strings")]
    GroupsClaimNotArrayOfStrings,

    /// IdP is disabled.
    #[error("identity provider is disabled")]
    IdentityProviderDisabled,

    /// Mapping is disabled.
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

    #[error("server did not returned an ID token")]
    NoToken,

    #[error("identity Provider client_id is missing")]
    ClientIdRequired,

    #[error("ID token does not contain user id claim {0}")]
    UserIdClaimRequired(String),

    #[error("ID token does not contain user id claim {0}")]
    UserNameClaimRequired(String),

    /// Domain_id for the user cannot be identified.
    #[error("can not identify resulting domain_id for the user")]
    UserDomainUnbound,

    /// Bound subject mismatch.
    #[error("bound subject mismatches {expected} != {found}")]
    BoundSubjectMismatch { expected: String, found: String },

    /// Bound audiences mismatch.
    #[error("bound audiences mismatch {expected} != {found}")]
    BoundAudiencesMismatch { expected: String, found: String },

    /// Bound claims mismatch.
    #[error("bound claims mismatch")]
    BoundClaimsMismatch {
        claim: String,
        expected: String,
        found: String,
    },

    /// Error building user data.
    #[error(transparent)]
    MappedUserDataBuilder {
        #[from]
        #[allow(private_interfaces)]
        source: MappedUserDataBuilderError,
    },

    /// Authentication expired.
    #[error("authentication expired")]
    AuthStateExpired,

    /// Cannot use OIDC attribute mapping for JWT login.
    #[error("non jwt mapping requested for jwt login")]
    NonJwtMapping,

    /// No JWT issuer can be identified for the mapping.
    #[error("no jwt issuer can be determined")]
    NoJwtIssuer,

    /// User not found
    #[error("token user not found")]
    UserNotFound(String),
}

impl OidcError {
    pub fn discovery<T: std::error::Error>(fail: &T) -> Self {
        Self::Discovery {
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
/// message
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
            OidcError::MappingDisabled => {
                KeystoneApiError::BadRequest("Federated Identity Provider mapping is disabled.".to_string())
            }
            OidcError::MappingRequired => {
                KeystoneApiError::BadRequest("Federated authentication requires mapping being specified in the payload or default set on the identity provider.".to_string())
            }
            OidcError::MappingRequiredJwt => {
                KeystoneApiError::BadRequest("JWT authentication requires `openstack-mapping` header to be provided.".to_string())
            }
            OidcError::BearerJwtTokenMissing => {
                KeystoneApiError::BadRequest("`bearer` token is missing in the `Authorization` header.".to_string())
            }
            OidcError::MappingIdOrNameWithIdp => {
                KeystoneApiError::BadRequest("Federated authentication requires mapping being specified in the payload either with ID or name with identity provider id.".to_string())
            }
            OidcError::GroupsClaimNotArrayOfStrings => {
                KeystoneApiError::BadRequest("Groups claim must be an array of strings representing group names.".to_string())
            }
            OidcError::RequestToken { msg } => {
                KeystoneApiError::BadRequest(format!("Error exchanging authorization code for the authorization token: {msg}"))
            }
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
                KeystoneApiError::BadRequest("Identity Provider mut set `client_id`.".to_string())
            }
            OidcError::UserIdClaimRequired(source) => {
                KeystoneApiError::BadRequest(format!("OIDC ID token does not contain user id claim: {source}"))
            }
            OidcError::UserNameClaimRequired(source) => {
                KeystoneApiError::BadRequest(format!("OIDC ID token does not contain user name claim: {source}"))
            }
            OidcError::UserDomainUnbound => {
                KeystoneApiError::BadRequest("Cannot identify domain_id of the user.".to_string())
            }
            OidcError::BoundSubjectMismatch{ expected, found } => {
                KeystoneApiError::BadRequest(format!("OIDC Bound subject mismatches: {expected} != {found}"))
            }
            OidcError::BoundAudiencesMismatch{ expected, found } => {
                KeystoneApiError::BadRequest(format!("OIDC Bound audiences mismatches: {expected} != {found}"))
            }
            OidcError::BoundClaimsMismatch{ claim, expected, found } => {
                KeystoneApiError::BadRequest(format!("OIDC Bound claim {claim} mismatch: {expected} != {found}"))
            }
            e @ OidcError::MappedUserDataBuilder { .. } => {
                KeystoneApiError::InternalError(e.to_string())
            }
            OidcError::AuthStateExpired => {
                KeystoneApiError::BadRequest("Authentication has expired. Please start again.".to_string())
            }
            OidcError::NonJwtMapping | OidcError::NoJwtIssuer => {
                // Not exposing info about mapping and idp existence.
                KeystoneApiError::Unauthorized(Some("mapping error".to_string()))
            }
            OidcError::UserNotFound(_) => {
                // Not exposing info about mapping and idp existence.
                KeystoneApiError::Unauthorized(Some("User not found".to_string()))
            }
        }
    }
}
