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
//! # Keystone API error.
use axum::{
    Json,
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;
use tracing::error;

use crate::assignment::error::AssignmentProviderError;
use crate::auth::AuthenticationError;
use crate::catalog::error::CatalogProviderError;
use crate::error::BuilderError;
use crate::identity::error::IdentityProviderError;
use crate::policy::PolicyError;
use crate::resource::error::ResourceProviderError;
use crate::revoke::error::RevokeProviderError;
use crate::token::error::TokenProviderError;

/// Keystone API operation errors.
#[derive(Debug, Error)]
pub enum KeystoneApiError {
    /// Selected authentication is forbidden.
    #[error("changing current authentication scope is forbidden")]
    AuthenticationRescopeForbidden,

    #[error("Attempted to authenticate with an unsupported method.")]
    AuthMethodNotSupported,

    #[error("{0}.")]
    BadRequest(String),

    /// Base64 decoding error.
    #[error(transparent)]
    Base64Decode(#[from] base64::DecodeError),

    #[error("conflict, resource already existing")]
    Conflict(String),

    #[error("domain id or name must be present")]
    DomainIdOrName,

    #[error("You are not authorized to perform the requested action.")]
    Forbidden,

    #[error("invalid header header")]
    InvalidHeader,

    #[error("invalid token")]
    InvalidToken,

    #[error(transparent)]
    JsonExtractorRejection(#[from] JsonRejection),

    #[error("internal server error: {0}")]
    InternalError(String),

    #[error("could not find {resource}: {identifier}")]
    NotFound {
        resource: String,
        identifier: String,
    },

    /// Others.
    #[error(transparent)]
    Other(#[from] eyre::Report),

    #[error(transparent)]
    Policy {
        #[from]
        source: PolicyError,
    },
    #[error("project id or name must be present")]
    ProjectIdOrName,

    #[error("project domain must be present")]
    ProjectDomain,

    /// Selected authentication is forbidden.
    #[error("selected authentication is forbidden")]
    SelectedAuthenticationForbidden,

    /// (de)serialization error.
    #[error(transparent)]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    #[error("missing x-subject-token header")]
    SubjectTokenMissing,

    #[error("{}", .0.clone().unwrap_or("The request you have made requires authentication.".to_string()))]
    Unauthorized(Option<String>),

    /// Request validation error.
    #[error("request validation failed: {source}")]
    Validator {
        /// The source of the error.
        #[from]
        source: validator::ValidationErrors,
    },
}

impl IntoResponse for KeystoneApiError {
    fn into_response(self) -> Response {
        error!("Error happened during request processing: {:#?}", self);

        let status_code = match self {
            KeystoneApiError::Conflict(_) => StatusCode::CONFLICT,
            KeystoneApiError::NotFound { .. } => StatusCode::NOT_FOUND,
            KeystoneApiError::BadRequest(..) => StatusCode::BAD_REQUEST,
            KeystoneApiError::Unauthorized(..) => StatusCode::UNAUTHORIZED,
            KeystoneApiError::Forbidden => StatusCode::FORBIDDEN,
            KeystoneApiError::Policy { .. } => StatusCode::FORBIDDEN,
            KeystoneApiError::SelectedAuthenticationForbidden
            | KeystoneApiError::AuthenticationRescopeForbidden => StatusCode::BAD_REQUEST,
            KeystoneApiError::InternalError(_) | KeystoneApiError::Other(..) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            _ => StatusCode::BAD_REQUEST,
        };

        (
            status_code,
            Json(json!({"error": {"code": status_code.as_u16(), "message": self.to_string()}})),
        )
            .into_response()
    }
}

impl From<AuthenticationError> for KeystoneApiError {
    fn from(value: AuthenticationError) -> Self {
        match value {
            AuthenticationError::StructBuilder { source } => {
                KeystoneApiError::InternalError(source.to_string())
            }
            AuthenticationError::UserDisabled(user_id) => KeystoneApiError::Unauthorized(Some(
                format!("The account is disabled for the user: {user_id}"),
            )),
            AuthenticationError::UserLocked(user_id) => KeystoneApiError::Unauthorized(Some(
                format!("The account is locked for the user: {user_id}"),
            )),
            AuthenticationError::UserPasswordExpired(user_id) => {
                KeystoneApiError::Unauthorized(Some(format!(
                    "The password is expired and need to be changed for user: {user_id}"
                )))
            }
            AuthenticationError::UserNameOrPasswordWrong => {
                KeystoneApiError::Unauthorized(Some("Invalid username or password".to_string()))
            }
            AuthenticationError::TokenRenewalForbidden => {
                KeystoneApiError::SelectedAuthenticationForbidden
            }
            AuthenticationError::Unauthorized => KeystoneApiError::Unauthorized(None),
        }
    }
}

impl From<AssignmentProviderError> for KeystoneApiError {
    fn from(source: AssignmentProviderError) -> Self {
        match source {
            AssignmentProviderError::RoleNotFound(x) => Self::NotFound {
                resource: "role".into(),
                identifier: x,
            },
            ref err @ AssignmentProviderError::Conflict(..) => Self::Conflict(err.to_string()),
            ref err @ AssignmentProviderError::Validation { .. } => {
                Self::BadRequest(err.to_string())
            }
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<BuilderError> for KeystoneApiError {
    fn from(value: crate::error::BuilderError) -> Self {
        Self::InternalError(value.to_string())
    }
}

impl From<serde_urlencoded::ser::Error> for KeystoneApiError {
    fn from(value: serde_urlencoded::ser::Error) -> Self {
        Self::InternalError(value.to_string())
    }
}

impl From<url::ParseError> for KeystoneApiError {
    fn from(value: url::ParseError) -> Self {
        Self::InternalError(value.to_string())
    }
}

impl From<CatalogProviderError> for KeystoneApiError {
    fn from(value: CatalogProviderError) -> Self {
        match value {
            ref err @ CatalogProviderError::Conflict(..) => Self::Conflict(err.to_string()),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<IdentityProviderError> for KeystoneApiError {
    fn from(value: IdentityProviderError) -> Self {
        match value {
            IdentityProviderError::AuthenticationInfo { source } => source.into(),
            IdentityProviderError::UserNotFound(x) => Self::NotFound {
                resource: "user".into(),
                identifier: x,
            },
            IdentityProviderError::GroupNotFound(x) => Self::NotFound {
                resource: "group".into(),
                identifier: x,
            },
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<ResourceProviderError> for KeystoneApiError {
    fn from(value: ResourceProviderError) -> Self {
        match value {
            ref err @ ResourceProviderError::Conflict(..) => Self::BadRequest(err.to_string()),
            ResourceProviderError::DomainNotFound(x) => Self::NotFound {
                resource: "domain".into(),
                identifier: x,
            },
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<RevokeProviderError> for KeystoneApiError {
    fn from(value: RevokeProviderError) -> Self {
        match value {
            ref err @ RevokeProviderError::Conflict(..) => Self::BadRequest(err.to_string()),
            other => Self::InternalError(other.to_string()),
        }
    }
}

impl From<TokenProviderError> for KeystoneApiError {
    fn from(value: TokenProviderError) -> Self {
        match value {
            TokenProviderError::AuthenticationInfo(source) => source.into(),
            TokenProviderError::TokenRestrictionNotFound(x) => Self::NotFound {
                resource: "token restriction".into(),
                identifier: x,
            },
            other => Self::InternalError(other.to_string()),
        }
    }
}
