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
use crate::identity::error::IdentityProviderError;
use crate::policy::PolicyError;
use crate::resource::error::ResourceProviderError;
use crate::revoke::error::RevokeProviderError;
use crate::token::error::TokenProviderError;

/// Keystone API operation errors
#[derive(Debug, Error)]
pub enum KeystoneApiError {
    #[error("conflict, resource already existing")]
    Conflict(String),

    #[error("could not find {resource}: {identifier}")]
    NotFound {
        resource: String,
        identifier: String,
    },

    #[error("Attempted to authenticate with an unsupported method.")]
    AuthMethodNotSupported,

    #[error("{0}.")]
    BadRequest(String),

    #[error("{}", .0.clone().unwrap_or("The request you have made requires authentication.".to_string()))]
    Unauthorized(Option<String>),

    #[error("You are not authorized to perform the requested action.")]
    Forbidden,

    #[error("missing x-subject-token header")]
    SubjectTokenMissing,

    #[error("invalid header header")]
    InvalidHeader,

    #[error("invalid token")]
    InvalidToken,

    #[error("error building token data: {}", source)]
    Token {
        #[from]
        source: TokenError,
    },

    #[error("internal server error: {0}")]
    InternalError(String),

    #[error(transparent)]
    AssignmentError {
        #[from]
        source: AssignmentProviderError,
    },

    //    #[error(transparent)]
    //    AuthenticationInfo {
    //        //#[from]
    //        source: crate::auth::AuthenticationError,
    //    },
    #[error(transparent)]
    CatalogError {
        #[from]
        source: CatalogProviderError,
    },

    #[error(transparent)]
    IdentityError { source: IdentityProviderError },

    #[error(transparent)]
    Policy {
        #[from]
        source: PolicyError,
    },

    #[error(transparent)]
    ResourceError {
        #[from]
        source: ResourceProviderError,
    },

    /// Revoke provider error.
    #[error(transparent)]
    RevokeProvider {
        /// The source of the error.
        #[from]
        source: RevokeProviderError,
    },

    #[error(transparent)]
    TokenError { source: TokenProviderError },

    #[error(transparent)]
    Uuid {
        #[from]
        source: uuid::Error,
    },

    #[error(transparent)]
    Serde {
        #[from]
        source: serde_json::Error,
    },

    /// Base64 decoding error.
    #[error(transparent)]
    Base64Decode(#[from] base64::DecodeError),

    #[error("domain id or name must be present")]
    DomainIdOrName,

    #[error("project id or name must be present")]
    ProjectIdOrName,

    #[error("project domain must be present")]
    ProjectDomain,

    #[error(transparent)]
    JsonExtractorRejection(#[from] JsonRejection),

    /// Selected authentication is forbidden.
    #[error("selected authentication is forbidden")]
    SelectedAuthenticationForbidden,

    /// Selected authentication is forbidden.
    #[error("changing current authentication scope is forbidden")]
    AuthenticationRescopeForbidden,

    /// Request validation error.
    #[error("request validation failed: {source}")]
    Validator {
        /// The source of the error.
        #[from]
        source: validator::ValidationErrors,
    },

    /// Others.
    #[error(transparent)]
    Other(#[from] eyre::Report),
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
            KeystoneApiError::InternalError(_)
            | KeystoneApiError::IdentityError { .. }
            | KeystoneApiError::ResourceError { .. }
            | KeystoneApiError::AssignmentError { .. }
            | KeystoneApiError::TokenError { .. }
            | KeystoneApiError::RevokeProvider { .. }
            | KeystoneApiError::Other(..) => StatusCode::INTERNAL_SERVER_ERROR,
            _ =>
            // KeystoneApiError::SubjectTokenMissing | KeystoneApiError::InvalidHeader |
            // KeystoneApiError::InvalidToken | KeystoneApiError::Token{..} |
            // KeystoneApiError::WebAuthN{..} | KeystoneApiError::Uuid {..} |
            // KeystoneApiError::Serde {..} | KeystoneApiError::DomainIdOrName |
            // KeystoneApiError::ProjectIdOrName | KeystoneApiError::ProjectDomain =>
            {
                StatusCode::BAD_REQUEST
            }
        };

        (
            status_code,
            Json(json!({"error": {"code": status_code.as_u16(), "message": self.to_string()}})),
        )
            .into_response()
    }
}

impl KeystoneApiError {
    pub fn assignment(source: AssignmentProviderError) -> Self {
        match source {
            AssignmentProviderError::RoleNotFound(x) => Self::NotFound {
                resource: "role".into(),
                identifier: x,
            },
            _ => source.into(),
        }
    }

    pub fn identity(source: IdentityProviderError) -> Self {
        match source {
            IdentityProviderError::UserNotFound(x) => Self::NotFound {
                resource: "user".into(),
                identifier: x,
            },
            IdentityProviderError::GroupNotFound(x) => Self::NotFound {
                resource: "group".into(),
                identifier: x,
            },
            _ => source.into(),
        }
    }

    pub fn resource(source: ResourceProviderError) -> Self {
        match source {
            ResourceProviderError::DomainNotFound(x) => Self::NotFound {
                resource: "domain".into(),
                identifier: x,
            },
            _ => source.into(),
        }
    }
    pub fn token(source: TokenProviderError) -> Self {
        match source {
            TokenProviderError::TokenRestrictionNotFound(x) => Self::NotFound {
                resource: "token restriction".into(),
                identifier: x,
            },
            _ => source.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("error building token data: {}", source)]
    Builder {
        #[from]
        source: crate::api::v3::auth::token::types::TokenBuilderError,
    },

    #[error("error building token data: {}", source)]
    Builder4 {
        #[from]
        source: crate::api::v4::auth::token::types::TokenBuilderError,
    },

    #[error("error building token user data: {}", source)]
    UserBuilder {
        #[from]
        source: crate::api::v3::auth::token::types::UserBuilderError,
    },

    #[error("error building token user data: {}", source)]
    UserBuilder4 {
        #[from]
        source: crate::api::v4::auth::token::types::UserBuilderError,
    },

    #[error("error building token user data: {}", source)]
    ProjectBuilder {
        #[from]
        source: crate::api::types::ProjectBuilderError,
    },

    #[error(transparent)]
    UserPasswordAuthBuilder {
        #[from]
        source: crate::identity::types::user::UserPasswordAuthRequestBuilderError,
    },
    #[error(transparent)]
    DomainBuilder {
        #[from]
        source: crate::identity::types::user::DomainBuilderError,
    },
}

impl From<AuthenticationError> for KeystoneApiError {
    fn from(value: AuthenticationError) -> Self {
        match value {
            AuthenticationError::AuthenticatedInfoBuilder { source } => {
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

impl From<IdentityProviderError> for KeystoneApiError {
    fn from(value: IdentityProviderError) -> Self {
        match value {
            IdentityProviderError::AuthenticationInfo { source } => source.into(),
            _ => Self::IdentityError { source: value },
        }
    }
}

impl From<TokenProviderError> for KeystoneApiError {
    fn from(value: TokenProviderError) -> Self {
        match value {
            TokenProviderError::AuthenticationInfo { source } => source.into(),
            _ => Self::TokenError { source: value },
        }
    }
}
