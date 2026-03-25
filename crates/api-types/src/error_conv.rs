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

use {
    axum::{
        Json,
        extract::rejection::JsonRejection,
        http::StatusCode,
        response::{IntoResponse, Response},
    },
    serde_json::json,
};

use openstack_keystone_core_types::assignment::AssignmentProviderError;
use openstack_keystone_core_types::auth::AuthenticationError;
use openstack_keystone_core_types::catalog::CatalogProviderError;
use openstack_keystone_core_types::error::BuilderError;
use openstack_keystone_core_types::identity::IdentityProviderError;
use openstack_keystone_core_types::resource::ResourceProviderError;
use openstack_keystone_core_types::revoke::RevokeProviderError;
use openstack_keystone_core_types::role::RoleProviderError;
use openstack_keystone_core_types::token::TokenProviderError;

use crate::error::KeystoneApiError;

impl IntoResponse for KeystoneApiError {
    fn into_response(self) -> Response {
        let status_code = match self {
            KeystoneApiError::Conflict(_) => StatusCode::CONFLICT,
            KeystoneApiError::NotFound { .. } => StatusCode::NOT_FOUND,
            KeystoneApiError::BadRequest(..) => StatusCode::BAD_REQUEST,
            KeystoneApiError::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            KeystoneApiError::UnauthorizedNoContext => StatusCode::UNAUTHORIZED,
            KeystoneApiError::Forbidden { .. } => StatusCode::FORBIDDEN,
            //KeystoneApiError::Policy { .. } => StatusCode::FORBIDDEN,
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

impl From<BuilderError> for KeystoneApiError {
    fn from(value: BuilderError) -> Self {
        Self::InternalError(value.to_string())
    }
}

impl From<JsonRejection> for KeystoneApiError {
    fn from(value: JsonRejection) -> Self {
        Self::BadRequest(value.to_string())
    }
}

impl From<AuthenticationError> for KeystoneApiError {
    fn from(value: AuthenticationError) -> Self {
        match value {
            AuthenticationError::DomainDisabled(..) => {
                KeystoneApiError::unauthorized(value, None::<String>)
            }
            AuthenticationError::ProjectDisabled(..) => {
                KeystoneApiError::unauthorized(value, None::<String>)
            }
            AuthenticationError::StructBuilder { source } => {
                KeystoneApiError::InternalError(source.to_string())
            }
            AuthenticationError::UserDisabled(ref user_id) => {
                let uid = user_id.clone();
                KeystoneApiError::unauthorized(
                    value,
                    Some(format!("The account is disabled for the user: {uid}")),
                )
            }
            AuthenticationError::UserLocked(ref user_id) => {
                let uid = user_id.clone();
                KeystoneApiError::unauthorized(
                    value,
                    Some(format!("The account is locked for the user: {uid}")),
                )
            }
            AuthenticationError::UserPasswordExpired(ref user_id) => {
                let uid = user_id.clone();
                KeystoneApiError::unauthorized(
                    value,
                    Some(format!(
                        "The password is expired and need to be changed for user: {uid}"
                    )),
                )
            }
            AuthenticationError::UserNameOrPasswordWrong => KeystoneApiError::unauthorized(
                value,
                Some("Invalid username or password".to_string()),
            ),
            AuthenticationError::TokenRenewalForbidden => {
                KeystoneApiError::SelectedAuthenticationForbidden
            }
            AuthenticationError::Unauthorized => {
                KeystoneApiError::unauthorized(value, None::<String>)
            }
        }
    }
}

impl From<AssignmentProviderError> for KeystoneApiError {
    fn from(source: AssignmentProviderError) -> Self {
        match source {
            AssignmentProviderError::AssignmentNotFound(x) => Self::NotFound {
                resource: "assignment".into(),
                identifier: x,
            },
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

impl From<RoleProviderError> for KeystoneApiError {
    fn from(source: RoleProviderError) -> Self {
        match source {
            RoleProviderError::RoleNotFound(x) => Self::NotFound {
                resource: "role".into(),
                identifier: x,
            },
            ref err @ RoleProviderError::Conflict(..) => Self::Conflict(err.to_string()),
            ref err @ RoleProviderError::Validation { .. } => Self::BadRequest(err.to_string()),
            other => Self::InternalError(other.to_string()),
        }
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
            IdentityProviderError::Authentication { source } => source.into(),
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
            TokenProviderError::Authentication(source) => source.into(),
            TokenProviderError::DomainDisabled(x) => Self::NotFound {
                resource: "domain".into(),
                identifier: x,
            },
            TokenProviderError::TokenRestrictionNotFound(x) => Self::NotFound {
                resource: "token restriction".into(),
                identifier: x,
            },
            TokenProviderError::ProjectDisabled(x) => Self::NotFound {
                resource: "project".into(),
                identifier: x,
            },
            other => Self::InternalError(other.to_string()),
        }
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

impl From<uuid::Error> for KeystoneApiError {
    fn from(value: uuid::Error) -> Self {
        Self::InternalError(value.to_string())
    }
}

impl From<validator::ValidationErrors> for KeystoneApiError {
    fn from(value: validator::ValidationErrors) -> Self {
        Self::BadRequest(value.to_string())
    }
}
