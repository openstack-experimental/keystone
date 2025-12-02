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

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::identity::types as identity_types;

/// User response object.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct User {
    /// User ID.
    #[validate(length(max = 64))]
    pub id: String,
    /// User domain ID.
    #[validate(length(max = 64))]
    pub domain_id: String,
    /// User name.
    #[validate(length(max = 255))]
    pub name: String,
    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    pub enabled: bool,
    /// The ID of the default project for the user. A user’s default project
    /// must not be a domain. Setting this attribute does not grant any
    /// actual authorization on the project, and is merely provided for
    /// convenience. Therefore, the referenced project does not need to exist
    /// within the user domain. (Since v3.1) If the user does not have
    /// authorization to their default project, the default project is
    /// ignored at token creation. (Since v3.1) Additionally, if your
    /// default project is not valid, a token is issued without an explicit
    /// scope of authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub default_project_id: Option<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
    /// The date and time when the password expires. The time zone is UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_expires_at: Option<DateTime<Utc>>,
    /// The resource options for the user. Available resource options are
    /// ignore_change_password_upon_first_use, ignore_password_expiry,
    /// ignore_lockout_failure_attempts, lock_password,
    /// multi_factor_auth_enabled, and multi_factor_auth_rules
    /// ignore_user_inactivity.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub options: Option<UserOptions>,
    /// List of federated objects associated with a user. Each object in the list contains the idp_id and protocols. protocols is a list of objects, each of which contains protocol_id and unique_id of the protocol and user respectively.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub federated: Option<Vec<Federation>>,
}

/// Complete response with the user data.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct UserResponse {
    /// User object
    #[validate(nested)]
    pub user: User,
}

/// Create user data.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct UserCreate {
    /// User domain ID.
    #[validate(length(max = 64))]
    pub domain_id: String,
    /// The user name. Must be unique within the owning domain.
    #[validate(length(max = 255))]
    pub name: String,
    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    pub enabled: Option<bool>,
    /// The ID of the default project for the user. A user’s default project
    /// must not be a domain. Setting this attribute does not grant any
    /// actual authorization on the project, and is merely provided for
    /// convenience. Therefore, the referenced project does not need to exist
    /// within the user domain. (Since v3.1) If the user does not have
    /// authorization to their default project, the default project is
    /// ignored at token creation. (Since v3.1) Additionally, if your
    /// default project is not valid, a token is issued without an explicit
    /// scope of authorization.
    #[validate(length(max = 64))]
    pub default_project_id: Option<String>,
    /// The password for the user.
    #[validate(length(max = 72))]
    pub password: Option<String>,
    /// The resource options for the user. Available resource options are
    /// ignore_change_password_upon_first_use, ignore_password_expiry,
    /// ignore_lockout_failure_attempts, lock_password,
    /// multi_factor_auth_enabled, and multi_factor_auth_rules
    /// ignore_user_inactivity.
    #[validate(nested)]
    pub options: Option<UserOptions>,
    /// Additional user properties
    #[serde(flatten)]
    pub extra: Option<Value>,
}

/// Update user data.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct UserUpdateRequest {
    /// The user name. Must be unique within the owning domain.
    #[validate(length(max = 255))]
    pub name: Option<String>,
    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    pub enabled: Option<bool>,
    /// The ID of the default project for the user. A user’s default project
    /// must not be a domain. Setting this attribute does not grant any
    /// actual authorization on the project, and is merely provided for
    /// convenience. Therefore, the referenced project does not need to exist
    /// within the user domain. (Since v3.1) If the user does not have
    /// authorization to their default project, the default project is
    /// ignored at token creation. (Since v3.1) Additionally, if your
    /// default project is not valid, a token is issued without an explicit
    /// scope of authorization.
    #[validate(length(max = 64))]
    pub default_project_id: Option<String>,
    /// The password for the user.
    pub password: Option<String>,
    /// The resource options for the user. Available resource options are
    /// ignore_change_password_upon_first_use, ignore_password_expiry,
    /// ignore_lockout_failure_attempts, lock_password,
    /// multi_factor_auth_enabled, and multi_factor_auth_rules
    /// ignore_user_inactivity.
    #[validate(nested)]
    pub options: Option<UserOptions>,
    /// Additional user properties
    #[serde(flatten)]
    pub extra: Option<Value>,
}

/// User options.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct UserOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_change_password_upon_first_use: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_password_expiry: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_lockout_failure_attempts: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_password: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_user_inactivity: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multi_factor_auth_rules: Option<Vec<Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multi_factor_auth_enabled: Option<bool>,
}

impl From<identity_types::UserOptions> for UserOptions {
    fn from(value: identity_types::UserOptions) -> Self {
        Self {
            ignore_change_password_upon_first_use: value.ignore_change_password_upon_first_use,
            ignore_password_expiry: value.ignore_password_expiry,
            ignore_lockout_failure_attempts: value.ignore_lockout_failure_attempts,
            lock_password: value.lock_password,
            ignore_user_inactivity: value.ignore_user_inactivity,
            multi_factor_auth_rules: value.multi_factor_auth_rules,
            multi_factor_auth_enabled: value.multi_factor_auth_enabled,
        }
    }
}

impl From<UserOptions> for identity_types::UserOptions {
    fn from(value: UserOptions) -> Self {
        Self {
            ignore_change_password_upon_first_use: value.ignore_change_password_upon_first_use,
            ignore_password_expiry: value.ignore_password_expiry,
            ignore_lockout_failure_attempts: value.ignore_lockout_failure_attempts,
            lock_password: value.lock_password,
            ignore_user_inactivity: value.ignore_user_inactivity,
            multi_factor_auth_rules: value.multi_factor_auth_rules,
            multi_factor_auth_enabled: value.multi_factor_auth_enabled,
        }
    }
}

/// Complete create user request.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct UserCreateRequest {
    /// User object.
    #[validate(nested)]
    pub user: UserCreate,
}

impl From<identity_types::UserResponse> for User {
    fn from(value: identity_types::UserResponse) -> Self {
        let opts: UserOptions = value.options.clone().into();
        // We only want to see user options if there is at least 1 option set
        let opts = if opts.ignore_change_password_upon_first_use.is_some()
            || opts.ignore_password_expiry.is_some()
            || opts.ignore_lockout_failure_attempts.is_some()
            || opts.lock_password.is_some()
            || opts.ignore_user_inactivity.is_some()
            || opts.multi_factor_auth_rules.is_some()
            || opts.multi_factor_auth_enabled.is_some()
        {
            Some(opts)
        } else {
            None
        };
        Self {
            id: value.id,
            domain_id: value.domain_id,
            name: value.name,
            enabled: value.enabled,
            default_project_id: value.default_project_id,
            extra: value.extra,
            password_expires_at: value.password_expires_at,
            options: opts,
            federated: value
                .federated
                .map(|val| val.into_iter().map(Into::into).collect()),
        }
    }
}

impl From<UserCreateRequest> for identity_types::UserCreate {
    fn from(value: UserCreateRequest) -> Self {
        let user = value.user;
        Self {
            id: String::new(),
            name: user.name,
            domain_id: user.domain_id,
            enabled: user.enabled,
            password: user.password,
            extra: user.extra,
            default_project_id: user.default_project_id,
            options: user.options.map(Into::into),
            federated: None,
        }
    }
}

/// User federation data.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct Federation {
    /// Identity provider ID.
    pub idp_id: String,
    /// Protocols.
    #[validate(nested)]
    pub protocols: Vec<FederationProtocol>,
}

/// Federation protocol data.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct FederationProtocol {
    /// Federation protocol ID
    #[validate(length(max = 64))]
    pub protocol_id: String,
    // TODO: unique ID should potentially belong to the IDP and not to the protocol
    /// Unique ID of the associated user
    #[validate(length(max = 64))]
    pub unique_id: String,
}

impl From<identity_types::Federation> for Federation {
    fn from(value: identity_types::Federation) -> Self {
        Self {
            idp_id: value.idp_id,
            protocols: value.protocols.into_iter().map(Into::into).collect(),
        }
    }
}
impl From<identity_types::FederationProtocol> for FederationProtocol {
    fn from(value: identity_types::FederationProtocol) -> Self {
        Self {
            protocol_id: value.protocol_id,
            unique_id: value.unique_id,
        }
    }
}

impl IntoResponse for UserResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

impl IntoResponse for identity_types::UserResponse {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            Json(UserResponse {
                user: User::from(self),
            }),
        )
            .into_response()
    }
}

/// List of users.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct UserList {
    /// Collection of user objects
    #[validate(nested)]
    pub users: Vec<User>,
}

impl From<Vec<identity_types::UserResponse>> for UserList {
    fn from(value: Vec<identity_types::UserResponse>) -> Self {
        let objects: Vec<User> = value.into_iter().map(User::from).collect();
        Self { users: objects }
    }
}

impl IntoResponse for UserList {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// User list parameters.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, IntoParams, Validate)]
pub struct UserListParameters {
    /// Filter users by Domain ID.
    #[validate(length(max = 64))]
    pub domain_id: Option<String>,
    /// Filter users by Name.
    #[validate(length(max = 255))]
    pub name: Option<String>,
    /// Filter users by the federated unique ID.
    #[validate(length(max = 64))]
    pub unique_id: Option<String>,
}

impl From<UserListParameters> for identity_types::UserListParameters {
    fn from(value: UserListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            name: value.name,
            unique_id: value.unique_id,
            //    limit: value.limit,
        }
    }
}
