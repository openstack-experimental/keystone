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

use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use validator::Validate;

use crate::error::BuilderError;

/// User response object.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct User {
    /// The ID of the default project for the user. A user's default project
    /// must not be a domain. Setting this attribute does not grant any actual
    /// authorization on the project, and is merely provided for convenience.
    /// Therefore, the referenced project does not need to exist within the user
    /// domain. If the user does not have authorization to their default
    /// project, the default project is ignored at token creation. Additionally,
    /// if your default project is not valid, a token is issued without an
    /// explicit scope of authorization.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub default_project_id: Option<String>,

    /// User domain ID.
    #[validate(length(max = 64))]
    pub domain_id: String,

    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    pub enabled: bool,

    #[builder(default)]
    #[serde(
        flatten,
        deserialize_with = "crate::deserialize_optional_flatten_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub extra: Option<Value>,

    /// List of federated objects associated with a user. Each object in the
    /// list contains the idp_id and protocols. protocols is a list of objects,
    /// each of which contains protocol_id and unique_id of the protocol and
    /// user respectively.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub federated: Option<Vec<Federation>>,

    /// User ID.
    #[validate(length(max = 64))]
    pub id: String,

    /// User name.
    #[validate(length(max = 255))]
    pub name: String,

    /// The resource options for the user. Available resource options are
    /// ignore_change_password_upon_first_use, ignore_password_expiry,
    /// ignore_lockout_failure_attempts, lock_password,
    /// multi_factor_auth_enabled, and multi_factor_auth_rules
    /// ignore_user_inactivity.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub options: Option<UserOptions>,

    /// The date and time when the password expires. The time zone is UTC.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_expires_at: Option<DateTime<Utc>>,
}

/// Complete response with the user data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserResponse {
    /// User object.
    #[validate(nested)]
    pub user: User,
}

/// Create user data.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserCreate {
    /// The ID of the default project for the user. A user's default project
    /// must not be a domain. Setting this attribute does not grant any actual
    /// authorization on the project, and is merely provided for convenience.
    /// Therefore, the referenced project does not need to exist within the user
    /// domain. If the user does not have authorization to their default
    /// project, the default project is ignored at token creation. Additionally,
    /// if your default project is not valid, a token is issued without an
    /// explicit scope of authorization.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub default_project_id: Option<String>,

    /// User domain ID.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: String,

    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    #[builder(default)]
    pub enabled: bool,

    /// Additional user properties.
    #[builder(default)]
    #[serde(flatten)]
    pub extra: Option<Value>,

    /// The user name. Must be unique within the owning domain.
    #[validate(length(min = 1, max = 255))]
    pub name: String,

    /// The resource options for the user. Available resource options are
    /// ignore_change_password_upon_first_use, ignore_password_expiry,
    /// ignore_lockout_failure_attempts, lock_password,
    /// multi_factor_auth_enabled, and multi_factor_auth_rules
    /// ignore_user_inactivity.
    #[builder(default)]
    #[validate(nested)]
    pub options: Option<UserOptions>,

    /// The password for the user.
    #[builder(default)]
    #[validate(length(min = 1, max = 72))]
    pub password: Option<String>,
}

/// Complete create user request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserCreateRequest {
    /// User object.
    #[validate(nested)]
    pub user: UserCreate,
}

/// Update user data.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserUpdate {
    /// The ID of the default project for the user. A user's default project
    /// must not be a domain. Setting this attribute does not grant any actual
    /// authorization on the project, and is merely provided for convenience.
    /// Therefore, the referenced project does not need to exist within the user
    /// domain. If the user does not have authorization to their default
    /// project, the default project is ignored at token creation. Additionally,
    /// if your default project is not valid, a token is issued without an
    /// explicit scope of authorization.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub default_project_id: Option<Option<String>>,

    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    #[builder(default)]
    pub enabled: Option<bool>,

    /// Additional user properties.
    #[builder(default)]
    #[serde(flatten)]
    pub extra: Option<Value>,

    /// The user name. Must be unique within the owning domain.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub name: Option<String>,

    /// The resource options for the user. Available resource options are
    /// ignore_change_password_upon_first_use, ignore_password_expiry,
    /// ignore_lockout_failure_attempts, lock_password,
    /// multi_factor_auth_enabled, and multi_factor_auth_rules
    /// ignore_user_inactivity.
    #[builder(default)]
    #[validate(nested)]
    pub options: Option<UserOptions>,

    /// The password for the user.
    #[builder(default)]
    pub password: Option<String>,
}

/// Complete update user request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserUpdateRequest {
    /// User object.
    #[validate(nested)]
    pub user: UserCreate,
}

/// User options.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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

/// User federation data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Federation {
    /// Identity provider ID.
    pub idp_id: String,
    /// Protocols.
    #[validate(nested)]
    pub protocols: Vec<FederationProtocol>,
}

/// Federation protocol data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FederationProtocol {
    /// Federation protocol ID.
    #[validate(length(max = 64))]
    pub protocol_id: String,

    // TODO: unique ID should potentially belong to the IDP and not to the protocol
    /// Unique ID of the associated user.
    #[validate(length(max = 64))]
    pub unique_id: String,
}

/// List of users.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserList {
    /// Collection of user objects.
    #[validate(nested)]
    pub users: Vec<User>,
}

/// User list parameters.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_user_create() {
        let sot = UserCreateBuilder::default()
            .domain_id("domain")
            .name("name")
            .build()
            .unwrap();
        assert!(!sot.enabled, "user enabled flag defaults to `false`");
    }

    #[test]
    fn test_user() {
        let sot: User = serde_json::from_str(
            r#"
          {"domain_id": "did", "enabled": true, "id": "id", "name": "name"}
        "#,
        )
        .unwrap();
        assert!(sot.options.is_none(), "user options are unset");
        assert!(sot.extra.is_none(), "user extras are unset");
        let sot: User = serde_json::from_str(
            r#"
          {"domain_id": "did", "enabled": true, "id": "id", "name": "name", "foo": "bar"}
        "#,
        )
        .unwrap();
        assert!(sot.options.is_none(), "user options are unset");
        assert_eq!(
            sot.extra,
            Some(json!({"foo": "bar"})),
            "user extras are set"
        );
    }
}
