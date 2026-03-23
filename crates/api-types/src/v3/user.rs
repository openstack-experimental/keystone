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
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "validate")]
use validator::Validate;

/// User response object.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct User {
    /// The ID of the default project for the user. A user's default project
    /// must not be a domain. Setting this attribute does not grant any actual
    /// authorization on the project, and is merely provided for convenience.
    /// Therefore, the referenced project does not need to exist within the user
    /// domain. If the user does not have authorization to their default
    /// project, the default project is ignored at token creation. Additionally,
    /// if your default project is not valid, a token is issued without an
    /// explicit scope of authorization.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub default_project_id: Option<String>,

    /// User domain ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: String,

    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    pub enabled: bool,

    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,

    /// List of federated objects associated with a user. Each object in the
    /// list contains the idp_id and protocols. protocols is a list of objects,
    /// each of which contains protocol_id and unique_id of the protocol and
    /// user respectively.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub federated: Option<Vec<Federation>>,

    /// User ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: String,

    /// User name.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: String,

    /// The resource options for the user. Available resource options are
    /// ignore_change_password_upon_first_use, ignore_password_expiry,
    /// ignore_lockout_failure_attempts, lock_password,
    /// multi_factor_auth_enabled, and multi_factor_auth_rules
    /// ignore_user_inactivity.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub options: Option<UserOptions>,

    /// The date and time when the password expires. The time zone is UTC.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_expires_at: Option<DateTime<Utc>>,
}

/// Complete response with the user data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct UserResponse {
    /// User object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub user: User,
}

/// Create user data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct UserCreate {
    /// The ID of the default project for the user. A user's default project
    /// must not be a domain. Setting this attribute does not grant any actual
    /// authorization on the project, and is merely provided for convenience.
    /// Therefore, the referenced project does not need to exist within the user
    /// domain. If the user does not have authorization to their default
    /// project, the default project is ignored at token creation. Additionally,
    /// if your default project is not valid, a token is issued without an
    /// explicit scope of authorization.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub default_project_id: Option<String>,

    /// User domain ID.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: String,

    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    #[cfg_attr(feature = "builder", builder(default))]
    pub enabled: bool,

    /// Additional user properties.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,

    /// The user name. Must be unique within the owning domain.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: String,

    /// The resource options for the user. Available resource options are
    /// ignore_change_password_upon_first_use, ignore_password_expiry,
    /// ignore_lockout_failure_attempts, lock_password,
    /// multi_factor_auth_enabled, and multi_factor_auth_rules
    /// ignore_user_inactivity.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub options: Option<UserOptions>,

    /// The password for the user.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 72)))]
    pub password: Option<String>,
}

/// Complete create user request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct UserCreateRequest {
    /// User object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub user: UserCreate,
}

/// Update user data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct UserUpdate {
    /// The ID of the default project for the user. A user's default project
    /// must not be a domain. Setting this attribute does not grant any actual
    /// authorization on the project, and is merely provided for convenience.
    /// Therefore, the referenced project does not need to exist within the user
    /// domain. If the user does not have authorization to their default
    /// project, the default project is ignored at token creation. Additionally,
    /// if your default project is not valid, a token is issued without an
    /// explicit scope of authorization.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub default_project_id: Option<Option<String>>,

    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    #[cfg_attr(feature = "builder", builder(default))]
    pub enabled: Option<bool>,

    /// Additional user properties.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,

    /// The user name. Must be unique within the owning domain.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: Option<String>,

    /// The resource options for the user. Available resource options are
    /// ignore_change_password_upon_first_use, ignore_password_expiry,
    /// ignore_lockout_failure_attempts, lock_password,
    /// multi_factor_auth_enabled, and multi_factor_auth_rules
    /// ignore_user_inactivity.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub options: Option<UserOptions>,

    /// The password for the user.
    #[cfg_attr(feature = "builder", builder(default))]
    pub password: Option<String>,
}

/// Complete update user request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct UserUpdateRequest {
    /// User object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub user: UserCreate,
}

/// User options.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
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
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Federation {
    /// Identity provider ID.
    pub idp_id: String,
    /// Protocols.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub protocols: Vec<FederationProtocol>,
}

/// Federation protocol data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct FederationProtocol {
    /// Federation protocol ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub protocol_id: String,

    // TODO: unique ID should potentially belong to the IDP and not to the protocol
    /// Unique ID of the associated user.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub unique_id: String,
}

/// List of users.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct UserList {
    /// Collection of user objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub users: Vec<User>,
}

/// User list parameters.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct UserListParameters {
    /// Filter users by Domain ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: Option<String>,

    /// Filter users by Name.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: Option<String>,

    /// Filter users by the federated unique ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub unique_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "builder")]
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
        //assert!(sot.extra.is_none(), "user extras are unset");
        let sot: User = serde_json::from_str(
            r#"
          {"domain_id": "did", "enabled": true, "id": "id", "name": "name", "foo": "bar"}
        "#,
        )
        .unwrap();
        assert!(sot.options.is_none(), "user options are unset");
        //assert_eq!(
        //    sot.extra,
        //    Some(json!({"foo": "bar"})),
        //    "user extras are set"
        //);
    }
}
