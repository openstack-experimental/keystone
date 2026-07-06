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
use derive_builder::Builder;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde_json::Value;
use validator::{Validate, ValidationError};

use crate::error::BuilderError;

fn validate_secret_length(secret: &SecretString, max: usize) -> Result<(), ValidationError> {
    if secret.expose_secret().chars().count() <= max {
        Ok(())
    } else {
        Err(ValidationError::new("length"))
    }
}

fn validate_optional_secret_length(
    secret: &Option<SecretString>,
    max: usize,
) -> Result<(), ValidationError> {
    match secret {
        Some(secret) => validate_secret_length(secret, max),
        None => Ok(()),
    }
}

// NOTE: password length/non-emptiness is not validated with a field-level
// validator here — `SecretString` cannot use validator's `length` (no
// `ValidateLength`) nor `custom` (which requires the field to be `Serialize`).
// Non-emptiness is enforced centrally on the wrapped value at the service layer
// via `security_compliance.validate_password`.

#[derive(Builder, Clone, Debug, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct UserResponse {
    /// The ID of the default project for the user. A user's default project
    /// must not be a domain. Setting this attribute does not grant any actual
    /// authorization on the project, and is merely provided for convenience.
    /// Therefore, the referenced project does not need to exist within the user
    /// domain. If the user does not have authorization to their
    /// default project, the default project is ignored at token creation.
    /// Additionally, if your default project is not valid, a token
    /// is issued without an explicit scope of authorization.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub default_project_id: Option<String>,

    /// The ID of the domain.
    #[validate(length(max = 64))]
    pub domain_id: String,
    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    pub enabled: bool,

    /// Additional user properties.
    #[builder(default)]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,

    /// List of federated objects associated with a user. Each object in the
    /// list contains the `idp_id` and `protocols`. `protocols` is a list of
    /// objects, each of which contains `protocol_id` and `unique_id` of the
    /// protocol and user respectively.
    #[builder(default)]
    #[validate(nested)]
    pub federated: Option<Vec<Federation>>,

    /// The user ID.
    #[validate(length(max = 64))]
    pub id: String,

    /// The user name. Must be unique within the owning domain.
    #[validate(length(max = 255))]
    pub name: String,
    #[builder(default)]

    /// The options for the user.
    #[validate(nested)]
    pub options: UserOptions,

    #[builder(default)]
    pub password_expires_at: Option<DateTime<Utc>>,
}

/// User creation data.
///
/// `PartialEq` is intentionally not derived: `password` is wrapped in
/// [`SecretString`], which does not implement `PartialEq` by design.
#[derive(Builder, Clone, Debug, Validate)]
#[validate(schema(function = "validate_user_create_secret"))]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct UserCreate {
    /// The ID of the default project for the user.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub default_project_id: Option<String>,

    /// The ID of the domain.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: String,

    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    #[builder(default)]
    pub enabled: Option<bool>,

    /// Additional user properties.
    #[builder(default)]
    pub extra: HashMap<String, Value>,

    /// List of federated objects associated with a user. Each object in the
    /// list contains the `idp_id` and `protocols`. `protocols` is a list of
    /// objects, each of which contains `protocol_id` and `unique_id` of the
    /// protocol and user respectively.
    #[builder(default)]
    #[validate(nested)]
    pub federated: Option<Vec<Federation>>,

    /// The ID of the user. When unset a new UUID would be assigned.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,

    /// The user name. Must be unique within the owning domain.
    #[validate(length(min = 1, max = 255))]
    pub name: String,

    /// The resource options for the user.
    #[builder(default)]
    #[validate(nested)]
    pub options: Option<UserOptions>,

    /// User password. Non-emptiness and regex policy are enforced at the service
    /// layer via `security_compliance.validate_password`.
    #[builder(default)]
    pub password: Option<SecretString>,

    /// The kind of local-authentication row to create for the user:
    /// `Local` creates a `local_user` row (password allowed), `NonLocal`
    /// creates a `nonlocal_user` row (no password allowed, for externally
    /// managed identities such as SCIM-provisioned users). Ignored when
    /// `federated` is set.
    #[builder(default = "UserType::Local")]
    pub user_type: UserType,
}

fn validate_user_create_secret(value: &UserCreate) -> Result<(), ValidationError> {
    validate_optional_secret_length(&value.password, 72)
}

/// User update data.
///
/// `PartialEq` is intentionally not derived: `password` is wrapped in
/// [`SecretString`], which does not implement `PartialEq` by design.
#[derive(Builder, Clone, Debug, Default, Validate)]
#[validate(schema(function = "validate_user_update_secret"))]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct UserUpdate {
    /// The ID of the default project for the user.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub default_project_id: Option<Option<String>>,

    /// If the user is enabled, this value is true. If the user is disabled,
    /// this value is false.
    #[builder(default)]
    pub enabled: Option<bool>,

    /// Additional user properties.
    #[builder(default)]
    pub extra: HashMap<String, Value>,

    /// List of federated objects associated with a user. Each object in the
    /// list contains the idp_id and protocols. protocols is a list of objects,
    /// each of which contains protocol_id and unique_id of the protocol and
    /// user respectively.
    #[builder(default)]
    #[validate(nested)]
    pub federated: Option<Vec<Federation>>,

    /// The user name. Must be unique within the owning domain.
    #[validate(length(max = 255))]
    #[builder(default)]
    pub name: Option<String>,

    /// The resource options for the user.
    #[builder(default)]
    #[validate(nested)]
    pub options: Option<UserOptions>,

    /// New user password. Non-emptiness/policy enforced at the service layer via
    /// `security_compliance.validate_password`.
    #[builder(default)]
    pub password: Option<SecretString>,
}

fn validate_user_update_secret(value: &UserUpdate) -> Result<(), ValidationError> {
    validate_optional_secret_length(&value.password, 72)
}

/// User options.
#[derive(Builder, Clone, Debug, Default, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct UserOptions {
    pub ignore_change_password_upon_first_use: Option<bool>,

    pub ignore_password_expiry: Option<bool>,

    pub ignore_lockout_failure_attempts: Option<bool>,

    pub lock_password: Option<bool>,

    pub ignore_user_inactivity: Option<bool>,

    pub multi_factor_auth_rules: Option<Vec<Vec<String>>>,

    pub multi_factor_auth_enabled: Option<bool>,

    /// Identifies whether the user is a service account.
    pub is_service_account: Option<bool>,
}

/// User federation data.
#[derive(Builder, Clone, Debug, Default, Eq, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Federation {
    /// Identity provider ID.
    #[validate(length(max = 64))]
    pub idp_id: String,

    /// Protocols.
    #[builder(default)]
    #[validate(nested)]
    pub protocols: Vec<FederationProtocol>,

    /// Unique ID of the user within the IdP.
    #[builder]
    pub unique_id: String,
}

/// Federation protocol data.
#[derive(Builder, Clone, Debug, Default, Eq, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct FederationProtocol {
    /// Federation protocol ID.
    #[validate(length(max = 64))]
    pub protocol_id: String,

    // TODO: unique ID should potentially belong to the IDP and not to the protocol
    /// Unique ID of the associated user.
    #[validate(length(max = 64))]
    pub unique_id: String,
}

/// User listing parameters.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
pub struct UserListParameters {
    /// Filter users by the domain.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub domain_id: Option<String>,

    /// Filter users by the name attribute.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub name: Option<String>,

    /// Filter users by the federated unique ID.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub unique_id: Option<String>,

    /// Filter users by User Type (local, federated, nonlocal, all).
    #[builder(default)]
    //#[serde(default, rename = "type")]
    pub user_type: Option<UserType>,
}

/// User type for filtering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
//#[serde(rename_all = "lowercase")]
pub enum UserType {
    /// All users (default behavior).
    #[default]
    All,

    /// Federated users only (authenticated via external IdP).
    Federated,

    /// Local users only (with passwords).
    Local,

    /// Non-local users (users without local authentication).
    NonLocal,

    /// Service Accounts (bots, etc).
    ServiceAccount,
}

/// User password information.
///
/// `Default` and `PartialEq` are intentionally not derived: `password` is a
/// required [`SecretString`], which implements neither by design.
#[derive(Builder, Clone, Debug, Validate)]
#[validate(schema(function = "validate_user_password_auth_secret"))]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct UserPasswordAuthRequest {
    /// User ID.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub id: Option<String>,

    /// User Name.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub name: Option<String>,

    /// User domain.
    #[builder(default)]
    #[validate(nested)]
    pub domain: Option<Domain>,

    /// User password. Required (no builder default: `SecretString` does not
    /// implement `Default`).
    pub password: SecretString,
}

fn validate_user_password_auth_secret(
    value: &UserPasswordAuthRequest,
) -> Result<(), ValidationError> {
    validate_secret_length(&value.password, 72)
}

/// Manual `Default` (the derive cannot be used because `SecretString` does not
/// implement `Default`). Preserves the pre-wrapping default of an empty
/// password. Production code constructs this via the builder, which requires an
/// explicit password.
impl Default for UserPasswordAuthRequest {
    fn default() -> Self {
        Self {
            id: None,
            name: None,
            domain: None,
            password: SecretString::from(""),
        }
    }
}

/// User TOTP authentication request.
///
/// `PartialEq`/`Default` are intentionally not derived: `passcode` is a required
/// [`SecretString`], which implements neither by design.
#[derive(Builder, Clone, Debug, Validate)]
#[validate(schema(function = "validate_user_totp_auth_secret"))]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct UserTotpAuthRequest {
    /// User ID.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub id: Option<String>,

    /// User Name.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub name: Option<String>,

    /// User domain.
    #[builder(default)]
    #[validate(nested)]
    pub domain: Option<Domain>,

    /// The passcode generated by the user's TOTP device/app.
    pub passcode: SecretString,
}

fn validate_user_totp_auth_secret(value: &UserTotpAuthRequest) -> Result<(), ValidationError> {
    validate_secret_length(&value.passcode, 32)
}

/// Domain information.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Domain {
    /// Domain ID.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub id: Option<String>,

    /// Domain Name.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub name: Option<String>,
}
