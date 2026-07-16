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
use secrecy::SecretString;
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
    #[serde(serialize_with = "crate::common::serialize_optional_datetime_micros")]
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
#[derive(Clone, Debug, Deserialize, Serialize)]
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
#[cfg_attr(
    feature = "validate",
    validate(schema(function = "validate_user_create_secret"))
)]
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
    #[serde(default = "crate::default_true")]
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

    /// The password for the user. Non-emptiness and regex policy are enforced
    /// at the service layer via `security_compliance.validate_password`.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::common::serialize_optional_secret"
    )]
    pub password: Option<SecretString>,
}

impl UserCreate {
    #[must_use]
    pub fn to_policy_input(&self) -> serde_json::Value {
        let mut value = serde_json::to_value(self).unwrap_or_default();
        if let Some(input) = value.as_object_mut() {
            input.remove("password");
        }
        value
    }
}

#[cfg(feature = "validate")]
// NOTE: Struct-level (not field-level #[validate(custom)]) because validator
// 0.20 serializes the failing field into ValidationError, which does not
// compile for SecretString and would leak the secret; the derive still
// validates all other fields.
fn validate_user_create_secret(value: &UserCreate) -> Result<(), validator::ValidationError> {
    crate::common::validate_optional_secret_length(&value.password, 72)
}

/// Complete create user request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct UserCreateRequest {
    /// User object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub user: UserCreate,
}

/// Update user data.
#[derive(Clone, Debug, Deserialize, Serialize)]
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
#[cfg_attr(
    feature = "validate",
    validate(schema(function = "validate_user_update_secret"))
)]
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
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::common::serialize_optional_secret"
    )]
    pub password: Option<SecretString>,
}

impl UserUpdate {
    #[must_use]
    pub fn to_policy_input(&self) -> serde_json::Value {
        let mut input = self
            .extra
            .clone()
            .into_iter()
            .collect::<serde_json::Map<_, _>>();
        input.insert(
            "default_project_id".to_string(),
            serde_json::json!(self.default_project_id),
        );
        input.insert("enabled".to_string(), serde_json::json!(self.enabled));
        input.insert("name".to_string(), serde_json::json!(self.name));
        input.insert("options".to_string(), serde_json::json!(self.options));
        serde_json::Value::Object(input)
    }
}

#[cfg(feature = "validate")]
// NOTE: Struct-level (not field-level #[validate(custom)]) because validator
// 0.20 serializes the failing field into ValidationError, which does not
// compile for SecretString and would leak the secret; the derive still
// validates all other fields.
fn validate_user_update_secret(value: &UserUpdate) -> Result<(), validator::ValidationError> {
    crate::common::validate_optional_secret_length(&value.password, 72)
}

/// Complete update user request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct UserUpdateRequest {
    /// User object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub user: UserUpdate,
}

/// Change user password data.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
#[cfg_attr(
    feature = "validate",
    validate(schema(function = "validate_user_password_secret"))
)]
pub struct UserPassword {
    /// The current password for the user.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[serde(serialize_with = "crate::common::serialize_secret_string")]
    pub original_password: SecretString,

    /// The new password for the user.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[serde(serialize_with = "crate::common::serialize_secret_string")]
    pub password: SecretString,
}

#[cfg(feature = "validate")]
fn validate_user_password_secret(value: &UserPassword) -> Result<(), validator::ValidationError> {
    crate::common::validate_secret_length(&value.original_password, 72)
        .and(crate::common::validate_secret_length(&value.password, 72))
}

/// Complete password change request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct UserPasswordRequest {
    /// User object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub user: UserPassword,
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
    ///
    /// Unlike other `*_id` fields this is not a Keystone-generated ID, but an
    /// arbitrary subject string supplied by the external IdP (e.g. a GitHub
    /// Actions OIDC `sub` claim), which for merge-queue-triggered runs can
    /// exceed 100 characters. The limit is kept below the backing column
    /// width (`VARCHAR(255)`) rather than the usual 64-char ID convention.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
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
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub unique_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    /// Critical: `UserCreate` carries BOTH `#[serde(flatten)] extra` and a
    /// `password`. Prove the flatten interaction round-trips the password for
    /// transport and does not drop `extra`, while `Debug` never leaks the
    /// value.
    #[test]
    fn usercreate_flatten_keeps_password_and_extra() {
        let uc: UserCreate = serde_json::from_str(
            r#"{"domain_id":"d","name":"alice","enabled":true,
                "password":"PWLEAK","x_custom":"xval","y_custom":"yval"}"#,
        )
        .unwrap();
        // sanity: password wrapped, extra captured via flatten
        assert_eq!(
            uc.password.as_ref().map(|s| s.expose_secret()),
            Some("PWLEAK")
        );
        assert_eq!(
            uc.extra.get("x_custom").and_then(|v| v.as_str()),
            Some("xval")
        );

        // Debug (the logging vector) must never reveal the password.
        assert!(
            !format!("{uc:?}").contains("PWLEAK"),
            "Debug leaked password: {uc:?}"
        );

        // Serialization is transparent (the body must round-trip on the wire),
        // and the flattened `extra` keys are preserved alongside `password`.
        let rendered = serde_json::to_string(&uc).unwrap();
        assert!(
            rendered.contains("PWLEAK"),
            "password not carried for transport: {rendered}"
        );
        assert!(
            rendered.contains("x_custom") && rendered.contains("xval"),
            "extra dropped by flatten: {rendered}"
        );
        assert!(
            rendered.contains("y_custom") && rendered.contains("yval"),
            "extra dropped by flatten: {rendered}"
        );
    }

    /// `UserUpdate` has the same flatten shape.
    #[test]
    fn userupdate_flatten_keeps_password_and_extra() {
        let uu: UserUpdate =
            serde_json::from_str(r#"{"password":"UPWLEAK","z_extra":"zz"}"#).unwrap();
        assert!(
            !format!("{uu:?}").contains("UPWLEAK"),
            "Debug leaked password: {uu:?}"
        );
        let rendered = serde_json::to_string(&uu).unwrap();
        assert!(rendered.contains("z_extra"), "extra dropped: {rendered}");
    }

    #[test]
    fn user_policy_input_omits_password_and_keeps_extra() {
        let create: UserCreate = serde_json::from_str(
            r#"{"domain_id":"d","name":"alice","enabled":true,
                "password":"PWLEAK","x_custom":"xval"}"#,
        )
        .unwrap();
        let input = create.to_policy_input();
        let rendered = input.to_string();
        assert!(
            !rendered.contains("PWLEAK"),
            "policy input leaked password: {rendered}"
        );
        assert!(input.get("password").is_none());
        assert_eq!(input.get("x_custom").and_then(|v| v.as_str()), Some("xval"));

        let update: UserUpdate =
            serde_json::from_str(r#"{"password":"UPWLEAK","z_extra":"zz"}"#).unwrap();
        let input = update.to_policy_input();
        let rendered = input.to_string();
        assert!(
            !rendered.contains("UPWLEAK"),
            "policy input leaked password: {rendered}"
        );
        assert!(input.get("password").is_none());
        assert_eq!(input.get("z_extra").and_then(|v| v.as_str()), Some("zz"));
    }

    /// Explicit `null` and absent password both deserialize to `None` (no
    /// panic, no plaintext resurrected).
    #[test]
    fn usercreate_password_null_and_absent_are_none() {
        let with_null: UserCreate =
            serde_json::from_str(r#"{"domain_id":"d","name":"a","enabled":true,"password":null}"#)
                .unwrap();
        assert!(with_null.password.is_none());
        let absent: UserCreate =
            serde_json::from_str(r#"{"domain_id":"d","name":"a","enabled":true}"#).unwrap();
        assert!(absent.password.is_none());
    }

    /// Debug of a populated `UserCreate` never renders the password.
    #[test]
    fn usercreate_debug_does_not_leak_password() {
        let uc: UserCreate = serde_json::from_str(
            r#"{"domain_id":"d","name":"a","enabled":true,"password":"DBGLEAK"}"#,
        )
        .unwrap();
        assert!(!format!("{uc:?}").contains("DBGLEAK"));
    }

    #[cfg(feature = "validate")]
    #[test]
    fn usercreate_validates_password_and_other_fields() {
        let valid: UserCreate = serde_json::from_str(
            r#"{"domain_id":"d","name":"alice","enabled":true,"password":"secret"}"#,
        )
        .unwrap();
        assert!(valid.validate().is_ok());

        let overlong_password: UserCreate = serde_json::from_str(&format!(
            r#"{{"domain_id":"d","name":"alice","enabled":true,"password":"{}"}}"#,
            "x".repeat(73)
        ))
        .unwrap();
        assert!(overlong_password.validate().is_err());

        let overlong_name: UserCreate = serde_json::from_str(&format!(
            r#"{{"domain_id":"d","name":"{}","enabled":true,"password":"secret"}}"#,
            "x".repeat(256)
        ))
        .unwrap();
        assert!(overlong_name.validate().is_err());
    }

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

    #[cfg(feature = "validate")]
    #[test]
    fn userpassword_validates_both_fields() {
        use validator::Validate;

        let valid: UserPassword =
            serde_json::from_str(r#"{"original_password":"old","password":"new"}"#).unwrap();
        assert!(valid.validate().is_ok());

        let overlong_new: UserPassword = serde_json::from_str(&format!(
            r#"{{"original_password":"old","password":"{}"}}"#,
            "x".repeat(73)
        ))
        .unwrap();
        assert!(overlong_new.validate().is_err());

        let overlong_old: UserPassword = serde_json::from_str(&format!(
            r#"{{"original_password":"{}","password":"new"}}"#,
            "x".repeat(73)
        ))
        .unwrap();
        assert!(overlong_old.validate().is_err());
    }

    #[test]
    fn userpassword_debug_does_not_leak_secrets() {
        let pw: UserPassword =
            serde_json::from_str(r#"{"original_password":"OLDLEAK","password":"NEWLEAK"}"#)
                .unwrap();
        let debug_output = format!("{pw:?}");
        assert!(
            !debug_output.contains("OLDLEAK"),
            "Debug leaked original_password: {debug_output}"
        );
        assert!(
            !debug_output.contains("NEWLEAK"),
            "Debug leaked password: {debug_output}"
        );
    }

    #[test]
    fn userpassword_request_roundtrip() {
        let req: UserPasswordRequest =
            serde_json::from_str(r#"{"user":{"original_password":"old","password":"new"}}"#)
                .unwrap();
        assert_eq!(req.user.original_password.expose_secret(), "old");
        assert_eq!(req.user.password.expose_secret(), "new");

        let rendered = serde_json::to_string(&req).unwrap();
        assert!(
            rendered.contains("old"),
            "original_password not carried: {rendered}"
        );
        assert!(rendered.contains("new"), "password not carried: {rendered}");
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

    #[test]
    fn federation_protocol_accepts_long_external_unique_id() {
        let long_unique_id =
            "repo:openstack-experimental/keystone:ref:refs/heads/gh-readonly-queue/main/pr-1030-d9517d719ea07d21b45f078970fc0efcf083670e".to_string();
        assert!(long_unique_id.len() > 64 && long_unique_id.len() <= 255);

        let protocol = FederationProtocol {
            protocol_id: "github".to_string(),
            unique_id: long_unique_id,
        };
        assert!(protocol.validate().is_ok());
    }

    #[test]
    fn federation_protocol_rejects_overlong_unique_id() {
        let protocol = FederationProtocol {
            protocol_id: "github".to_string(),
            unique_id: "x".repeat(256),
        };
        assert!(protocol.validate().is_err());
    }
}
