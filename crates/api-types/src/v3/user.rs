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

use crate::secret_serde::serialize_secret_redacted;

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
///
/// `PartialEq` is intentionally not derived: `password` is wrapped in
/// [`SecretString`], which does not implement `PartialEq` by design.
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

    /// The password for the user. Wrapped in [`SecretString`] to prevent
    /// accidental exposure via Debug/tracing; redacted (never exposed) when
    /// serialized into policy/audit payloads. Non-emptiness and regex policy are
    /// enforced on the wrapped value at the service layer via
    /// `security_compliance.validate_password`.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[serde(
        default,
        serialize_with = "serialize_secret_redacted",
        skip_serializing_if = "Option::is_none"
    )]
    pub password: Option<SecretString>,
}

/// Complete create user request.
///
/// `PartialEq` is not derived because the embedded `UserCreate` carries a
/// `SecretString`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct UserCreateRequest {
    /// User object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub user: UserCreate,
}

/// Update user data.
///
/// `PartialEq` is intentionally not derived: `password` is wrapped in
/// [`SecretString`], which does not implement `PartialEq` by design.
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

    /// The password for the user. Wrapped in [`SecretString`] to prevent
    /// accidental exposure via Debug/tracing; redacted (never exposed) when
    /// serialized into policy/audit payloads.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[serde(
        default,
        serialize_with = "serialize_secret_redacted",
        skip_serializing_if = "Option::is_none"
    )]
    pub password: Option<SecretString>,
}

/// Complete update user request.
///
/// `PartialEq` is not derived because the embedded `UserUpdate` carries a
/// `SecretString`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct UserUpdateRequest {
    /// User object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub user: UserUpdate,
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
    use secrecy::ExposeSecret;

    use super::*;

    /// Critical: `UserCreate` carries BOTH `#[serde(flatten)] extra` and a
    /// `password` with a custom `serialize_with` + `skip_serializing_if`. This is
    /// the exact struct the handler serializes into OPA policy input
    /// (`json!({"user": req.user})`). Prove the flatten interaction does not
    /// leak the password and does not drop `extra`.
    #[test]
    fn usercreate_flatten_redacts_password_and_keeps_extra() {
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

        // Both the raw serialize and the OPA-shaped `json!({"user": uc})` path.
        let direct = serde_json::to_string(&uc).unwrap();
        let opa = serde_json::json!({ "user": &uc }).to_string();
        for rendered in [direct, opa] {
            assert!(
                !rendered.contains("PWLEAK"),
                "flatten leaked password: {rendered}"
            );
            assert!(
                rendered.contains("[REDACTED]"),
                "password not redacted: {rendered}"
            );
            assert!(
                rendered.contains("x_custom") && rendered.contains("xval"),
                "extra dropped by flatten+redact: {rendered}"
            );
            assert!(
                rendered.contains("y_custom") && rendered.contains("yval"),
                "extra dropped by flatten+redact: {rendered}"
            );
        }
    }

    /// `UserUpdate` has the same flatten+redact shape.
    #[test]
    fn userupdate_flatten_redacts_password_and_keeps_extra() {
        let uu: UserUpdate =
            serde_json::from_str(r#"{"password":"UPWLEAK","z_extra":"zz"}"#).unwrap();
        let rendered = serde_json::json!({ "user": &uu }).to_string();
        assert!(!rendered.contains("UPWLEAK"), "leaked: {rendered}");
        assert!(rendered.contains("[REDACTED]"), "not redacted: {rendered}");
        assert!(rendered.contains("z_extra"), "extra dropped: {rendered}");
    }

    /// Explicit `null` and absent password both deserialize to `None` (no panic,
    /// no plaintext resurrected).
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
