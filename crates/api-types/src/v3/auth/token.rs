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
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};
#[cfg(feature = "validate")]
use validator::Validate;

use crate::catalog::*;
use crate::scope::*;
use crate::trust::TokenTrustRepr;
use crate::v3::role::RoleRef;

/// Serialize a secret transparently for transport. These fields arrive in the
/// auth request body and must round-trip to the server; `SecretString` keeps
/// them out of `Debug`/logs, which is the exposure vector that matters.
fn serialize_secret_string<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(secret.expose_secret())
}

/// Authorization token.
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
pub struct Token {
    /// A list of one or two audit IDs. An audit ID is a unique, randomly
    /// generated, URL-safe string that you can use to track a token. The
    /// first audit ID is the current audit ID for the token. The second
    /// audit ID is present for only re-scoped tokens and is the audit ID
    /// from the token before it was re-scoped. A re- scoped token is one that
    /// was exchanged for another token of the same or different scope. You
    /// can use these audit IDs to track the use of a token or chain of
    /// tokens across multiple requests and endpoints without exposing the
    /// token ID to non-privileged users.
    pub audit_ids: Vec<String>,

    /// The authentication methods, which are commonly password, token, or other
    /// methods. Indicates the accumulated set of authentication methods
    /// that were used to obtain the token. For example, if the token was
    /// obtained by password authentication, it contains password. Later, if
    /// the token is exchanged by using the token authentication method one or
    /// more times, the subsequently created tokens contain both password
    /// and token in their methods attribute. Unlike multi-factor
    /// authentication, the methods attribute merely indicates the methods that
    /// were used to authenticate the user in exchange for a token. The client
    /// is responsible for determining the total number of authentication
    /// factors.
    pub methods: Vec<String>,

    /// The date and time when the token expires.
    pub expires_at: DateTime<Utc>,

    /// The date and time when the token was issued.
    pub issued_at: DateTime<Utc>,

    // # Subject
    /// A user object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub user: User,

    // # Scope
    /// A domain object including the id and name representing the domain the
    /// token is scoped to. This is only included in tokens that are scoped
    /// to a domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub domain: Option<Domain>,

    /// A project object including the id, name and domain object representing
    /// the project the token is scoped to. This is only included in tokens
    /// that are scoped to a project.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub project: Option<Project>,

    /// A trust object.
    #[serde(skip_serializing_if = "Option::is_none", rename = "OS-TRUST:trust")]
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub trust: Option<TokenTrustRepr>,

    // # Roles on the scope.
    /// A list of role objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub roles: Option<Vec<RoleRef>>,

    /// A system object.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub system: Option<System>,

    /// A catalog object.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub catalog: Option<Catalog>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "builder", derive(derive_builder::Builder))]
#[cfg_attr(
    feature = "builder",
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TokenResponse {
    /// Token.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub token: Token,
}

/// An authentication request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct AuthRequest {
    /// An identity object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub auth: AuthRequestInner,
}

/// An authentication request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct AuthRequestInner {
    /// An identity object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub identity: Identity,

    /// The authorization scope, including the system (Since v3.10), a project,
    /// or a domain (Since v3.4). If multiple scopes are specified in the
    /// same request (e.g. project and domain or domain and system) an HTTP
    /// 400 Bad Request will be returned, as a token cannot be
    /// simultaneously scoped to multiple authorization targets. An ID is
    /// sufficient to uniquely identify a project but if a project is
    /// specified by name, then the domain of the project must also be
    /// specified in order to uniquely identify the project by name. A domain
    /// scope may be specified by either the domain's ID or name with
    /// equivalent results.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub scope: Option<Scope>,
}

/// An identity object.
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
pub struct Identity {
    /// The authentication method. For password authentication, specify
    /// password.
    pub methods: Vec<String>,

    /// The password object, contains the authentication information.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub password: Option<PasswordAuth>,

    /// The token object, contains the authentication information.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub token: Option<TokenAuth>,

    /// The TOTP object, contains the authentication information for
    /// multi-factor authentication with a TOTP passcode (ADR 0019 §3).
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub totp: Option<TotpAuth>,
}

/// The password object, contains the authentication information.
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
pub struct PasswordAuth {
    /// A user object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub user: UserPassword,
}

/// User password information.
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
pub struct UserPassword {
    /// User ID.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: Option<String>,
    /// User Name.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: Option<String>,
    /// User domain.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub domain: Option<Domain>,
    /// User password.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[serde(serialize_with = "serialize_secret_string")]
    pub password: SecretString,
}

/// The TOTP object, contains the authentication information.
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
pub struct TotpAuth {
    /// A user object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub user: TotpUser,
}

/// User TOTP information.
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
pub struct TotpUser {
    /// User ID.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: Option<String>,
    /// User Name.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: Option<String>,
    /// User domain.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub domain: Option<Domain>,
    /// The passcode generated by the user's TOTP device/app.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[serde(serialize_with = "serialize_secret_string")]
    pub passcode: SecretString,
}

/// User information.
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
    /// User ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: String,
    /// User Name.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: Option<String>,
    /// User domain.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub domain: Domain,
    /// User password expiry date.
    #[cfg_attr(feature = "builder", builder(default))]
    pub password_expires_at: Option<DateTime<Utc>>,
}

/// The token object, contains the authentication information.
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
pub struct TokenAuth {
    /// An authentication token.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[serde(serialize_with = "serialize_secret_string")]
    pub id: SecretString,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct CreateTokenParameters {
    /// The authentication response excludes the service catalog. By default,
    /// the response includes the service catalog.
    pub nocatalog: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ValidateTokenParameters {
    /// The authentication response excludes the service catalog. By default,
    /// the response includes the service catalog.
    pub nocatalog: Option<bool>,
    /// Allow fetching a token that has expired. By default expired tokens
    /// return a 404 exception.
    pub allow_expired: Option<bool>,
}

/// System information.
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
pub struct System {
    /// All.
    pub all: bool,
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    const PWD: &str = "hunter2-plaintext";

    #[test]
    fn user_password_deserializes_plaintext_and_debug_never_leaks() {
        // Plaintext arrives on the wire and is accepted into the secret field.
        let up: UserPassword =
            serde_json::from_str(&format!(r#"{{"name":"alice","password":"{PWD}"}}"#)).unwrap();
        assert_eq!(up.password.expose_secret(), PWD);

        // Debug (the #[instrument] / log vector) must not leak.
        assert!(
            !format!("{up:?}").contains(PWD),
            "Debug leaked the password"
        );

        // Serialization is transparent: the auth body must carry the real
        // password so the request round-trips to the server.
        let json = serde_json::to_string(&up).unwrap();
        assert!(
            json.contains(PWD),
            "password not carried for transport: {json}"
        );
    }

    #[test]
    fn full_auth_request_debug_does_not_leak_password() {
        let req = nested_auth_request();
        // Debug of the whole nested request tree must not leak the password.
        assert!(
            !format!("{req:?}").contains(PWD),
            "Debug leaked via nested request"
        );
    }

    #[test]
    fn full_auth_request_serialize_carries_password_for_transport() {
        // The password sits 4 levels deep (auth -> identity -> password -> user).
        // Serialization must carry it through the whole nested tree so a client
        // can send the request, via both `to_string` and `to_value`.
        let req = nested_auth_request();
        let as_string = serde_json::to_string(&req).unwrap();
        let as_value = serde_json::to_value(&req).unwrap().to_string();
        for rendered in [as_string, as_value] {
            assert!(
                rendered.contains(PWD),
                "password not carried for transport at depth: {rendered}"
            );
        }
    }

    fn nested_auth_request() -> AuthRequest {
        serde_json::from_str(&format!(
            r#"{{"auth":{{"identity":{{"methods":["password"],
                 "password":{{"user":{{"name":"alice","password":"{PWD}"}}}}}}}}}}"#
        ))
        .unwrap()
    }
}
