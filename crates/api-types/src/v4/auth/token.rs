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
use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

use crate::catalog::*;
use crate::scope::*;
use crate::trust::TokenTrustRepr;
use crate::v3::role::RoleRef;

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
    //#[cfg_attr(feature = "builder", builder(default))]
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

    /// A system object.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub system: Option<System>,

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

    /// A catalog object.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub catalog: Option<Catalog>,
}

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
pub struct TokenResponse {
    /// Token.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub token: Token,
}

/// An authentication request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct AuthRequest {
    /// An identity object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub auth: AuthRequestInner,
}

/// An authentication request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Identity {
    /// The authentication method. For password authentication, specify
    /// password.
    pub methods: Vec<String>,

    /// The password object, contains the authentication information.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub password: Option<PasswordAuth>,

    /// The token object, contains the authentication information.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub token: Option<TokenAuth>,
}

/// The password object, contains the authentication information.
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
pub struct PasswordAuth {
    /// A user object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub user: UserPassword,
}

/// User password information.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct UserPassword {
    /// User ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: Option<String>,
    /// User Name.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub name: Option<String>,
    /// User domain.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub domain: Option<Domain>,
    /// User password.
    #[cfg_attr(feature = "validate", validate(length(max = 72)))]
    pub password: String,
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
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub name: Option<String>,
    /// User domain.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub domain: Domain,
    /// User password expiry date.
    #[cfg_attr(feature = "builder", builder(default))]
    pub password_expires_at: Option<DateTime<Utc>>,
}

/// The token object, contains the authentication information.
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
pub struct TokenAuth {
    /// An authentication token.
    #[cfg_attr(feature = "validate", validate(length(max = 1024)))]
    pub id: String,
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
