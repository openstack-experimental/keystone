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
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::api::error::TokenError;
use crate::api::types::*;
use crate::api::v3::role::types::Role;
use crate::identity::types as identity_types;
use crate::token::Token as BackendToken;

/// Authorization token
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
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

    /// A user object.
    //#[builder(default)]
    pub user: User,

    /// A project object including the id, name and domain object representing
    /// the project the token is scoped to. This is only included in tokens
    /// that are scoped to a project.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub project: Option<Project>,

    /// A domain object including the id and name representing the domain the
    /// token is scoped to. This is only included in tokens that are scoped
    /// to a domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub domain: Option<Domain>,

    /// A list of role objects
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub roles: Option<Vec<Role>>,

    /// A catalog object.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(default)]
    pub catalog: Option<Catalog>,
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct TokenResponse {
    /// Token
    pub token: Token,
}

impl IntoResponse for TokenResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// An authentication request.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct AuthRequest {
    /// An identity object.
    pub auth: AuthRequestInner,
}

/// An authentication request.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct AuthRequestInner {
    /// An identity object.
    pub identity: Identity,

    /// The authorization scope, including the system (Since v3.10), a project,
    /// or a domain (Since v3.4). If multiple scopes are specified in the
    /// same request (e.g. project and domain or domain and system) an HTTP
    /// 400 Bad Request will be returned, as a token cannot be
    /// simultaneously scoped to multiple authorization targets. An ID is
    /// sufficient to uniquely identify a project but if a project is
    /// specified by name, then the domain of the project must also be
    /// specified in order to uniquely identify the project by name. A domain
    /// scope may be specified by either the domain’s ID or name with
    /// equivalent results.
    pub scope: Option<Scope>,
}

/// An identity object.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct Identity {
    /// The authentication method. For password authentication, specify
    /// password.
    pub methods: Vec<String>,

    /// The password object, contains the authentication information.
    pub password: Option<PasswordAuth>,

    /// The token object, contains the authentication information.
    pub token: Option<TokenAuth>,
}

/// The password object, contains the authentication information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct PasswordAuth {
    /// A user object.
    #[builder(default)]
    pub user: UserPassword,
}

/// User password information
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
pub struct UserPassword {
    /// User ID
    pub id: Option<String>,
    /// User Name
    pub name: Option<String>,
    /// User domain
    pub domain: Option<Domain>,
    /// User password expiry date
    pub password: String,
}

impl TryFrom<UserPassword> for identity_types::UserPasswordAuthRequest {
    type Error = TokenError;

    fn try_from(value: UserPassword) -> Result<Self, Self::Error> {
        let mut upa = identity_types::UserPasswordAuthRequestBuilder::default();
        if let Some(id) = &value.id {
            upa.id(id);
        }
        if let Some(name) = &value.name {
            upa.name(name);
        }
        if let Some(domain) = &value.domain {
            let mut domain_builder = identity_types::DomainBuilder::default();
            if let Some(id) = &domain.id {
                domain_builder.id(id);
            }
            if let Some(name) = &domain.name {
                domain_builder.name(name);
            }
            upa.domain(domain_builder.build()?);
        }
        upa.password(value.password.clone());
        Ok(upa.build()?)
    }
}

/// User information
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(into))]
pub struct User {
    /// User ID
    pub id: String,
    /// User Name
    #[builder(default)]
    pub name: Option<String>,
    /// User domain
    pub domain: Domain,
    /// User password expiry date
    #[builder(default)]
    pub password_expires_at: Option<DateTime<Utc>>,
}

impl TryFrom<&BackendToken> for Token {
    type Error = TokenError;

    fn try_from(value: &BackendToken) -> Result<Self, Self::Error> {
        let mut token = TokenBuilder::default();
        token.user(UserBuilder::default().id(value.user_id()).build()?);
        token.methods(value.methods().clone());
        token.audit_ids(value.audit_ids().clone());
        token.expires_at(*value.expires_at());
        Ok(token.build()?)
    }
}

/// The token object, contains the authentication information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct TokenAuth {
    /// An authentication token.
    pub id: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, IntoParams)]
pub struct CreateTokenParameters {
    /// The authentication response excludes the service catalog. By default,
    /// the response includes the service catalog.
    pub nocatalog: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, IntoParams)]
pub struct ValidateTokenParameters {
    /// The authentication response excludes the service catalog. By default,
    /// the response includes the service catalog.
    pub nocatalog: Option<bool>,
    /// Allow fetching a token that has expired. By default expired tokens
    /// return a 404 exception.
    pub allow_expired: Option<bool>,
}
