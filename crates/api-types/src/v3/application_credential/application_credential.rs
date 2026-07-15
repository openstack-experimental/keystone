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
//! # Application credential API types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

use crate::v3::application_credential::access_rule::{AccessRule, AccessRuleCreate};
use crate::v3::role::RoleRef;

/// Full application credential representation.
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
pub struct ApplicationCredential {
    /// Optional list of access rules that restrict which API requests this
    /// credential is permitted to make. Each rule specifies a service, HTTP
    /// method, and URL path.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub access_rules: Option<Vec<AccessRule>>,

    /// Optional human-readable description of the application credential's
    /// purpose.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub description: Option<String>,

    /// Optional expiration date and time for the application credential. After
    /// this timestamp the credential is no longer valid. When `None`, the
    /// credential does not expire.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Unique identifier of the application credential.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,

    /// User-provided name of the application credential. Must be unique within
    /// the owning user's set of application credentials.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: String,

    /// Identifier of the project that the application credential is scoped to.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub project_id: String,

    /// List of roles delegated to this application credential. These must be a
    /// subset of the roles the owning user holds on the target project.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub roles: Vec<RoleRef>,

    /// Whether this application credential has unrestricted access. When
    /// `false` (the default), the credential cannot be used to create
    /// additional application credentials or trusts.
    pub unrestricted: bool,
}

/// Data for creating an application credential.
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
pub struct ApplicationCredentialCreate {
    /// Optional list of access rules to restrict which API requests the new
    /// credential is allowed to make.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub access_rules: Option<Vec<AccessRuleCreate>>,

    /// Optional human-readable description of the application credential.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Optional expiration date and time. When `None`, the credential does not
    /// expire.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Optional client-supplied identifier for the application credential. If
    /// not provided, the server generates one.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: Option<String>,

    /// Name of the application credential. Must be unique among the owning
    /// user's application credentials.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: String,

    /// Roles to delegate to the new credential. Must be a subset of the
    /// user's roles on the project. Defaults to all of the user's roles on the
    /// project when empty.
    #[cfg_attr(feature = "builder", builder(default))]
    pub roles: Vec<RoleRef>,

    /// Whether to allow unrestricted access. When `true`, the credential can
    /// create additional application credentials or trusts, which is
    /// potentially dangerous. Defaults to `false`.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unrestricted: Option<bool>,
}

/// Wrapper for a single application credential response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ApplicationCredentialResponse {
    /// The application credential object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub application_credential: ApplicationCredential,
}

/// Wrapper for a create request body.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ApplicationCredentialCreateRequest {
    /// The application credential creation payload.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub application_credential: ApplicationCredentialCreate,
}

/// Application credential as returned by create — includes secret (shown once only).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ApplicationCredentialCreated {
    /// Optional list of access rules associated with the credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_rules: Option<Vec<AccessRule>>,

    /// Optional human-readable description of the application credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Optional expiration date and time. `None` means the credential does not
    /// expire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Unique identifier of the newly created application credential.
    pub id: String,

    /// Name of the application credential.
    pub name: String,

    /// Identifier of the project the credential is scoped to.
    pub project_id: String,

    /// List of roles delegated to this application credential.
    pub roles: Vec<RoleRef>,

    /// The secret used for authentication. The secret is hashed before storage,
    /// so this is the only time it is returned in plaintext. If lost, a new
    /// application credential must be created.
    pub secret: String,

    /// Whether this credential has unrestricted access.
    pub unrestricted: bool,
}

/// Wrapper for create response body.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ApplicationCredentialCreateResponse {
    /// The newly created application credential, including the one-time
    /// secret.
    pub application_credential: ApplicationCredentialCreated,
}

/// List of application credentials.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ApplicationCredentialList {
    /// Collection of application credentials belonging to the user.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub application_credentials: Vec<ApplicationCredential>,
}

/// List parameters for filtering application credentials.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct ApplicationCredentialListParameters {
    /// Optional name filter. When set, only application credentials whose
    /// name matches this value are returned.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: Option<String>,
}
