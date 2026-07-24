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
//! Credential wire types (ADR 0019).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "validate")]
use validator::Validate;

/// The credential data, as returned to API clients. `blob` is the decrypted
/// secret serialised as a JSON-encoded string (ADR 0019 §2, "Wire format of
/// `blob`") — never a nested object. `encrypted_blob`/`key_hash` are never
/// exposed.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Credential {
    /// Credential ID. For `ec2` this is `SHA-256(blob['access'])`
    /// hex-encoded; otherwise a random UUID.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,

    /// The decrypted secret blob, as a JSON-encoded string.
    pub blob: String,

    /// The project associated with the credential (mandatory for `ec2`).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub project_id: Option<String>,

    /// The credential type (`ec2`, `totp`, or an arbitrary custom string).
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub r#type: String,

    /// The ID of the user who owns the credential.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub user_id: String,

    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Single credential envelope.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct CredentialResponse {
    /// Credential object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub credential: Credential,
}

/// Credentials list envelope.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct CredentialList {
    /// Collection of credential objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub credentials: Vec<Credential>,

    /// Pagination links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<crate::Link>>,
}

/// Query parameters for `GET /v3/credentials`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct CredentialListParameters {
    /// Filter by credential type.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub r#type: Option<String>,
    /// Filter by owning user ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub user_id: Option<String>,
}

/// Credential create request body.
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
pub struct CredentialCreate {
    /// The decrypted secret blob, as a JSON string. For `ec2` must contain an
    /// `access` key.
    pub blob: String,

    /// The credential type.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub r#type: String,

    /// The project to associate the credential with. Required if `type` is
    /// `ec2`.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub project_id: Option<String>,

    /// The user to own the credential. Defaults to the authenticated user
    /// under user scope; must be supplied explicitly under system scope
    /// (ADR 0019 §2).
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub user_id: Option<String>,

    /// Extra attributes for the credential.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(inline, additional_properties))]
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// New credential creation request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct CredentialCreateRequest {
    /// Credential object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub credential: CredentialCreate,
}

/// Credential update request body. Only `blob`, `type`, and `project_id` are
/// updatable; `user_id` is immutable (CVE-2020-12691).
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
pub struct CredentialUpdate {
    /// New decrypted secret blob (triggers re-encryption).
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,

    /// New credential type.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub r#type: Option<String>,
}

/// Credential update request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct CredentialUpdateRequest {
    /// Credential update patch.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub credential: CredentialUpdate,
}
