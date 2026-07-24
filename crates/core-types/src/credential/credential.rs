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
//! # Credential types
use std::collections::HashMap;

use derive_builder::Builder;
use serde::Serialize;
use serde_json::Value;
use validator::Validate;

use crate::error::BuilderError;

/// The credential object as returned to API clients.
///
/// `blob` is the *decrypted* secret, serialised the same way Python Keystone
/// serialises it: as a JSON-encoded **string** (not a nested object) — see
/// ADR 0019 §2 "Wire format of `blob`". `encrypted_blob` and `key_hash` are
/// never exposed here.
#[derive(Builder, Clone, Debug, PartialEq, Serialize, Validate)]
#[builder(setter(strip_option, into))]
#[builder(build_fn(error = "BuilderError"))]
pub struct Credential {
    /// Extensible JSON field, stored by Python as a JSON-encoded string in a
    /// `Text` column (`JsonBlob`). Modelled as a parsed map here for API
    /// serialisation.
    #[builder(default)]
    pub extra: Option<HashMap<String, Value>>,

    /// The ID of the credential. For `ec2` this is `SHA-256(blob['access'])`
    /// hex-encoded; otherwise a random UUID.
    #[validate(length(min = 1, max = 64))]
    pub id: String,

    /// The decrypted secret blob, as a JSON-encoded string.
    pub blob: String,

    /// The ID of the project associated with the credential (mandatory for
    /// `ec2`).
    #[builder(default)]
    #[validate(length(max = 64))]
    pub project_id: Option<String>,

    /// The credential type (`ec2`, `totp`, or an arbitrary custom string).
    #[validate(length(min = 1, max = 255))]
    pub r#type: String,

    /// The ID of the user who owns the credential.
    #[validate(length(min = 1, max = 64))]
    pub user_id: String,
}

/// The credential object to be created.
#[derive(Builder, Clone, Debug, Default, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct CredentialCreate {
    /// Extensible JSON field.
    #[builder(default)]
    pub extra: Option<HashMap<String, Value>>,

    /// The decrypted secret blob, as a JSON string. For `ec2` must contain an
    /// `access` key.
    pub blob: String,

    /// The ID of the credential. Computed by the service layer before the
    /// backend call so it is known up-front for audit events: `ec2` uses
    /// `SHA-256(blob['access'])` hex-encoded; other types use a random UUID
    /// (ADR 0019 §1, ID Generation). Not user-settable via the public API.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub id: Option<String>,

    /// The ID of the project associated with the credential. Required if
    /// `r#type` is `ec2`.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub project_id: Option<String>,

    /// The credential type.
    #[validate(length(min = 1, max = 255))]
    pub r#type: String,

    /// The ID of the user who owns the credential. Defaults to the
    /// authenticated user when the request is user-scoped; must be supplied
    /// explicitly under system scope (ADR 0019 §2, Create).
    #[builder(default)]
    #[validate(length(max = 64))]
    pub user_id: Option<String>,
}

/// The credential object to be updated. Only `Some` fields are applied;
/// `user_id` is intentionally absent — it is immutable (CVE-2020-12691).
#[derive(Builder, Clone, Debug, Default, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct CredentialUpdate {
    /// New decrypted secret blob (triggers re-encryption with the current
    /// Primary Key and updates `key_hash`).
    #[builder(default)]
    pub blob: Option<String>,

    /// New credential type.
    #[builder(default)]
    #[validate(length(min = 1, max = 255))]
    pub r#type: Option<String>,
}

/// Parameters for listing credentials.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct CredentialListParameters {
    /// Filter by credential type.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub r#type: Option<String>,

    /// Filter by owning user.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub user_id: Option<String>,

    /// Pagination controls (limit/marker/page_reverse).
    #[builder(default)]
    pub pagination: crate::ListPagination,
}
