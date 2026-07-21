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

use serde::{Deserialize, Serialize};
/// Short access rule representation.
///
/// Access rules are fine-grained permissions attached to application
/// credentials. Each rule constrains the credential to a specific service
/// type, HTTP method, and API path. Once created, an access rule can be
/// viewed and deleted independently of the application credential.
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
pub struct AccessRule {
    /// Unique identifier of the access rule. This ID can be used to reuse an
    /// existing access rule when creating a new application credential.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,

    /// HTTP method that this access rule permits (e.g., `GET`, `POST`, `PUT`,
    /// `DELETE`, `PATCH`).
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 16)))]
    pub method: Option<String>,

    /// API path pattern that this access rule permits. Supports wildcard
    /// syntax: `*` matches a single path segment, `**` matches any number
    /// of segments recursively, and `{variable}` matches a named path
    /// parameter. For example, `/v2.1/servers/*/ips` or `/v2.1/**`.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 128)))]
    pub path: Option<String>,

    /// OpenStack service type that this access rule applies to
    /// (e.g., `compute`, `monitoring`, `identity`). Matched against the
    /// service catalog.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub service: Option<String>,
}

/// Access rule for creation (id is optional).
///
/// When creating an application credential, access rules can either be
/// defined inline (with `method`, `path`, and `service`) or reference an
/// existing rule by its `id`. All fields are optional so that both creation
/// patterns are supported.
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
pub struct AccessRuleCreate {
    /// Optional identifier of an existing access rule to reuse. When
    /// provided, the other fields (`method`, `path`, `service`) are ignored
    /// and the referenced rule is attached to the new application credential.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: Option<String>,

    /// HTTP method that this access rule permits (e.g., `GET`, `POST`, `PUT`,
    /// `DELETE`, `PATCH`). Required when creating a new rule inline (i.e.,
    /// without specifying `id`).
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 16)))]
    pub method: Option<String>,

    /// API path pattern that this access rule permits. Supports wildcard
    /// syntax: `*` matches a single path segment, `**` matches any number
    /// of segments recursively, and `{variable}` matches a named path
    /// parameter. Required when creating a new rule inline.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 128)))]
    pub path: Option<String>,

    /// OpenStack service type that this access rule applies to
    /// (e.g., `compute`, `monitoring`, `identity`). Matched against the
    /// service catalog. Required when creating a new rule inline.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub service: Option<String>,
}
