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

//! # OpenStack Keystone API types
//!
//! This crates defines reusable types that OpenStack Keystone is using for
//! the REST API.

use serde::{Deserialize, Serialize};

pub mod catalog;
#[cfg(feature = "conv")]
mod catalog_conv;
mod common;
pub mod error;
#[cfg(feature = "conv")]
mod error_conv;
pub mod federation;
pub mod k8s_auth;
pub mod scope;
#[cfg(feature = "conv")]
mod scope_conv;
pub mod trust;
pub mod v3;
pub mod v4;
pub mod version;
pub mod webauthn;

/// Link object.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Link {
    /// Link rel attribute.
    #[cfg_attr(feature = "validate", validate(length(max = 10)))]
    pub rel: String,
    /// link href attribute.
    #[cfg_attr(feature = "validate", validate(url))]
    pub href: String,
}

impl Link {
    pub fn new(href: String) -> Self {
        Self {
            rel: "self".into(),
            href,
        }
    }
}

/// Return `true` to be used as a positive default for the serde macros.
pub fn default_true() -> bool {
    true
}

/// Deserialize an `Option<bool>` query parameter leniently.
///
/// OpenStack's python keystone (via `oslo.utils.strutils.bool_from_string`)
/// accepts `1`/`0`, `yes`/`no`, `on`/`off`, and `true`/`false` (any case) for
/// boolean query params like `nocatalog`/`allow_expired`. Plain
/// `Option<bool>` only accepts `true`/`false` and 400s on anything else
/// (e.g. `allow_expired=1`), which is what real clients send. Use as
/// `#[serde(default, deserialize_with = "deserialize_lenient_bool_opt")]`
/// on `Option<bool>` query fields.
pub fn deserialize_lenient_bool_opt<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        other => Err(serde::de::Error::custom(format!(
            "invalid boolean value: `{other}`"
        ))),
    }
}

/// Default `limit` when the client does not supply one: **`None`**.
///
/// Deliberately not a hard-coded page size. ADR 0029's precedence chain is
/// "user limit -> per-resource `list_limit` -> global `[DEFAULT] list_limit`
/// -> `max_db_limit`", and `Config::resolve_list_limit` only consults the
/// configured values when the request carries no limit. Returning `Some(20)`
/// here made `requested` always populated, which silently rendered every
/// `list_limit` setting dead config. `None` also matches python keystone,
/// whose `[DEFAULT] list_limit` is unset (no truncation) out of the box.
pub fn default_list_limit() -> Option<u64> {
    None
}

/// Shared pagination query parameters, reused by every v3/v4 list endpoint.
///
/// Handlers take this as a *second*, independent `Query<PaginationQuery>`
/// extractor alongside each resource's own filter-only params type — axum
/// re-parses the full query string per extractor and ignores fields it
/// doesn't declare, so this composes cleanly without `#[serde(flatten)]`
/// (which breaks typed-field deserialization over `serde_urlencoded`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct PaginationQuery {
    /// Limit number of entries on the single response page.
    #[serde(default = "default_list_limit")]
    pub limit: Option<u64>,
    /// Page marker (id of the last entry of the previous page).
    pub marker: Option<String>,
    /// Fetch the page preceding `marker` instead of the page following it.
    ///
    /// v3 endpoints accept this field (unknown-to-python-keystone query
    /// params are harmless) but never read or forward it; only v4 endpoints
    /// wire it through.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub page_reverse: bool,
}
