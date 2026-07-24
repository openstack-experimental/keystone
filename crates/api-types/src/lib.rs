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

/// Default page size applied when the client does not supply `limit`.
pub fn default_list_limit() -> Option<u64> {
    Some(20)
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
