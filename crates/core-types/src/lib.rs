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

//! # OpenStack Keystone core provider types

#![allow(clippy::module_inception)]
#![deny(clippy::unwrap_used)]

use serde::{Deserialize, Serialize};

pub mod api_key;
pub mod application_credential;
pub mod assignment;
pub mod auth;
pub mod auth_plugin_identity;
pub mod catalog;
pub mod credential;
pub mod error;
pub mod events;
pub mod federation;
pub mod identity;
pub mod idmapping;
pub mod k8s_auth;
pub mod mapping;
pub mod oauth2_client;
pub mod oauth2_key;
pub mod oauth2_session;
pub mod resource;
pub mod revoke;
pub mod role;
pub mod scim;
pub mod scope;
pub mod token;
pub mod trust;

/// Return `true` to be used as a positive default for the serde macros.
pub fn default_true() -> bool {
    true
}

/// Shared pagination modifiers for `*ListParameters` structs.
///
/// Embedded as a named field (`pub pagination: ListPagination`) rather than
/// duplicated per-domain, so every domain's list-parameters struct gets the
/// same shape and can implement `HasPagination` with a one-line accessor.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct ListPagination {
    /// Limit number of entries on the single response page.
    pub limit: Option<u64>,
    /// Page marker (id of the last entry of the previous page).
    pub marker: Option<String>,
    /// Fetch the page preceding `marker` instead of the page following it.
    ///
    /// Only meaningful for v4 endpoints; v3 handlers never read or forward
    /// this field, keeping v3 forward-only and python-keystone compatible.
    pub page_reverse: bool,
}
