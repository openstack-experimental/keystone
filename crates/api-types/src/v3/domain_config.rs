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
//! # Domain configuration API types.
//!
//! Every domain-configuration endpoint nests its payload under a single
//! `config` key. The value is an object of groups (`identity`, `ldap`), each an
//! object of option name to value:
//!
//! ```json
//! {"config": {"identity": {"driver": "ldap"},
//!             "ldap": {"url": "ldap://localhost", "user_tree_dn": "ou=Users,dc=example,dc=org"}}}
//! ```
//!
//! Group- and option-scoped requests and responses use the same envelope with
//! only the addressed group (or option) present. Sensitive options
//! (`ldap.password`) may be written but are never echoed back in a response.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `PUT` / `PATCH` body for the domain-configuration endpoints.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DomainConfigRequest {
    /// The configuration, an object of groups each mapping option name to
    /// value. For a group- or option-scoped request only the addressed group
    /// is present.
    pub config: Value,
}

/// Response body for the domain-configuration endpoints, including the
/// defaults endpoints.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DomainConfigResponse {
    /// The configuration, an object of groups each mapping option name to
    /// value. Sensitive options are omitted.
    pub config: Value,
}
