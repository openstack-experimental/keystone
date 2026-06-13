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
//! Virtual user metadata and match result types.

use serde::{Deserialize, Serialize};

use super::authorization::Authorization;

use crate::identity::GroupRef;

/// Virtual user list query parameters.
#[derive(Debug, Clone, Default)]
pub struct VirtualUserListParameters {
    /// Filter by the originating mapping ruleset ID.
    pub mapping_id: Option<String>,

    /// Filter by enabled/disabled state.
    pub enabled: Option<bool>,

    /// Filter by domain ID.
    pub domain_id: Option<String>,

    /// Limit number of entries per page.
    pub limit: Option<u64>,

    /// Page marker (ID of the last entry on the previous page).
    pub marker: Option<String>,
}

/// Shadow virtual user registry record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualUser {
    /// HMAC-SHA256-derived deterministic user ID.
    pub user_id: String,

    /// Unique workload identifier from the claims map.
    pub unique_workload_id: String,

    /// Direct anchor to the `MappingRuleSet` that matched.
    pub mapping_id: String,

    /// Name of the matched rule.
    pub matched_rule_name: String,

    /// Effective domain ID.
    pub domain_id: Option<String>,

    /// Resolved username.
    pub resolved_user_name: String,

    /// System-service flag; immutably preserved from initial creation.
    pub is_system: bool,

    /// Resolved group bindings.
    pub resolved_group_bindings: Vec<GroupRef>,

    /// Snapshot of authorizations at issuance time.
    pub authorizations: Vec<Authorization>,

    /// SHA-256 hash captured at issuance.
    pub ruleset_version: u128,

    /// Whether the virtual user is enabled.
    pub enabled: bool,

    /// UNIX timestamp of record creation.
    pub created_at: i64,

    /// UNIX timestamp of last successful authentication.
    pub last_authenticated_at: i64,
}

/// Output of a successful ruleset match evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    /// Name of the matched rule.
    pub rule_name: String,

    /// Interpolated username.
    pub user_name: String,

    /// Optional interpolated user ID.
    pub user_id: Option<String>,

    /// Resolved domain ID.
    pub user_domain_id: Option<String>,

    /// System-service flag.
    pub is_system: bool,

    /// Snapshot of authorizations.
    pub authorizations: Vec<Authorization>,

    /// Resolved group bindings.
    pub resolved_group_bindings: Vec<GroupRef>,

    /// Content-aware ruleset version.
    pub ruleset_version: u128,
}
