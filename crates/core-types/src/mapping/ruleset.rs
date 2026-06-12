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
//! Mapping ruleset types: ruleset, create, update, and list parameters.

use serde::{Deserialize, Serialize};
use validator::Validate;

use super::resolution::{DomainResolutionMode, IdentitySource};
use super::rule::MappingRule;

/// A complete mapping ruleset stored in the distributed store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Validate)]
pub struct MappingRuleSet {
    /// Unique ruleset identifier.
    #[validate(length(min = 1, max = 64))]
    pub mapping_id: String,

    /// Owning domain boundary. `None` for `ClaimsOnly`/`ClaimsOrMapping` modes.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: Option<String>,

    /// Identifies the ingress provider instance.
    pub source: IdentitySource,

    /// Domain resolution mode.
    pub domain_resolution_mode: DomainResolutionMode,

    /// Whether the ruleset is enabled.
    pub enabled: bool,

    /// Ordered rules; array position defines execution priority.
    #[validate(length(min = 1, max = 64))]
    pub rules: Vec<MappingRule>,

    /// Content-aware SHA-256 hash (first 16 bytes) of the full ruleset.
    pub ruleset_version: u128,
}

/// Mapping ruleset creation request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Validate)]
pub struct MappingRuleSetCreate {
    /// Optional ruleset identifier (auto-generated if `None`).
    #[validate(length(min = 1, max = 64))]
    pub mapping_id: Option<String>,

    /// Owning domain boundary. `None` for `ClaimsOnly`/`ClaimsOrMapping` modes.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: Option<String>,

    /// Identifies the ingress provider instance.
    pub source: IdentitySource,

    /// Domain resolution mode.
    pub domain_resolution_mode: DomainResolutionMode,

    /// Whether the ruleset is enabled.
    pub enabled: bool,

    /// Ordered rules; array position defines execution priority.
    #[validate(length(min = 1, max = 64))]
    pub rules: Vec<MappingRule>,
}

/// Mapping ruleset update request.
///
/// Only mutable fields are included. `domain_id`, `source`, and
/// `domain_resolution_mode` are immutable after creation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MappingRuleSetUpdate {
    /// Toggle ruleset enabled/disabled.
    pub enabled: Option<bool>,

    /// Replace `allowed_domains` within the existing `DomainResolutionMode`
    /// variant. The mode variant itself
    /// (`Fixed`/`ClaimsOrMapping`/`ClaimsOnly`) cannot change.
    pub allowed_domains: Option<Vec<String>>,

    /// Replace the entire rules vector.
    pub rules: Option<Vec<MappingRule>>,
}

/// Mapping ruleset list query parameters.
#[derive(Debug, Clone, Default)]
pub struct MappingRuleSetListParameters {
    /// Filter by domain ID.
    pub domain_id: Option<String>,

    /// Filter by enabled/disabled state.
    pub enabled: Option<bool>,

    /// Limit number of entries per page.
    pub limit: Option<u64>,

    /// Page marker (ID of the last entry on the previous page).
    pub marker: Option<String>,
}
