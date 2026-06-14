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
//! Mapping rule types: rule definition, match criteria, and identity binding.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use validator::Validate;

/// A single rule within a `MappingRuleSet`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Validate)]
pub struct MappingRule {
    /// Immutable rule name handle (alphanumeric identifier).
    #[validate(length(min = 1, max = 255))]
    pub name: String,

    /// Human-readable description.
    pub description: Option<String>,

    /// Claim matching criteria.
    pub r#match: MatchCriteria,

    /// Identity mapping configuration.
    pub identity: IdentityBinding,

    /// Authorization assignments.
    pub authorizations: Vec<super::authorization::Authorization>,

    /// Group assignments.
    pub groups: Vec<super::authorization::GroupAssignment>,
}

/// Boolean match criteria for claim evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchCriteria {
    /// All conditions must match.
    AllOf(Vec<MatchCondition>),

    /// At least one condition must match.
    AnyOf(Vec<MatchCondition>),

    /// All conditions must match; when `require_all_keys` is `true`,
    /// evaluation fails if any referenced claim key is absent.
    AllOfStrict {
        conditions: Vec<MatchCondition>,
        require_all_keys: bool,
    },
}

/// A single match condition that can be a leaf claim assertion or a nested
/// group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MatchCondition {
    /// A leaf claim condition.
    Condition(ClaimCondition),

    /// A nested boolean criteria group.
    Nested(Box<MatchCriteria>),
}

/// A leaf-level claim assertion evaluated against the claims map.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClaimCondition {
    /// At least one claim value must match the target after JSON-to-string
    /// normalization.
    Equals { claim: String, value: Value },
    /// At least one claim value must match at least one target value.
    AnyOf { claim: String, values: Vec<Value> },
    /// At least one claim value must match the precompiled regex pattern.
    MatchesRegex { claim: String, regex: String },
}

impl ClaimCondition {
    /// Extract the claim key referenced by this condition.
    ///
    /// # Returns
    /// Reference to the claim name string.
    pub fn claim_name(&self) -> &str {
        match self {
            Self::Equals { claim, .. } => claim,
            Self::AnyOf { claim, .. } => claim,
            Self::MatchesRegex { claim, .. } => claim,
        }
    }

    /// Check if this condition uses a regex pattern.
    ///
    /// # Returns
    /// `true` if this is a `MatchesRegex` variant.
    pub fn is_regex(&self) -> bool {
        matches!(self, Self::MatchesRegex { .. })
    }

    /// Extract the regex pattern if this is a `MatchesRegex` condition.
    ///
    /// # Returns
    /// `Some(pattern)` for `MatchesRegex`, `None` otherwise.
    pub fn regex_pattern(&self) -> Option<&str> {
        match self {
            Self::MatchesRegex { regex, .. } => Some(regex),
            _ => None,
        }
    }
}

/// Identity binding configuration for a matched rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityBinding {
    /// Interpolated username for the principal.
    pub user_name: String,

    /// Optional interpolated user ID.
    pub user_id: Option<String>,

    /// Optional interpolated domain ID; resolved per `DomainResolutionMode`.
    pub user_domain_id: Option<String>,

    /// Control-plane bypass flag; defaults to `false`.
    #[serde(default = "default_false")]
    pub is_system: bool,
}

fn default_false() -> bool {
    false
}

// ---------------------------------------------------------------------------
// Walker helpers
// ---------------------------------------------------------------------------

impl MatchCriteria {
    /// Recursively collect all leaf `ClaimCondition` references within this
    /// criteria tree, including nested groups.
    ///
    /// Used during write-time validation to scan every regex pattern and
    /// verify template safety before persistence.
    ///
    /// # Returns
    /// A vector of references to every `ClaimCondition` in the tree.
    pub fn walk_all_claim_conditions(&self) -> Vec<&ClaimCondition> {
        let mut result = Vec::new();
        self.walk_into(&mut result);
        result
    }

    fn walk_into<'a>(&'a self, out: &mut Vec<&'a ClaimCondition>) {
        match self {
            MatchCriteria::AllOf(conditions)
            | MatchCriteria::AnyOf(conditions)
            | MatchCriteria::AllOfStrict { conditions, .. } => {
                for cond in conditions {
                    cond.walk_into(out);
                }
            }
        }
    }
}

impl MatchCondition {
    fn walk_into<'a>(&'a self, out: &mut Vec<&'a ClaimCondition>) {
        match self {
            MatchCondition::Condition(cc) => out.push(cc),
            MatchCondition::Nested(criteria) => criteria.walk_into(out),
        }
    }
}
