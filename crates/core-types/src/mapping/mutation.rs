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
//! Imperative rule mutation types.

use serde::{Deserialize, Serialize};

use super::rule::MappingRule;

/// Request payload for imperative rule mutations.
///
/// Carried as the request body for `POST
/// /v4/mappings/{mapping_id}/rules/mutate`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleMutations {
    /// Ordered mutations; executed sequentially within a single atomic
    /// transaction.
    pub mutations: Vec<RuleMutation>,
}

/// A single rule mutation operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum RuleMutation {
    /// Insert a new rule at the specified position.
    Insert {
        /// Rule to insert.
        rule: MappingRule,
        /// Optional anchor: position relative to an existing rule.
        #[serde(skip_serializing_if = "Option::is_none")]
        position: Option<RulePosition>,
    },
    /// Update an existing rule by name.
    Update {
        /// Target rule name.
        rule_name: String,
        /// New rule definition.
        rule: MappingRule,
    },
    /// Delete an existing rule by name.
    Delete {
        /// Target rule name.
        rule_name: String,
    },
}

/// Positioning anchor for rule insertion.
///
/// Allows relative positioning of a new rule with respect to an existing rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RulePosition {
    /// Insert before the rule with the given name.
    Before {
        /// Name of the existing rule to anchor to.
        anchor: String,
    },
    /// Insert after the rule with the given name.
    After {
        /// Name of the existing rule to anchor to.
        anchor: String,
    },
}
