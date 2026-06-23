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
//! Authorization and group assignment types.

use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::role::RoleRef;

/// Authorization assignment within a mapping rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Authorization {
    /// Project-scoped authorization.
    Project {
        /// Project UUID.
        project_id: String,
        /// Domain UUID the project belongs to.
        project_domain_id: String,
        /// Roles to assign.
        roles: Vec<RoleRef>,
    },
    /// Domain-scoped authorization.
    Domain {
        /// Domain UUID.
        domain_id: String,
        /// Roles to assign.
        roles: Vec<RoleRef>,
    },
    /// System-scoped authorization (requires `is_system: true`).
    System {
        /// System scope identifier (e.g., `"all"`).
        system_id: String,
        /// Roles to assign.
        roles: Vec<RoleRef>,
    },
}

/// Group assignment within a mapping rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Validate)]
pub struct GroupAssignment {
    /// Optional group UUID. When absent, the group is resolved by name at
    /// runtime (used for `Local` identity mode where groups are created on the
    /// fly).
    #[serde(default)]
    #[validate(length(min = 1, max = 64))]
    pub group_id: Option<String>,

    /// Optional domain ID for the group.
    #[validate(length(min = 1, max = 64))]
    pub group_domain_id: Option<String>,

    /// Interpolated group name for display/lookup.
    #[validate(length(min = 1, max = 255))]
    pub group_name: String,

    /// Group resolution strategy.
    #[serde(default = "default_create_or_get")]
    pub strategy: Option<GroupStrategy>,
}

fn default_create_or_get() -> Option<GroupStrategy> {
    Some(GroupStrategy::CreateOrGet)
}

/// Group resolution strategy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupStrategy {
    /// Create the group if it does not exist, or fetch it.
    CreateOrGet,
    /// Only fetch an existing group; fail if missing.
    Get,
}
