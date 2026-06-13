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
//! # Mapping engine types
//!
//! Domain types for the unified mapping engine (ADR-0020).

pub mod auth;
pub mod authorization;
pub mod error;
pub mod mutation;
pub mod resolution;
pub mod rule;
pub mod ruleset;
pub mod virtual_user;

// Re-export auth types
pub use auth::{MappingAuthRequest, MappingContext};

// Re-export resolution types
pub use resolution::{DomainResolutionMode, IdentitySource};

// Re-export ruleset types
pub use ruleset::{
    MappingRuleSet, MappingRuleSetCreate, MappingRuleSetListParameters, MappingRuleSetUpdate,
};

// Re-export rule types
pub use rule::{ClaimCondition, IdentityBinding, MappingRule, MatchCondition, MatchCriteria};

// Re-export authorization types
pub use authorization::{Authorization, GroupAssignment, GroupStrategy};

// Re-export mutation types
pub use mutation::{RuleMutation, RuleMutations, RulePosition};

// Re-export virtual user types
pub use virtual_user::{MatchResult, VirtualUser, VirtualUserListParameters};

// Re-export error types
pub use error::MappingProviderError;
