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
//! Mapping ruleset API types for the unified mapping engine.

use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "validate")]
use validator::Validate;

use crate::Link;
use crate::v3::role::RoleRef;

// ---------------------------------------------------------------------------
// Domain Resolution & Identity Source
// ---------------------------------------------------------------------------

/// Domain resolution mode for the mapping ruleset.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DomainResolutionMode {
    /// Domain is resolved exclusively from claims.
    ClaimsOnly {
        /// Allowed domain IDs that may be resolved from claims.
        allowed_domains: Vec<String>,
    },
    /// Domain is resolved from the mapping ruleset, falling back to claims.
    ClaimsOrMapping {
        /// Allowed domain IDs that may be resolved from claims.
        allowed_domains: Vec<String>,
    },
    /// Domain is fixed to the `domain_id` set on the ruleset.
    #[default]
    Fixed,
}

/// Identity source type identifying the ingress provider.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IdentitySource {
    /// Federation-based identity source.
    Federation {
        /// ID of the IdP that supplies the tokens.
        idp_id: String,
    },
    /// Kubernetes-based identity source.
    K8s {
        /// Kubernetes cluster identifier.
        cluster_id: String,
    },
    /// SPIFFE-based identity source.
    Spiffe {
        /// SPIFFE trust domain identifier.
        trust_domain: String,
    },
}

// ---------------------------------------------------------------------------
// Claim Matching
// ---------------------------------------------------------------------------

/// A single claim condition evaluated against the claims map.
///
/// Externally tagged to avoid duplicate `type` field when nested inside
/// `MatchCondition::Condition(ClaimCondition)`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ClaimCondition {
    /// Match if the claim value equals any of the given values.
    AnyOf {
        /// Acceptable claim values.
        values: Vec<serde_json::Value>,
    },
    /// Match if the claim value equals the given value.
    Equals {
        /// Expected claim value.
        value: serde_json::Value,
    },
    /// Match if the claim value matches the given regex pattern.
    MatchesRegex {
        /// Regex pattern to match against the claim value.
        regex: String,
    },
}

impl Default for ClaimCondition {
    fn default() -> Self {
        Self::Equals { value: Value::Null }
    }
}

#[cfg(feature = "validate")]
impl validator::Validate for ClaimCondition {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        Ok(())
    }
}

/// A single match condition that can be a leaf claim assertion or a nested
/// group.
///
/// Note: Does NOT derive `utoipa::ToSchema` to avoid infinite recursion with
/// `MatchCriteria`. The schema for fields using this type is provided via
/// `#[utoipa(value_type = serde_json::Value)]` at the usage site.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MatchCondition {
    /// Leaf claim assertion.
    Condition(ClaimCondition),
    /// Nested boolean criteria group.
    Nested(Box<MatchCriteria>),
}
#[allow(clippy::derivable_impls)]
impl Default for MatchCondition {
    fn default() -> Self {
        Self::Condition(ClaimCondition::default())
    }
}

#[cfg(feature = "validate")]
impl validator::Validate for MatchCondition {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        match self {
            Self::Condition(cc) => cc.validate(),
            Self::Nested(mc) => mc.validate(),
        }
    }
}

/// Boolean match criteria for claim evaluation.
///
/// External-tagged per ADR-0020 examples:
/// `{ "all_of": [...] }`, `{ "any_of": [...] }`,
/// `{ "all_of_strict": { "conditions": [...], "require_all_keys": bool } }`
///
/// Note: Does NOT derive `utoipa::ToSchema` to avoid infinite recursion with
/// `MatchCondition`. The `value_type = serde_json::Value` is used at the
/// usage site (`MappingRule::r#match`) for OpenAPI schema generation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchCriteria {
    /// All conditions must match.
    AllOf(Vec<MatchCondition>),
    /// All conditions must match, and no extra claim keys are allowed
    /// beyond those referenced by the conditions.
    AllOfStrict {
        /// Conditions that must all match.
        conditions: Vec<MatchCondition>,
        /// When `true`, reject tokens that contain claim keys not referenced
        /// by the conditions.
        require_all_keys: bool,
    },
    /// At least one condition must match.
    AnyOf(Vec<MatchCondition>),
}

impl Default for MatchCriteria {
    fn default() -> Self {
        Self::AllOf(Vec::new())
    }
}

#[cfg(feature = "validate")]
impl validator::Validate for MatchCriteria {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        match self {
            Self::AllOf(conds)
            | Self::AnyOf(conds)
            | Self::AllOfStrict {
                conditions: conds, ..
            } => {
                for cond in conds {
                    cond.validate()?;
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Identity, Authorization & Groups
// ---------------------------------------------------------------------------
/// Identity binding that defines how the external identity maps to a
/// localized Keystone identity.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct IdentityBinding {
    /// Whether the resolved identity has system-level privileges.
    #[serde(default)]
    pub is_system: bool,
    /// User domain ID for the resolved identity.
    #[cfg_attr(feature = "validate", validate(length(max = 256)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_domain_id: Option<String>,
    /// User ID for the resolved identity.
    #[cfg_attr(feature = "validate", validate(length(max = 256)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// User name for the resolved identity.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 256)))]
    pub user_name: String,
}

/// Authorization assignment within a mapping rule.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Authorization {
    /// Domain-level role assignment.
    Domain {
        /// Domain ID to assign the roles on.
        domain_id: String,
        /// Roles to assign.
        roles: Vec<RoleRef>,
    },
    /// Project-level role assignment.
    Project {
        /// Project domain ID.
        project_domain_id: String,
        /// Project ID to assign the roles on.
        project_id: String,
        /// Roles to assign.
        roles: Vec<RoleRef>,
    },
    /// System-level role assignment.
    System {
        /// Roles to assign.
        roles: Vec<RoleRef>,
        /// System ID (typically `all` for global system scope).
        system_id: String,
    },
}

/// Group resolution strategy.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GroupStrategy {
    /// Create the group if it does not exist, or retrieve the existing one.
    #[default]
    CreateOrGet,
    /// Retrieve the group; fail if it does not already exist.
    Get,
}

/// Group assignment within a mapping rule.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct GroupAssignment {
    /// Group domain ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_domain_id: Option<String>,
    /// Group identifier.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub group_id: String,
    /// Group name.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 256)))]
    pub group_name: String,
    /// Strategy for resolving the group. Defaults to `CreateOrGet`.
    #[serde(default = "default_create_or_get")]
    pub strategy: Option<GroupStrategy>,
}

fn default_create_or_get() -> Option<GroupStrategy> {
    Some(GroupStrategy::CreateOrGet)
}

// ---------------------------------------------------------------------------
// Mapping Rule

/// A single rule within a `MappingRuleSet`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct MappingRule {
    /// Role assignments granted when this rule matches.
    pub authorizations: Vec<Authorization>,
    /// Human-readable description of the rule purpose.
    #[cfg_attr(feature = "validate", validate(length(max = 512)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Group assignments granted when this rule matches.
    pub groups: Vec<GroupAssignment>,
    /// Identity binding that defines the localized Keystone identity.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub identity: IdentityBinding,
    /// Claim match criteria that determine when this rule applies.
    #[serde(rename = "match")]
    #[cfg_attr(feature = "openapi", schema(value_type = serde_json::Value))]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub r#match: MatchCriteria,
    /// Unique rule name within the ruleset.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 256)))]
    pub name: String,
}

// ---------------------------------------------------------------------------
// MappingRuleSet (stored object)
// ---------------------------------------------------------------------------

/// A complete mapping ruleset stored in the distributed store.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct MappingRuleSet {
    /// Owning domain boundary; `None` for global rulesets.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_id: Option<String>,
    /// Domain resolution mode.
    pub domain_resolution_mode: DomainResolutionMode,
    /// Whether the ruleset is enabled.
    pub enabled: bool,
    /// Unique ruleset identifier.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub mapping_id: String,
    /// Ordered rules; array position defines execution priority.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub rules: Vec<MappingRule>,
    /// Identifies the ingress provider instance.
    pub source: IdentitySource,
}

// ---------------------------------------------------------------------------
// MappingRuleSet Create/Update/List
// ---------------------------------------------------------------------------

/// Mapping ruleset creation request payload.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct MappingRuleSetCreate {
    /// Owning domain boundary; `None` for global rulesets.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_id: Option<String>,
    /// Domain resolution mode.
    pub domain_resolution_mode: DomainResolutionMode,
    /// Whether the ruleset is enabled.
    pub enabled: bool,
    /// Optional ruleset identifier (auto-generated if `None`).
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping_id: Option<String>,
    /// Ordered rules; array position defines execution priority.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub rules: Vec<MappingRule>,
    /// Identifies the ingress provider instance.
    pub source: IdentitySource,
}

/// Mapping ruleset creation request wrapper.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct MappingRuleSetCreateRequest {
    /// Mapping ruleset creation payload.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub mapping: MappingRuleSetCreate,
}

/// Mapping ruleset update request payload.
///
/// Only mutable fields are included. `domain_id`, `source`, and
/// `domain_resolution_mode` are immutable after creation.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct MappingRuleSetUpdate {
    /// Replace `allowed_domains` within the existing `DomainResolutionMode`
    /// variant. The mode variant itself cannot change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,
    /// Toggle ruleset enabled/disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Replace the entire rules vector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<MappingRule>>,
}

/// Mapping ruleset update request wrapper.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct MappingRuleSetUpdateRequest {
    /// Mapping ruleset update payload.
    pub mapping: MappingRuleSetUpdate,
}

/// Mapping ruleset response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct MappingRuleSetResponse {
    /// Mapping ruleset object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub mapping: MappingRuleSet,
}

/// Mapping ruleset list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MappingRuleSetList {
    /// Pagination links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
    /// Collection of mapping rulesets.
    pub mappings: Vec<MappingRuleSet>,
}

/// Mapping ruleset list query parameters.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct MappingRuleSetListParameters {
    /// Filter by domain ID.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_id: Option<String>,
    /// Filter by enabled/disabled state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Limit number of entries per page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Page marker (ID of the last entry on the previous page).
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
}

// ---------------------------------------------------------------------------
// Rule Mutation
// ---------------------------------------------------------------------------

/// Rule mutation for imperative operations.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum RuleMutation {
    /// Delete a rule by name.
    Delete {
        /// Name of the rule to delete.
        rule_name: String,
    },
    /// Insert a new rule into the ruleset.
    Insert {
        /// Optional position hint for the inserted rule.
        #[serde(skip_serializing_if = "Option::is_none")]
        position: Option<RulePosition>,
        /// Rule to insert.
        rule: MappingRule,
    },
    /// Update an existing rule by name.
    Update {
        /// Name of the existing rule to update.
        rule_name: String,
        /// Updated rule definition.
        rule: MappingRule,
    },
}

/// Rule position for insert operations.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RulePosition {
    /// Insert after the rule with the given name.
    After {
        /// Name of the existing rule to anchor to.
        anchor: String,
    },
    /// Insert before the rule with the given name.
    Before {
        /// Name of the existing rule to anchor to.
        anchor: String,
    },
}

/// Rule mutations request wrapper.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RuleMutationsRequest {
    /// List of mutations to apply.
    pub mutations: Vec<RuleMutation>,
}
