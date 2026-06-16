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
//! Mapping ruleset conversion implementations.

use openstack_keystone_core_types::mapping as core;
use openstack_keystone_core_types::role as core_role;

use crate::v3::role as api_role;
use crate::v4::mapping::ruleset as api;

impl From<api::DomainResolutionMode> for core::DomainResolutionMode {
    fn from(value: api::DomainResolutionMode) -> Self {
        match value {
            api::DomainResolutionMode::Fixed => Self::Fixed,
            api::DomainResolutionMode::ClaimsOrMapping { allowed_domains } => {
                Self::ClaimsOrMapping { allowed_domains }
            }
            api::DomainResolutionMode::ClaimsOnly { allowed_domains } => {
                Self::ClaimsOnly { allowed_domains }
            }
        }
    }
}

impl From<core::DomainResolutionMode> for api::DomainResolutionMode {
    fn from(value: core::DomainResolutionMode) -> Self {
        match value {
            core::DomainResolutionMode::Fixed => Self::Fixed,
            core::DomainResolutionMode::ClaimsOrMapping { allowed_domains } => {
                Self::ClaimsOrMapping { allowed_domains }
            }
            core::DomainResolutionMode::ClaimsOnly { allowed_domains } => {
                Self::ClaimsOnly { allowed_domains }
            }
        }
    }
}

impl From<api::IdentitySource> for core::IdentitySource {
    fn from(value: api::IdentitySource) -> Self {
        match value {
            api::IdentitySource::Federation { idp_id } => Self::Federation { idp_id },
            api::IdentitySource::K8s { cluster_id } => Self::K8s { cluster_id },
            api::IdentitySource::Spiffe { trust_domain } => Self::Spiffe { trust_domain },
        }
    }
}

impl From<core::IdentitySource> for api::IdentitySource {
    fn from(value: core::IdentitySource) -> Self {
        match value {
            core::IdentitySource::Federation { idp_id } => Self::Federation { idp_id },
            core::IdentitySource::K8s { cluster_id } => Self::K8s { cluster_id },
            core::IdentitySource::Spiffe { trust_domain } => Self::Spiffe { trust_domain },
        }
    }
}

impl From<api::ClaimCondition> for core::ClaimCondition {
    fn from(value: api::ClaimCondition) -> Self {
        match value {
            api::ClaimCondition::Equals { claim, value } => Self::Equals { claim, value },
            api::ClaimCondition::AnyOf { claim, values } => Self::AnyOf { claim, values },
            api::ClaimCondition::MatchesRegex { claim, regex } => {
                Self::MatchesRegex { claim, regex }
            }
        }
    }
}

impl From<core::ClaimCondition> for api::ClaimCondition {
    fn from(value: core::ClaimCondition) -> Self {
        match value {
            core::ClaimCondition::Equals { claim, value, .. } => Self::Equals { claim, value },
            core::ClaimCondition::AnyOf { claim, values, .. } => Self::AnyOf { claim, values },
            core::ClaimCondition::MatchesRegex { claim, regex, .. } => {
                Self::MatchesRegex { claim, regex }
            }
        }
    }
}

impl From<api::MatchCondition> for core::MatchCondition {
    fn from(value: api::MatchCondition) -> Self {
        match value {
            api::MatchCondition::Condition(cc) => Self::Condition(cc.into()),
            api::MatchCondition::Nested(mc) => Self::Nested(Box::new((*mc).into())),
        }
    }
}

impl From<core::MatchCondition> for api::MatchCondition {
    fn from(value: core::MatchCondition) -> Self {
        match value {
            core::MatchCondition::Condition(cc) => Self::Condition(cc.into()),
            core::MatchCondition::Nested(mc) => Self::Nested(Box::new((*mc).into())),
        }
    }
}

impl From<api::MatchCriteria> for core::MatchCriteria {
    fn from(value: api::MatchCriteria) -> Self {
        match value {
            api::MatchCriteria::AllOf(conds) => {
                Self::AllOf(conds.into_iter().map(Into::into).collect())
            }
            api::MatchCriteria::AnyOf(conds) => {
                Self::AnyOf(conds.into_iter().map(Into::into).collect())
            }
            api::MatchCriteria::AllOfStrict {
                conditions,
                require_all_keys,
            } => Self::AllOfStrict {
                conditions: conditions.into_iter().map(Into::into).collect(),
                require_all_keys,
            },
        }
    }
}

impl From<core::MatchCriteria> for api::MatchCriteria {
    fn from(value: core::MatchCriteria) -> Self {
        match value {
            core::MatchCriteria::AllOf(conds) => {
                Self::AllOf(conds.into_iter().map(Into::into).collect())
            }
            core::MatchCriteria::AnyOf(conds) => {
                Self::AnyOf(conds.into_iter().map(Into::into).collect())
            }
            core::MatchCriteria::AllOfStrict {
                conditions,
                require_all_keys,
            } => Self::AllOfStrict {
                conditions: conditions.into_iter().map(Into::into).collect(),
                require_all_keys,
            },
        }
    }
}

impl From<api::IdentityBinding> for core::IdentityBinding {
    fn from(value: api::IdentityBinding) -> Self {
        Self {
            user_name: value.user_name,
            user_id: value.user_id,
            user_domain_id: value.user_domain_id,
            is_system: value.is_system,
        }
    }
}

impl From<core::IdentityBinding> for api::IdentityBinding {
    fn from(value: core::IdentityBinding) -> Self {
        Self {
            user_name: value.user_name,
            user_id: value.user_id,
            user_domain_id: value.user_domain_id,
            is_system: value.is_system,
        }
    }
}

// ---------------------------------------------------------------------------
// Authorization (RoleRef conversion)
// ---------------------------------------------------------------------------

impl From<api_role::RoleRef> for core_role::RoleRef {
    fn from(value: api_role::RoleRef) -> Self {
        Self {
            domain_id: value.domain_id,
            id: value.id,
            name: Some(value.name),
        }
    }
}

impl From<api::Authorization> for core::Authorization {
    fn from(value: api::Authorization) -> Self {
        match value {
            api::Authorization::Project {
                project_id,
                project_domain_id,
                roles,
            } => Self::Project {
                project_id,
                project_domain_id,
                roles: roles.into_iter().map(core_role::RoleRef::from).collect(),
            },
            api::Authorization::Domain { domain_id, roles } => Self::Domain {
                domain_id,
                roles: roles.into_iter().map(core_role::RoleRef::from).collect(),
            },
            api::Authorization::System { system_id, roles } => Self::System {
                system_id,
                roles: roles.into_iter().map(core_role::RoleRef::from).collect(),
            },
        }
    }
}

impl From<core::Authorization> for api::Authorization {
    fn from(value: core::Authorization) -> Self {
        match value {
            core::Authorization::Project {
                project_id,
                project_domain_id,
                roles,
            } => Self::Project {
                project_id,
                project_domain_id,
                roles: roles.into_iter().map(api_role::RoleRef::from).collect(),
            },
            core::Authorization::Domain { domain_id, roles } => Self::Domain {
                domain_id,
                roles: roles.into_iter().map(api_role::RoleRef::from).collect(),
            },
            core::Authorization::System { system_id, roles } => Self::System {
                system_id,
                roles: roles.into_iter().map(api_role::RoleRef::from).collect(),
            },
        }
    }
}

impl From<api::GroupStrategy> for core::GroupStrategy {
    fn from(value: api::GroupStrategy) -> Self {
        match value {
            api::GroupStrategy::CreateOrGet => Self::CreateOrGet,
            api::GroupStrategy::Get => Self::Get,
        }
    }
}

impl From<core::GroupStrategy> for api::GroupStrategy {
    fn from(value: core::GroupStrategy) -> Self {
        match value {
            core::GroupStrategy::CreateOrGet => Self::CreateOrGet,
            core::GroupStrategy::Get => Self::Get,
        }
    }
}

impl From<api::GroupAssignment> for core::GroupAssignment {
    fn from(value: api::GroupAssignment) -> Self {
        Self {
            group_id: value.group_id,
            group_name: value.group_name,
            group_domain_id: value.group_domain_id,
            strategy: value.strategy.map(Into::into),
        }
    }
}

impl From<core::GroupAssignment> for api::GroupAssignment {
    fn from(value: core::GroupAssignment) -> Self {
        Self {
            group_id: value.group_id,
            group_name: value.group_name,
            group_domain_id: value.group_domain_id,
            strategy: value.strategy.map(Into::into),
        }
    }
}

impl From<api::MappingRule> for core::MappingRule {
    fn from(value: api::MappingRule) -> Self {
        Self {
            name: value.name,
            description: value.description,
            r#match: value.r#match.into(),
            identity: value.identity.into(),
            authorizations: value.authorizations.into_iter().map(Into::into).collect(),
            groups: value.groups.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<core::MappingRule> for api::MappingRule {
    fn from(value: core::MappingRule) -> Self {
        Self {
            name: value.name,
            description: value.description,
            r#match: value.r#match.into(),
            identity: value.identity.into(),
            authorizations: value.authorizations.into_iter().map(Into::into).collect(),
            groups: value.groups.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<api::MappingRuleSetCreateRequest> for core::MappingRuleSetCreate {
    fn from(value: api::MappingRuleSetCreateRequest) -> Self {
        Self {
            mapping_id: value.mapping.mapping_id,
            domain_id: value.mapping.domain_id,
            source: value.mapping.source.into(),
            domain_resolution_mode: value.mapping.domain_resolution_mode.into(),
            enabled: value.mapping.enabled,
            rules: value.mapping.rules.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<core::MappingRuleSet> for api::MappingRuleSet {
    fn from(value: core::MappingRuleSet) -> Self {
        Self {
            mapping_id: value.mapping_id,
            domain_id: value.domain_id,
            source: value.source.into(),
            domain_resolution_mode: value.domain_resolution_mode.into(),
            enabled: value.enabled,
            rules: value.rules.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<api::MappingRuleSetUpdate> for core::MappingRuleSetUpdate {
    fn from(value: api::MappingRuleSetUpdate) -> Self {
        Self {
            enabled: value.enabled,
            allowed_domains: value.allowed_domains,
            rules: value.rules.map(|r| r.into_iter().map(Into::into).collect()),
        }
    }
}

impl From<api::MappingRuleSetListParameters> for core::MappingRuleSetListParameters {
    fn from(value: api::MappingRuleSetListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            enabled: value.enabled,
            limit: value.limit,
            marker: value.marker,
        }
    }
}

impl From<api::RulePosition> for core::RulePosition {
    fn from(value: api::RulePosition) -> Self {
        match value {
            api::RulePosition::Before { anchor } => Self::Before { anchor },
            api::RulePosition::After { anchor } => Self::After { anchor },
        }
    }
}

impl From<api::RuleMutation> for core::RuleMutation {
    fn from(value: api::RuleMutation) -> Self {
        match value {
            api::RuleMutation::Insert { rule, position } => Self::Insert {
                rule: rule.into(),
                position: position.map(Into::into),
            },
            api::RuleMutation::Update { rule_name, rule } => Self::Update {
                rule_name,
                rule: rule.into(),
            },
            api::RuleMutation::Delete { rule_name } => Self::Delete { rule_name },
        }
    }
}

impl From<api::RuleMutationsRequest> for core::RuleMutations {
    fn from(value: api::RuleMutationsRequest) -> Self {
        Self {
            mutations: value.mutations.into_iter().map(Into::into).collect(),
        }
    }
}
