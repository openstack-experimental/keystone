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
//! Claim evaluation engine for the unified mapping ruleset.
//!
//! Evaluates a flattened claims map against a `MappingRuleSet`, iterating rules
//! in priority order (first-match-wins). Per ADR-0020 §5.1-§5.3.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use openstack_keystone_core_types::identity::GroupRef;
use openstack_keystone_core_types::mapping::*;

use crate::mapping::error::MappingProviderError;
use crate::mapping::interpolation;

/// Cached regex patterns with LRU eviction to prevent adversarial cache
/// partition.
///
/// The map enforces a 1024-entry cap; once exceeded, the 100
/// least-recently-used entries are evicted per ADR-0020 §5.1.
static REGEX_CACHE: OnceLock<DashMap<String, Regex>> = OnceLock::new();
const REGEX_CACHE_CAP: usize = 1024;
const REGEX_CACHE_EVICT: usize = 100;

use dashmap::DashMap;

/// Evaluate a ruleset against a claims map, returning the first matching rule.
///
/// Iterates `ruleset.rules` top-to-bottom. For each rule:
/// 1. Evaluate `rule.r#match` against the claims map via [`evaluate_match`].
/// 2. On first match, interpolate identity fields, resolve domain, interpolate
///    groups, and return [`MatchResult`].
///
/// If no rule matches, returns `None`.
///
/// # Parameters
/// - `ruleset`: The ruleset to evaluate.
/// - `claims`: The flattened claims map from the ingress adapter.
/// - `domain_id`: The enclosing ruleset domain ID (used for
///   `${enclosing_domain_id}`).
///
/// # Returns
/// `Some(MatchResult)` on first match, `None` if no rule matches.
#[allow(dead_code)]
pub fn evaluate_ruleset(
    ruleset: &MappingRuleSet,
    claims: &HashMap<String, Vec<String>>,
    domain_id: Option<&str>,
) -> Result<Option<MatchResult>, MappingProviderError> {
    if !ruleset.enabled {
        return Ok(None);
    }

    let enclosing = domain_id.unwrap_or("");
    for rule in &ruleset.rules {
        if !evaluate_match(&rule.r#match, claims) {
            continue;
        }

        // Rule matched — interpolate identity fields and resolve result
        let user_name = interpolate_user_name(&rule.identity.user_name, claims, enclosing)
            .ok_or(MappingProviderError::InterpolatedValueTooLong)?;

        // user_name is required and must not be empty
        if user_name.is_empty() {
            continue;
        }

        let user_id = interpolate_user_id(&rule.identity.user_id, claims, enclosing)?;
        let user_domain_id =
            resolve_domain(&rule.identity.user_domain_id, claims, ruleset, enclosing)?;
        let resolved_group_bindings = interpolate_groups(&rule.groups, claims, ruleset, enclosing)?;

        return Ok(Some(MatchResult {
            rule_name: rule.name.clone(),
            user_name,
            user_id,
            user_domain_id,
            is_system: rule.identity.is_system,
            authorizations: rule.authorizations.clone(),
            resolved_group_bindings,
            ruleset_version: ruleset.ruleset_version,
        }));
    }

    Ok(None)
}

/// Evaluate a `MatchCriteria` node against a claims map.
///
/// Per ADR-0020 §5.2:
/// - `AllOf`: every child must evaluate to `true`.
/// - `AnyOf`: at least one child must evaluate to `true`.
/// - `AllOfStrict`: same as `AllOf`, but when `require_all_keys` is `true`, the
///   match fails if any referenced claim key is absent.
fn evaluate_match(criteria: &MatchCriteria, claims: &HashMap<String, Vec<String>>) -> bool {
    match criteria {
        MatchCriteria::AllOf(conditions) => {
            conditions.iter().all(|c| evaluate_condition(c, claims))
        }
        MatchCriteria::AnyOf(conditions) => {
            conditions.iter().any(|c| evaluate_condition(c, claims))
        }
        MatchCriteria::AllOfStrict {
            conditions,
            require_all_keys,
        } => {
            if *require_all_keys && !all_claim_keys_present(criteria, claims) {
                return false;
            }
            conditions.iter().all(|c| evaluate_condition(c, claims))
        }
    }
}

/// Evaluate a single `MatchCondition` (leaf claim or nested group).
fn evaluate_condition(condition: &MatchCondition, claims: &HashMap<String, Vec<String>>) -> bool {
    match condition {
        MatchCondition::Condition(cc) => evaluate_leaf(cc, claims),
        MatchCondition::Nested(criteria) => evaluate_match(criteria, claims),
    }
}

/// Evaluate a leaf `ClaimCondition` against the claims map.
///
/// Per ADR-0020 §5.1, JSON primitive values from the claims are normalized to
/// strings for comparison.
fn evaluate_leaf(condition: &ClaimCondition, claims: &HashMap<String, Vec<String>>) -> bool {
    let key = condition.claim_name();
    let values = claims.get(key);

    let Some(values) = values else {
        return false;
    };

    match condition {
        ClaimCondition::Equals { value, .. } => {
            let target = normalize_value(value);
            values.iter().any(|v| v == &target)
        }
        ClaimCondition::AnyOf {
            values: targets, ..
        } => {
            let normalized: Vec<String> = targets.iter().map(normalize_value).collect();
            values.iter().any(|v| normalized.iter().any(|t| v == t))
        }
        ClaimCondition::MatchesRegex { regex, .. } => {
            let re = match get_or_compile_regex(regex) {
                Ok(r) => r,
                Err(_) => return false,
            };
            values.iter().any(|v| {
                // Per-claim value limit: silently drop values exceeding 4 KiB
                if v.len() > 4096 {
                    return false;
                }
                re.is_match(v)
            })
        }
    }
}

/// Normalize a JSON `Value` to its string representation for comparison.
///
/// `Number` and `Bool` are converted via their `Display` representation,
/// `String` is used directly, and nested objects fall back to their JSON
/// serialization.
fn normalize_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

/// Get a precompiled regex from the cache, or compile and cache it on first
/// use.
///
/// Enforces a 1024-entry cap with LRU eviction of the 100 least recently used
/// entries to prevent adversarial cache partition attacks.
fn get_or_compile_regex(pattern: &str) -> Result<Regex, regex::Error> {
    let cache = REGEX_CACHE.get_or_init(DashMap::default);

    if let Some(re) = cache.get(pattern) {
        return Ok(re.value().clone());
    }

    let re = Regex::new(pattern)?;

    // Evict LRU entries if cache exceeds cap
    if cache.len() >= REGEX_CACHE_CAP {
        evict_lru(cache);
    }

    cache.insert(pattern.to_string(), re.clone());
    Ok(re)
}

/// Evict the N least recently used entries from the regex cache.
///
/// DashMap iterates in access order, so the first entries returned are
/// the least recently used.
fn evict_lru(cache: &DashMap<String, Regex>) {
    let mut to_remove = Vec::new();
    for entry in cache.iter() {
        if to_remove.len() >= REGEX_CACHE_EVICT {
            break;
        }
        to_remove.push(entry.key().clone());
    }
    for key in to_remove {
        cache.remove(&key);
    }
}

/// Check if all claim keys referenced in a `MatchCriteria` tree are present
/// in the claims map. Used by `AllOfStrict` with `require_all_keys: true`.
fn all_claim_keys_present(criteria: &MatchCriteria, claims: &HashMap<String, Vec<String>>) -> bool {
    for cc in criteria.walk_all_claim_conditions() {
        if !claims.contains_key(cc.claim_name()) {
            return false;
        }
    }
    true
}

/// Interpolate the `user_name` field. Returns `None` on overflow.
fn interpolate_user_name(
    template: &str,
    claims: &HashMap<String, Vec<String>>,
    domain_id: &str,
) -> Option<String> {
    interpolation::interpolate(template, claims, domain_id).ok()
}

/// Interpolate the `user_id` field. Returns `None` if absent or empty after
/// interpolation.
fn interpolate_user_id(
    template: &Option<String>,
    claims: &HashMap<String, Vec<String>>,
    domain_id: &str,
) -> Result<Option<String>, MappingProviderError> {
    match template {
        Some(t) => {
            let resolved = interpolation::interpolate(t, claims, domain_id)?;
            Ok(Some(resolved))
        }
        None => Ok(None),
    }
}

/// Resolve the effective domain ID for a principal.
///
/// Per ADR-0020 §5.3 step 3:
/// - If `identity.user_domain_id` contains a template, interpolate it.
/// - If `domain_resolution_mode` is `Fixed` and interpolated value doesn't
///   match `ruleset.domain_id`, fall back to `ruleset.domain_id`.
/// - If `ClaimsOrMapping` or `ClaimsOnly`, check against `allowed_domains`.
/// - If empty or absent, fall back to `ruleset.domain_id`.
fn resolve_domain(
    user_domain_id: &Option<String>,
    claims: &HashMap<String, Vec<String>>,
    ruleset: &MappingRuleSet,
    enclosing: &str,
) -> Result<Option<String>, MappingProviderError> {
    let interpolated = match user_domain_id {
        Some(t) => interpolation::interpolate(t, claims, enclosing)?,
        None => String::new(),
    };

    let fallback = || ruleset.domain_id.clone();

    if interpolated.is_empty() {
        return Ok(fallback());
    }

    // Fixed mode: only ruleset.domain_id is valid
    if matches!(ruleset.domain_resolution_mode, DomainResolutionMode::Fixed) {
        if let Some(ref did) = ruleset.domain_id
            && &interpolated != did
        {
            return Ok(fallback());
        }
        return Ok(fallback());
    }

    // ClaimsOrMapping / ClaimsOnly: check allowed_domains whitelist
    // Convert to HashSet for O(1) lookup — cardinality capped by validation
    // (MAX_ALLOWED_DOMAINS)
    let allowed: HashSet<String> = match &ruleset.domain_resolution_mode {
        DomainResolutionMode::ClaimsOrMapping { allowed_domains }
        | DomainResolutionMode::ClaimsOnly { allowed_domains } => {
            allowed_domains.iter().cloned().collect()
        }
        DomainResolutionMode::Fixed => HashSet::new(),
    };

    if !allowed.is_empty() && !allowed.contains(&interpolated) {
        return Ok(fallback());
    }

    Ok(Some(interpolated))
}

/// Interpolate group bindings, producing `GroupRef` entries.
fn interpolate_groups(
    groups: &[GroupAssignment],
    claims: &HashMap<String, Vec<String>>,
    _ruleset: &MappingRuleSet,
    enclosing: &str,
) -> Result<Vec<GroupRef>, MappingProviderError> {
    groups
        .iter()
        .map(|g| {
            let _ = interpolation::interpolate(&g.group_name, claims, enclosing)?;
            Ok(GroupRef {
                domain_id: g.group_domain_id.clone(),
                id: g.group_id.clone(),
                name: None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_core_types::mapping::resolution::DomainResolutionMode;
    use openstack_keystone_core_types::mapping::rule::{
        ClaimCondition, IdentityBinding, MappingRule, MatchCondition, MatchCriteria,
    };
    use openstack_keystone_core_types::mapping::ruleset::MappingRuleSet;

    fn build_ruleset(enabled: bool, rules: Vec<MappingRule>) -> MappingRuleSet {
        MappingRuleSet {
            mapping_id: "test-ruleset".to_string(),
            domain_id: Some("default-domain".to_string()),
            source: IdentitySource::Federation {
                idp_id: "okta".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled,
            rules,
            ruleset_version: 1,
        }
    }

    fn simple_rule(name: &str, claim: &str, value: &str, user_name: &str) -> MappingRule {
        MappingRule {
            name: name.to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::Equals {
                    claim: claim.to_string(),
                    value: serde_json::Value::String(value.to_string()),
                },
            )]),
            identity: IdentityBinding {
                user_name: user_name.to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }
    }

    fn test_claims() -> HashMap<String, Vec<String>> {
        let mut claims = HashMap::new();
        claims.insert("sub".to_string(), vec!["user-123".to_string()]);
        claims.insert("preferred_username".to_string(), vec!["alice".to_string()]);
        claims.insert("aud".to_string(), vec!["my-app".to_string()]);
        claims
    }

    #[test]
    fn test_first_match_wins() {
        let rules = vec![
            simple_rule("first", "sub", "user-123", "matched-first"),
            simple_rule("second", "sub", "user-123", "matched-second"),
        ];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_name, "first");
    }

    #[test]
    fn test_no_match_returns_none() {
        let rules = vec![simple_rule("nomatch", "sub", "user-999", "never-matched")];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_disabled_ruleset_returns_none() {
        let rules = vec![simple_rule("nomatch", "sub", "user-123", "matched")];
        let ruleset = build_ruleset(false, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_all_of_criteria_all_pass() {
        let rules = vec![MappingRule {
            name: "allmatch".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "sub".to_string(),
                    value: serde_json::Value::String("user-123".to_string()),
                }),
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "aud".to_string(),
                    value: serde_json::Value::String("my-app".to_string()),
                }),
            ]),
            identity: IdentityBinding {
                user_name: "allmatch-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_name, "allmatch");
    }

    #[test]
    fn test_all_of_criteria_one_fails() {
        let rules = vec![MappingRule {
            name: "allmatch".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "sub".to_string(),
                    value: serde_json::Value::String("user-123".to_string()),
                }),
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "sub".to_string(),
                    value: serde_json::Value::String("different".to_string()),
                }),
            ]),
            identity: IdentityBinding {
                user_name: "allmatch-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_any_of_criteria_one_passes() {
        let rules = vec![MappingRule {
            name: "anymatch".to_string(),
            description: None,
            r#match: MatchCriteria::AnyOf(vec![
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "sub".to_string(),
                    value: serde_json::Value::String("user-999".to_string()),
                }),
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "sub".to_string(),
                    value: serde_json::Value::String("user-123".to_string()),
                }),
            ]),
            identity: IdentityBinding {
                user_name: "anymatch-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_name, "anymatch");
    }

    #[test]
    fn test_regex_match() {
        let rules = vec![MappingRule {
            name: "regexmatch".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::MatchesRegex {
                    claim: "preferred_username".to_string(),
                    regex: "^a.*$".to_string(),
                },
            )]),
            identity: IdentityBinding {
                user_name: "regex-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_name, "regexmatch");
    }

    #[test]
    fn test_regex_no_match() {
        let rules = vec![MappingRule {
            name: "regexmatch".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::MatchesRegex {
                    claim: "preferred_username".to_string(),
                    regex: "^z.*$".to_string(),
                },
            )]),
            identity: IdentityBinding {
                user_name: "regex-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_all_of_strict_missing_key_with_require_all_keys() {
        let rules = vec![MappingRule {
            name: "strictmissing".to_string(),
            description: None,
            r#match: MatchCriteria::AllOfStrict {
                conditions: vec![
                    MatchCondition::Condition(ClaimCondition::Equals {
                        claim: "sub".to_string(),
                        value: serde_json::Value::String("user-123".to_string()),
                    }),
                    MatchCondition::Condition(ClaimCondition::Equals {
                        claim: "missing_key".to_string(),
                        value: serde_json::Value::String("value".to_string()),
                    }),
                ],
                require_all_keys: true,
            },
            identity: IdentityBinding {
                user_name: "strict-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_all_of_strict_missing_key_without_require_all_keys() {
        let rules = vec![MappingRule {
            name: "strictmissing".to_string(),
            description: None,
            r#match: MatchCriteria::AllOfStrict {
                conditions: vec![
                    MatchCondition::Condition(ClaimCondition::Equals {
                        claim: "sub".to_string(),
                        value: serde_json::Value::String("user-123".to_string()),
                    }),
                    MatchCondition::Condition(ClaimCondition::Equals {
                        claim: "missing_key".to_string(),
                        value: serde_json::Value::String("value".to_string()),
                    }),
                ],
                require_all_keys: false,
            },
            identity: IdentityBinding {
                user_name: "strict-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_domain_resolution_fixed_mode() {
        let rules = vec![MappingRule {
            name: "fixed".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::Equals {
                    claim: "sub".to_string(),
                    value: serde_json::Value::String("user-123".to_string()),
                },
            )]),
            identity: IdentityBinding {
                user_name: "fixed-user".to_string(),
                user_id: None,
                user_domain_id: Some("${claims.sub}".to_string()),
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        let match_result = result.unwrap();
        assert_eq!(
            match_result.user_domain_id,
            Some("default-domain".to_string())
        );
    }

    #[test]
    fn test_nested_match_criteria() {
        let rules = vec![MappingRule {
            name: "nested".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "sub".to_string(),
                    value: serde_json::Value::String("user-123".to_string()),
                }),
                MatchCondition::Nested(Box::new(MatchCriteria::AnyOf(vec![
                    MatchCondition::Condition(ClaimCondition::Equals {
                        claim: "aud".to_string(),
                        value: serde_json::Value::String("other-app".to_string()),
                    }),
                    MatchCondition::Condition(ClaimCondition::Equals {
                        claim: "aud".to_string(),
                        value: serde_json::Value::String("my-app".to_string()),
                    }),
                ]))),
            ]),
            identity: IdentityBinding {
                user_name: "nested-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_name, "nested");
    }

    #[test]
    fn test_interpolation_in_user_name() {
        let rules = vec![MappingRule {
            name: "interpolated".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::Equals {
                    claim: "sub".to_string(),
                    value: serde_json::Value::String("user-123".to_string()),
                },
            )]),
            identity: IdentityBinding {
                user_name: "${claims.preferred_username}@mapped".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        let match_result = result.unwrap();
        assert_eq!(match_result.user_name, "alice@mapped");
    }

    #[test]
    fn test_all_of_strict_all_keys_present_passes() {
        let rules = vec![MappingRule {
            name: "strictall".to_string(),
            description: None,
            r#match: MatchCriteria::AllOfStrict {
                conditions: vec![
                    MatchCondition::Condition(ClaimCondition::Equals {
                        claim: "sub".to_string(),
                        value: serde_json::Value::String("user-123".to_string()),
                    }),
                    MatchCondition::Condition(ClaimCondition::Equals {
                        claim: "aud".to_string(),
                        value: serde_json::Value::String("my-app".to_string()),
                    }),
                ],
                require_all_keys: true,
            },
            identity: IdentityBinding {
                user_name: "strictall-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_name, "strictall");
    }

    #[test]
    fn test_any_of_criteria_all_fail() {
        let rules = vec![MappingRule {
            name: "anyfail".to_string(),
            description: None,
            r#match: MatchCriteria::AnyOf(vec![
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "sub".to_string(),
                    value: serde_json::Value::String("user-999".to_string()),
                }),
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "aud".to_string(),
                    value: serde_json::Value::String("other-app".to_string()),
                }),
            ]),
            identity: IdentityBinding {
                user_name: "anyfail-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_domain_resolution_claims_only_passes() {
        let rules = vec![MappingRule {
            name: "claimsonly".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::Equals {
                    claim: "sub".to_string(),
                    value: serde_json::Value::String("user-123".to_string()),
                },
            )]),
            identity: IdentityBinding {
                user_name: "claimsonly-user".to_string(),
                user_id: None,
                user_domain_id: Some("${claims.domain_claim}".to_string()),
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = MappingRuleSet {
            mapping_id: "test-ruleset".to_string(),
            domain_id: None,
            source: IdentitySource::Federation {
                idp_id: "okta".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::ClaimsOnly {
                allowed_domains: vec!["target-domain".to_string()],
            },
            enabled: true,
            rules,
            ruleset_version: 1,
        };
        let mut claims = test_claims();
        claims.insert(
            "domain_claim".to_string(),
            vec!["target-domain".to_string()],
        );
        let result = evaluate_ruleset(&ruleset, &claims, Some("default-domain")).unwrap();
        let match_result = result.unwrap();
        assert_eq!(
            match_result.user_domain_id,
            Some("target-domain".to_string())
        );
    }

    #[test]
    fn test_domain_resolution_claims_only_fallback() {
        let rules = vec![MappingRule {
            name: "claimsonly-fallback".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::Equals {
                    claim: "sub".to_string(),
                    value: serde_json::Value::String("user-123".to_string()),
                },
            )]),
            identity: IdentityBinding {
                user_name: "claimsonly-fallback-user".to_string(),
                user_id: None,
                user_domain_id: Some("${claims.sub}".to_string()),
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = MappingRuleSet {
            mapping_id: "test-ruleset".to_string(),
            domain_id: Some("fallback-domain".to_string()),
            source: IdentitySource::Federation {
                idp_id: "okta".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::ClaimsOnly {
                allowed_domains: vec!["other-domain".to_string()],
            },
            enabled: true,
            rules,
            ruleset_version: 1,
        };
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        let match_result = result.unwrap();
        assert_eq!(
            match_result.user_domain_id,
            Some("fallback-domain".to_string())
        );
    }

    #[test]
    fn test_empty_user_name_is_skipped() {
        let rules = vec![
            MappingRule {
                name: "empty-name".to_string(),
                description: None,
                r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                    ClaimCondition::Equals {
                        claim: "sub".to_string(),
                        value: serde_json::Value::String("user-123".to_string()),
                    },
                )]),
                identity: IdentityBinding {
                    user_name: "".to_string(),
                    user_id: None,
                    user_domain_id: None,
                    is_system: false,
                },
                authorizations: vec![],
                groups: vec![],
            },
            simple_rule("fallback", "aud", "my-app", "fallback-user"),
        ];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_name, "fallback");
    }

    #[test]
    fn test_user_id_interpolation() {
        let rules = vec![MappingRule {
            name: "userid".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::Equals {
                    claim: "sub".to_string(),
                    value: serde_json::Value::String("user-123".to_string()),
                },
            )]),
            identity: IdentityBinding {
                user_name: "userid-user".to_string(),
                user_id: Some("${claims.sub}-suffix".to_string()),
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        let match_result = result.unwrap();
        assert_eq!(match_result.user_id, Some("user-123-suffix".to_string()));
    }

    // --- ClaimCondition::AnyOf ---
    #[test]
    fn test_claim_any_of_matches_first_value() {
        let rules = vec![MappingRule {
            name: "anyvalue".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::AnyOf {
                claim: "sub".to_string(),
                values: vec![
                    serde_json::Value::String("not-this".to_string()),
                    serde_json::Value::String("user-123".to_string()),
                ],
            })]),
            identity: IdentityBinding {
                user_name: "anyof-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_name, "anyvalue");
    }

    #[test]
    fn test_claim_any_of_no_match() {
        let rules = vec![MappingRule {
            name: "anyvalue".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(ClaimCondition::AnyOf {
                claim: "sub".to_string(),
                values: vec![
                    serde_json::Value::String("not-this".to_string()),
                    serde_json::Value::String("also-wrong".to_string()),
                ],
            })]),
            identity: IdentityBinding {
                user_name: "anyof-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_none());
    }

    // --- ClaimCondition::Equals with multiple claim values ---
    #[test]
    fn test_equals_matches_multi_value_claim_second_entry() {
        let mut claims = test_claims();
        claims.insert(
            "group".to_string(),
            vec!["group-a".to_string(), "admin".to_string()],
        );
        let rules = vec![MappingRule {
            name: "multivalue".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::Equals {
                    claim: "group".to_string(),
                    value: serde_json::Value::String("admin".to_string()),
                },
            )]),
            identity: IdentityBinding {
                user_name: "multivalue-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &claims, Some("default-domain")).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_name, "multivalue");
    }

    // --- ClaimCondition::MatchesRegex invalid pattern ---
    #[test]
    fn test_regex_invalid_pattern_returns_no_match() {
        let rules = vec![MappingRule {
            name: "badregex".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::MatchesRegex {
                    claim: "preferred_username".to_string(),
                    regex: "[invalid(regex".to_string(), // invalid: unclosed bracket
                },
            )]),
            identity: IdentityBinding {
                user_name: "badregex-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &test_claims(), Some("default-domain")).unwrap();
        assert!(result.is_none());
    }

    // --- ClaimCondition::MatchesRegex oversized claim value ---
    #[test]
    fn test_regex_oversized_claim_value_ignored() {
        let mut claims = test_claims();
        claims.insert(
            "large_claim".to_string(),
            vec!["a".repeat(4097)], // exceeds 4 KiB limit
        );
        let rules = vec![MappingRule {
            name: "large".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::MatchesRegex {
                    claim: "large_claim".to_string(),
                    regex: "a+".to_string(),
                },
            )]),
            identity: IdentityBinding {
                user_name: "large-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &claims, Some("default-domain")).unwrap();
        assert!(result.is_none());
    }

    // --- MatchesRegex with multiple claim values, one matches ---
    #[test]
    fn test_regex_matches_multi_value_claim_partial() {
        let mut claims = test_claims();
        claims.insert(
            "tags".to_string(),
            vec!["xyz-service".to_string(), "abc-allowed".to_string()],
        );
        let rules = vec![MappingRule {
            name: "tagregex".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::MatchesRegex {
                    claim: "tags".to_string(),
                    regex: "^abc-".to_string(),
                },
            )]),
            identity: IdentityBinding {
                user_name: "tagregex-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &claims, Some("default-domain")).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_name, "tagregex");
    }

    // --- SPIFFE claims end-to-end evaluation ---
    #[test]
    fn test_spiffe_claims_evaluation() {
        let mut claims = HashMap::new();
        claims.insert(
            "spiffe.id".to_string(),
            vec!["spiffe://example.org/workload".to_string()],
        );
        claims.insert(
            "spiffe.trust_domain".to_string(),
            vec!["example.org".to_string()],
        );
        let rules = vec![MappingRule {
            name: "spiffe-rule".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![
                MatchCondition::Condition(ClaimCondition::Equals {
                    claim: "spiffe.id".to_string(),
                    value: serde_json::Value::String("spiffe://example.org/workload".to_string()),
                }),
                MatchCondition::Condition(ClaimCondition::MatchesRegex {
                    claim: "spiffe.trust_domain".to_string(),
                    regex: "^example\\.".to_string(),
                }),
            ]),
            identity: IdentityBinding {
                user_name: "${claims.spiffe.trust_domain}-user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];
        let ruleset = build_ruleset(true, rules);
        let result = evaluate_ruleset(&ruleset, &claims, Some("default-domain")).unwrap();
        assert!(result.is_some());
        let match_result = result.unwrap();
        assert_eq!(match_result.rule_name, "spiffe-rule");
        assert_eq!(match_result.user_name, "example.org-user");
    }
}
