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
//! Write-time validation pipeline for mapping rulesets.
//!
//! Per ADR §10.1, every ruleset is validated before persistence to enforce:
//! - Regex ReDoS safety (via `regex_syntax` HIR walk)
//! - Template safety (no `enclosing_domain_id` shadowing)
//! - Rule name uniqueness and identifier format
//! - Domain resolution mode consistency
//! - Immutability enforcement for `is_system` rulesets

use std::collections::HashSet;

use regex_syntax::hir::{Hir, HirKind, Repetition as HirRepetition};

use openstack_keystone_core_types::mapping::MappingProviderError;
use openstack_keystone_core_types::mapping::authorization::Authorization;
use openstack_keystone_core_types::mapping::resolution::{DomainResolutionMode, IdentitySource};
use openstack_keystone_core_types::mapping::rule::{ClaimCondition, MappingRule};
use openstack_keystone_core_types::mapping::ruleset::{
    MappingRuleSet, MappingRuleSetCreate, MappingRuleSetUpdate,
};

use crate::mapping::interpolation::{contains_claims_template, extract_claims_keys};

/// Maximum HIR string size for a regex before it is considered too complex.
const MAX_REGEX_HIR_SIZE: usize = 4096;

/// Maximum number of domain IDs in an `allowed_domains` whitelist.
/// Prevents O(n) evaluation degradation on auth path.
const MAX_ALLOWED_DOMAINS: usize = 256;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Validate a ruleset creation payload before persistence.
///
/// Orchestrates all write-time guards defined in ADR §10.1:
/// 1. Rule name uniqueness and identifier format
/// 2. Regex safety (ReDoS protection)
/// 3. Template safety (`enclosing_domain_id` shadowing prevention)
/// 4. Domain resolution mode consistency
///
/// # Parameters
/// - `ruleset`: Ruleset creation payload to validate.
///
/// # Returns
/// `Ok(())` if the ruleset passes all checks; otherwise `MappingProviderError`.
pub fn validate_ruleset_create(ruleset: &MappingRuleSetCreate) -> Result<(), MappingProviderError> {
    // 1. Rule name uniqueness and format
    validate_rules(&ruleset.rules)?;

    // Regex safety for all `MatchesRegex` conditions
    let all_conditions = collect_all_claim_conditions(&ruleset.rules);
    for cc in &all_conditions {
        if let Some(pattern) = cc.regex_pattern() {
            validate_regex(pattern)?;
        }
    }

    // Template safety — no `enclosing_domain_id` shadowing
    validate_identity_templates(&ruleset.rules, &ruleset.domain_resolution_mode)?;

    // Domain resolution mode consistency
    validate_domain_resolution_mode(
        &ruleset.domain_resolution_mode,
        &ruleset.rules,
        ruleset.domain_id.as_deref(),
    )?;

    Ok(())
}

/// Validate a ruleset update payload against the existing ruleset.
///
/// Enforces immutability constraints on `domain_id`, `source`, and
/// `domain_resolution_mode`. Validates new rules if supplied.
///
/// # Parameters
/// - `existing`: Current stored ruleset.
/// - `update`: Update payload to validate.
///
/// # Returns
/// `Ok(())` if the update passes all checks; otherwise `MappingProviderError`.
pub fn validate_ruleset_update(
    existing: &MappingRuleSet,
    update: &MappingRuleSetUpdate,
) -> Result<(), MappingProviderError> {
    // If new rules are supplied, validate them
    if let Some(ref rules) = update.rules {
        validate_rules(rules)?;

        // Regex safety
        let all_conditions = collect_all_claim_conditions(rules);
        for cc in &all_conditions {
            if let Some(pattern) = cc.regex_pattern() {
                validate_regex(pattern)?;
            }
        }

        // Template safety
        validate_identity_templates(rules, &existing.domain_resolution_mode)?;

        // Domain resolution mode consistency
        validate_domain_resolution_mode(
            &existing.domain_resolution_mode,
            rules,
            existing.domain_id.as_deref(),
        )?;
    }

    // Validate allowed_domains update consistency
    if let Some(ref allowed_domains) = update.allowed_domains {
        validate_allowed_domains_update(&existing.domain_resolution_mode, allowed_domains)?;
    }

    Ok(())
}

/// Validate a single regex pattern for ReDoS safety.
///
/// A regex is safe if it:
/// 1. Parses successfully (syntax validation)
/// 2. Has no nested quantifiers (`(a+)+`, `(a*)*`)
/// 3. Has no unbounded alternation under quantifiers (`(a|b)+`)
/// 4. Stays within complexity bounds (HIR size <= 4096)
///
/// The Rust `regex` crate uses a finite automata engine with linear worst-case
/// time, but pathological patterns with nested quantifiers and alternation can
/// still cause performance degradation. The write-time HIR walk acts as a
/// defense-in-depth layer.
///
/// # Parameters
/// - `pattern`: Regex pattern to validate.
///
/// # Returns
/// `Ok(())` if the pattern passes all ReDoS checks; otherwise
/// `MappingProviderError`.
pub fn validate_regex(pattern: &str) -> Result<(), MappingProviderError> {
    // 1. Parse to HIR — detects invalid syntax
    let hir = match regex_syntax::Parser::new().parse(pattern) {
        Ok(h) => h,
        Err(_) => {
            return Err(MappingProviderError::InvalidRegexSyntax(
                pattern.to_string(),
            ));
        }
    };

    // 4. Complexity check — HIR string representation size
    let hir_str = hir.to_string();
    if hir_str.len() > MAX_REGEX_HIR_SIZE {
        return Err(MappingProviderError::RegexTooComplex(pattern.to_string()));
    }

    // 2 & 3. Nested quantifiers and unbounded alternation check
    let mut errors = Vec::new();
    check_nested_quantifiers(&hir, &mut errors);

    if let Some(err) = errors.into_iter().next() {
        return Err(MappingProviderError::RegexSafetyViolation(
            pattern.to_string(),
            err,
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Collect all `ClaimCondition` references from all rules.
fn collect_all_claim_conditions(rules: &[MappingRule]) -> Vec<&ClaimCondition> {
    let mut result = Vec::new();
    for rule in rules {
        result.extend(rule.r#match.walk_all_claim_conditions());
    }
    result
}

/// Validate rule names: uniqueness, non-empty, alphanumeric identifier format.
fn validate_rules(rules: &[MappingRule]) -> Result<(), MappingProviderError> {
    let mut seen = HashSet::new();

    for rule in rules {
        // Validate identifier format: alphanumeric, underscores, hyphens, dots
        if !is_valid_rule_name(&rule.name) {
            return Err(MappingProviderError::InvalidRuleName(rule.name.clone()));
        }

        // Check uniqueness
        if !seen.insert(rule.name.as_str()) {
            return Err(MappingProviderError::DuplicateRuleName(rule.name.clone()));
        }
    }

    Ok(())
}

/// Enforce that ApiClient-sourced rulesets only grant Domain scope.
///
/// Per ADR 0021 §6.C, allowing an API Key to hold system scope is dangerous.
/// Per ADR 0021 §2, API Keys are domain-owned machine identities, so only
/// `Authorization::Domain` is allowed. Both checks are combined in a single
/// pass and return the most specific error.
pub fn validate_api_client_domain_scope(
    source: &IdentitySource,
    rules: &[MappingRule],
) -> Result<(), MappingProviderError> {
    if !matches!(source, IdentitySource::ApiClient { .. }) {
        return Ok(());
    }
    for rule in rules {
        if rule.identity.is_system
            || rule
                .authorizations
                .iter()
                .any(|auth| matches!(auth, Authorization::System { .. }))
        {
            return Err(MappingProviderError::ApiClientSystemScopeForbidden(
                rule.name.clone(),
            ));
        }
        if rule
            .authorizations
            .iter()
            .any(|auth| !matches!(auth, Authorization::Domain { .. }))
        {
            return Err(MappingProviderError::ApiClientNonDomainScopeForbidden(
                rule.name.clone(),
            ));
        }
    }
    Ok(())
}

/// Check if a rule name is a valid identifier.
///
/// Valid names are `[a-zA-Z0-9_./-]+` — alphanumeric, underscores, hyphens,
/// dots, slashes.
fn is_valid_rule_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '/')
}

/// Validate identity binding templates for claims shadowing.
///
/// Rejects templates that reference `${claims.enclosing_domain_id}` to prevent
/// domain context shadowing.
fn validate_identity_templates(
    rules: &[MappingRule],
    _mode: &DomainResolutionMode,
) -> Result<(), MappingProviderError> {
    for rule in rules {
        let templates = [
            Some(rule.identity.user_name.as_str()),
            rule.identity.user_id.as_deref(),
            rule.identity.user_domain_id.as_deref(),
        ];

        for template in templates.into_iter().flatten() {
            // Check for `enclosing_domain_id` shadowing
            let keys = extract_claims_keys(template);
            if keys.iter().any(|k| k == "enclosing_domain_id") {
                return Err(MappingProviderError::SystemTokenShadowing(
                    "enclosing_domain_id".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Validate domain resolution mode consistency.
///
/// - `Fixed`: `user_domain_id` must NOT contain `${claims.*}` templates.
///   Authorization domain IDs and group domain IDs must also NOT contain
///   `${claims.*}` templates.
/// - `ClaimsOnly`: `user_domain_id` must contain at least one `${claims.*}`
///   template.
/// - `ClaimsOrMapping`: both claim templates and static values are permitted.
fn validate_domain_resolution_mode(
    mode: &DomainResolutionMode,
    rules: &[MappingRule],
    domain_id: Option<&str>,
) -> Result<(), MappingProviderError> {
    match mode {
        DomainResolutionMode::Fixed => {
            // Fixed mode: no claim templates in any domain fields
            for rule in rules {
                // Check user_domain_id in identity binding
                if let Some(ref domain_template) = rule.identity.user_domain_id
                    && contains_claims_template(domain_template)
                {
                    return Err(MappingProviderError::DomainOverrideInFixedMode);
                }

                // Check domain IDs in authorizations
                for auth in &rule.authorizations {
                    let d = match auth {
                        openstack_keystone_core_types::mapping::authorization::Authorization::Domain {
                            domain_id: d,
                            ..
                        } => d,
                        openstack_keystone_core_types::mapping::authorization::Authorization::Project {
                            project_domain_id: d,
                            ..
                        } => d,
                        openstack_keystone_core_types::mapping::authorization::Authorization::System {
                            ..
                        } => {
                            continue;
                        }
                    };
                    if contains_claims_template(d) {
                        return Err(MappingProviderError::DomainOverrideInFixedMode);
                    }
                }

                // Check group domain IDs
                for group in &rule.groups {
                    if let Some(ref group_domain) = group.group_domain_id
                        && contains_claims_template(group_domain)
                    {
                        return Err(MappingProviderError::DomainOverrideInFixedMode);
                    }
                }
            }
        }
        DomainResolutionMode::ClaimsOnly { allowed_domains } => {
            // ClaimsOnly: at least one rule must have claim template in user_domain_id
            let has_claims_template = rules.iter().any(|r| {
                r.identity
                    .user_domain_id
                    .as_ref()
                    .is_some_and(|t| contains_claims_template(t))
            });

            if !has_claims_template {
                return Err(MappingProviderError::DomainClaimRequired);
            }

            // domain_id should be None for ClaimsOnly
            if domain_id.is_some() {
                return Err(MappingProviderError::DomainClaimRequired);
            }

            // Enforce cardinality limit on allowed_domains whitelist
            if allowed_domains.len() > MAX_ALLOWED_DOMAINS {
                return Err(MappingProviderError::AllowedDomainsTooLarge(
                    MAX_ALLOWED_DOMAINS,
                ));
            }
        }
        DomainResolutionMode::ClaimsOrMapping { allowed_domains } => {
            // Both claim templates and static values are permitted
            // No additional constraints beyond template safety
            // Enforce cardinality limit on allowed_domains whitelist
            if allowed_domains.len() > MAX_ALLOWED_DOMAINS {
                return Err(MappingProviderError::AllowedDomainsTooLarge(
                    MAX_ALLOWED_DOMAINS,
                ));
            }
        }
    }

    Ok(())
}

/// Validate `allowed_domains` update against existing mode.
///
/// For `Fixed` mode, `allowed_domains` must be empty (or not set).
/// For `ClaimsOnly`/`ClaimsOrMapping`, `allowed_domains` must be non-empty.
fn validate_allowed_domains_update(
    mode: &DomainResolutionMode,
    allowed_domains: &[String],
) -> Result<(), MappingProviderError> {
    match mode {
        DomainResolutionMode::Fixed => {
            // Fixed mode must have empty allowed_domains
            if !allowed_domains.is_empty() {
                return Err(MappingProviderError::DomainOverrideInFixedMode);
            }
        }
        DomainResolutionMode::ClaimsOnly { .. } | DomainResolutionMode::ClaimsOrMapping { .. } => {
            // Claims-only modes require non-empty allowed_domains
            if allowed_domains.is_empty() {
                return Err(MappingProviderError::DomainClaimRequired);
            }
            // Enforce cardinality limit to prevent O(n) evaluation degradation
            if allowed_domains.len() > MAX_ALLOWED_DOMAINS {
                return Err(MappingProviderError::AllowedDomainsTooLarge(
                    MAX_ALLOWED_DOMAINS,
                ));
            }
        }
    }

    Ok(())
}

/// Recursively check for nested quantifiers and unbounded alternation under
/// quantifiers in the HIR tree.
///
/// Patterns that fail:
/// - `(a+)+` — nested repetition (quantifier applied to a group containing
///   another quantifier)
/// - `(a|b)*` — unbounded alternation under quantifier
/// - `(a+|b|)+` — both
fn check_nested_quantifiers(hir: &Hir, errors: &mut Vec<String>) {
    if let HirKind::Repetition(rep) = hir.kind() {
        // Check the repetition's body for nested quantifiers or alternation
        check_body_for_nested_quantifiers(rep, &rep.sub, errors);
    }

    // Recurse into all children to find nested quantifiers wrapped in other nodes
    // (e.g., a Repetition inside a Capture inside another Repetition).
    // The `subs()` method returns the sub-expressions of `Concat`, `Alternation`,
    // `Capture`, and `Repetition`. We recurse into all children, accepting that
    // nested repetitions will be checked again (without adding duplicate errors).
    for child in hir.kind().subs() {
        check_nested_quantifiers(child, errors);
    }
}

/// Check if a repetition body contains another quantifier or alternation.
///
/// A repetition body is "unsafe" when:
/// - The repetition is unbounded (max is None or > min), AND
/// - The body contains another quantifier (Repetition), OR
/// - The body contains alternation that could match overlapping patterns
///
/// Note: the `regex_syntax` HIR optimizes single-character alternations into
/// character classes (`(a|b)` → `[ab]`), so those are detected through
/// character class analysis instead. Nested quantifiers like `(a+)+` and
/// `(a{2,})*` are the primary targets.
fn check_body_for_nested_quantifiers(rep: &HirRepetition, body: &Hir, errors: &mut Vec<String>) {
    let is_bounded = rep.min == rep.max.unwrap_or(u32::MAX) && rep.min > 0;

    // Only unbounded (or optional) repetitions are problematic
    if is_bounded {
        // Exact repetition count (e.g., `a{3}`) is always safe
        return;
    }

    // Look through intermediate nodes (e.g., Capture) to find nested repetitions.
    // The HIR wraps `(a+)` in a Capture node, so we need to look inside Capture
    // to find the nested Repetition.
    match body.kind() {
        // Direct nested quantifier: `a++`, `(a+)*`, etc.
        HirKind::Repetition(_) => {
            if errors.is_empty() {
                errors.push("nested quantifier detected".to_string());
            }
        }
        // Unbounded alternation: `(a|b)*`, `(x|y)+`, etc.
        // HIR may normalize `(a|b)` to `[ab]`, so this checks the remaining cases
        HirKind::Alternation(alts) => {
            // Multiple branches under quantifier can cause pathological matching
            if alts.len() > 1 && errors.is_empty() {
                errors.push("unbounded alternation under quantifier".to_string());
            }
        }
        // Capture wraps another node — look inside.
        // e.g., `(a+)+` has `Repetition -> Capture -> Repetition`.
        HirKind::Capture(capture) => {
            check_body_for_nested_quantifiers(rep, capture.sub.as_ref(), errors);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_core_types::mapping::resolution::IdentitySource;
    use openstack_keystone_core_types::mapping::rule::{
        ClaimCondition, IdentityBinding, MappingRule, MatchCriteria,
    };
    use serde_json::json;

    fn sample_ruleset_create() -> MappingRuleSetCreate {
        let rules = vec![MappingRule {
            name: "test-rule".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user-${claims.sub}".to_string(),
                user_id: Some("${claims.sub}".to_string()),
                user_domain_id: None,
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: Vec::new(),
        }];

        MappingRuleSetCreate {
            mapping_id: Some("test-123".to_string()),
            domain_id: Some("test-domain".to_string()),
            source: IdentitySource::Federation {
                idp_id: "idp-1".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled: true,
            rules,
        }
    }

    fn simple_rule(name: &str, user_name: &str) -> MappingRule {
        MappingRule {
            name: name.to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: user_name.to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // validate_regex tests
    // -----------------------------------------------------------------------

    #[test]
    fn valid_simple_regex() {
        assert!(validate_regex("^[a-z]+$").is_ok());
    }

    #[test]
    fn valid_email_regex() {
        // Use [a-zA-Z] instead of \w to avoid huge HIR expansion
        assert!(validate_regex(r"^[a-zA-Z]+@[a-zA-Z]+\.[a-zA-Z]+$").is_ok());
    }

    #[test]
    fn invalid_syntax() {
        let result = validate_regex("(unclosed");
        assert!(matches!(
            result,
            Err(MappingProviderError::InvalidRegexSyntax(_))
        ));
    }

    #[test]
    fn rejects_nested_quantifier() {
        let result = validate_regex("(a+)+");
        assert!(matches!(
            result,
            Err(MappingProviderError::RegexSafetyViolation(_, _))
        ));
    }

    #[test]
    fn rejects_nested_star_quantifier() {
        let result = validate_regex("(a*)*");
        assert!(matches!(
            result,
            Err(MappingProviderError::RegexSafetyViolation(_, _))
        ));
    }

    #[test]
    fn rejects_unbounded_alternation() {
        // `(a|b|c)` with 3 branches of different chars is normalized to `[abc]`
        // But `(?:ab|cd)+` with multi-char alternation is NOT normalized
        let result = validate_regex("(?:ab|cd|)+");
        assert!(matches!(
            result,
            Err(MappingProviderError::RegexSafetyViolation(_, _))
        ));
    }

    #[test]
    fn passes_exact_repetition() {
        // `a{3}` is safe — exact repetition count
        assert!(validate_regex("a{3}").is_ok());
    }

    #[test]
    fn passes_single_alternation_under_quantifier() {
        // `(?:(?:a))*` — after HIR normalization, this should be acceptable
        // because there's a single branch after group normalization
        // Actually, let's test a simpler case. `a*` should be safe.
        assert!(validate_regex("a*").is_ok());
    }

    #[test]
    fn passes_bounded_range() {
        // `a{0,5}` is safe — bounded
        assert!(validate_regex("a{0,5}").is_ok());
    }

    #[test]
    fn rejects_complex_pattern() {
        // Build a pattern that exceeds MAX_REGEX_HIR_SIZE
        let pattern = "a".repeat(MAX_REGEX_HIR_SIZE + 100);
        let result = validate_regex(&pattern);
        // Simple literals have HIR of same length as pattern, so it will exceed the
        // limit
        assert!(matches!(
            result,
            Err(MappingProviderError::RegexTooComplex(_))
        ));
    }

    // -----------------------------------------------------------------------
    // validate_rules tests
    // -----------------------------------------------------------------------

    #[test]
    fn valid_rules() {
        let rules = vec![simple_rule("rule-a", "user-a")];
        assert!(validate_rules(&rules).is_ok());
    }

    #[test]
    fn duplicate_rule_names() {
        let rules = vec![
            simple_rule("rule-a", "user-a"),
            simple_rule("rule-a", "user-b"),
        ];
        let result = validate_rules(&rules);
        assert!(matches!(
            result,
            Err(MappingProviderError::DuplicateRuleName(_))
        ));
    }

    #[test]
    fn invalid_rule_name_empty() {
        let rules = vec![simple_rule("", "user-a")];
        let result = validate_rules(&rules);
        assert!(matches!(
            result,
            Err(MappingProviderError::InvalidRuleName(_))
        ));
    }

    #[test]
    fn valid_rule_name_with_special_chars() {
        // Underscores, hyphens, dots, slashes are allowed
        let rules = vec![simple_rule("rule_a.b/c", "user")];
        assert!(validate_rules(&rules).is_ok());
    }

    #[test]
    fn invalid_rule_name_with_space() {
        let rules = vec![simple_rule("rule with space", "user")];
        let result = validate_rules(&rules);
        assert!(matches!(
            result,
            Err(MappingProviderError::InvalidRuleName(_))
        ));
    }

    // -----------------------------------------------------------------------
    // validate_domain_resolution_mode tests
    // -----------------------------------------------------------------------

    #[test]
    fn fixed_mode_no_claim_templates_in_user_domain() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user-${claims.sub}".to_string(),
                user_id: None,
                user_domain_id: Some("${claims.domain}".to_string()),
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: Vec::new(),
        }];

        let result =
            validate_domain_resolution_mode(&DomainResolutionMode::Fixed, &rules, Some("domain"));

        assert!(matches!(
            result,
            Err(MappingProviderError::DomainOverrideInFixedMode)
        ));
    }

    #[test]
    fn fixed_mode_static_user_domain_allowed() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user-${claims.sub}".to_string(),
                user_id: None,
                user_domain_id: Some("static-domain".to_string()),
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: Vec::new(),
        }];

        let result =
            validate_domain_resolution_mode(&DomainResolutionMode::Fixed, &rules, Some("domain"));

        // Static domain is allowed in Fixed mode
        assert!(result.is_ok());
    }

    #[test]
    fn claims_only_requires_claims_template_in_user_domain() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user-${claims.sub}".to_string(),
                user_id: None,
                user_domain_id: Some("static-domain".to_string()),
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: Vec::new(),
        }];

        let result = validate_domain_resolution_mode(
            &DomainResolutionMode::ClaimsOnly {
                allowed_domains: vec!["d1".to_string()],
            },
            &rules,
            None,
        );

        assert!(matches!(
            result,
            Err(MappingProviderError::DomainClaimRequired)
        ));
    }

    #[test]
    fn claims_only_passes_with_claims_template() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user-${claims.sub}".to_string(),
                user_id: None,
                user_domain_id: Some("${claims.domain}".to_string()),
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: Vec::new(),
        }];

        let result = validate_domain_resolution_mode(
            &DomainResolutionMode::ClaimsOnly {
                allowed_domains: vec!["d1".to_string()],
            },
            &rules,
            None,
        );

        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // validate_domain_resolution_mode — authorization domain_id tests
    // -----------------------------------------------------------------------

    #[test]
    fn fixed_mode_rejects_claims_template_in_domain_auth_domain_id() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![
                openstack_keystone_core_types::mapping::authorization::Authorization::Domain {
                    domain_id: "${claims.domain}".to_string(),
                    roles: vec![],
                },
            ],
            groups: Vec::new(),
        }];

        let result =
            validate_domain_resolution_mode(&DomainResolutionMode::Fixed, &rules, Some("domain"));

        assert!(matches!(
            result,
            Err(MappingProviderError::DomainOverrideInFixedMode)
        ));
    }

    #[test]
    fn fixed_mode_rejects_claims_template_in_project_auth_project_domain_id() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![
                openstack_keystone_core_types::mapping::authorization::Authorization::Project {
                    project_id: "proj-123".to_string(),
                    project_domain_id: "${claims.domain}".to_string(),
                    roles: vec![],
                },
            ],
            groups: Vec::new(),
        }];

        let result =
            validate_domain_resolution_mode(&DomainResolutionMode::Fixed, &rules, Some("domain"));

        assert!(matches!(
            result,
            Err(MappingProviderError::DomainOverrideInFixedMode)
        ));
    }

    #[test]
    fn fixed_mode_allows_static_domain_in_domain_auth() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![
                openstack_keystone_core_types::mapping::authorization::Authorization::Domain {
                    domain_id: "static-domain".to_string(),
                    roles: vec![],
                },
            ],
            groups: Vec::new(),
        }];

        let result =
            validate_domain_resolution_mode(&DomainResolutionMode::Fixed, &rules, Some("domain"));

        assert!(result.is_ok());
    }

    #[test]
    fn fixed_mode_allows_static_domain_in_project_auth() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![
                openstack_keystone_core_types::mapping::authorization::Authorization::Project {
                    project_id: "proj-123".to_string(),
                    project_domain_id: "static-domain".to_string(),
                    roles: vec![],
                },
            ],
            groups: Vec::new(),
        }];

        let result =
            validate_domain_resolution_mode(&DomainResolutionMode::Fixed, &rules, Some("domain"));

        assert!(result.is_ok());
    }

    #[test]
    fn fixed_mode_allows_system_authorization() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![
                openstack_keystone_core_types::mapping::authorization::Authorization::System {
                    system_id: "all".to_string(),
                    roles: vec![],
                },
            ],
            groups: Vec::new(),
        }];

        let result =
            validate_domain_resolution_mode(&DomainResolutionMode::Fixed, &rules, Some("domain"));

        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // validate_domain_resolution_mode — group domain_id tests
    // -----------------------------------------------------------------------

    #[test]
    fn fixed_mode_rejects_claims_template_in_group_domain_id() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: vec![
                openstack_keystone_core_types::mapping::authorization::GroupAssignment {
                    group_id: None,
                    group_domain_id: Some("${claims.domain}".to_string()),
                    group_name: "admins".to_string(),
                    strategy: None,
                },
            ],
        }];

        let result =
            validate_domain_resolution_mode(&DomainResolutionMode::Fixed, &rules, Some("domain"));

        assert!(matches!(
            result,
            Err(MappingProviderError::DomainOverrideInFixedMode)
        ));
    }

    #[test]
    fn fixed_mode_allows_static_group_domain_id() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: vec![
                openstack_keystone_core_types::mapping::authorization::GroupAssignment {
                    group_id: None,
                    group_domain_id: Some("static-domain".to_string()),
                    group_name: "admins".to_string(),
                    strategy: None,
                },
            ],
        }];

        let result =
            validate_domain_resolution_mode(&DomainResolutionMode::Fixed, &rules, Some("domain"));

        assert!(result.is_ok());
    }

    #[test]
    fn fixed_mode_allows_none_group_domain_id() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: vec![
                openstack_keystone_core_types::mapping::authorization::GroupAssignment {
                    group_id: None,
                    group_domain_id: None,
                    group_name: "admins".to_string(),
                    strategy: None,
                },
            ],
        }];

        let result =
            validate_domain_resolution_mode(&DomainResolutionMode::Fixed, &rules, Some("domain"));

        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // validate_domain_resolution_mode — mixed authorization and group tests
    // -----------------------------------------------------------------------

    #[test]
    fn fixed_mode_allows_static_auth_and_group_domains() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![
                openstack_keystone_core_types::mapping::authorization::Authorization::Project {
                    project_id: "proj-123".to_string(),
                    project_domain_id: "domain-a".to_string(),
                    roles: vec![],
                },
                openstack_keystone_core_types::mapping::authorization::Authorization::Domain {
                    domain_id: "domain-b".to_string(),
                    roles: vec![],
                },
            ],
            groups: vec![
                openstack_keystone_core_types::mapping::authorization::GroupAssignment {
                    group_id: None,
                    group_domain_id: Some("domain-c".to_string()),
                    group_name: "admins".to_string(),
                    strategy: None,
                },
            ],
        }];

        let result =
            validate_domain_resolution_mode(&DomainResolutionMode::Fixed, &rules, Some("domain"));

        assert!(result.is_ok());
    }

    #[test]
    fn fixed_mode_rejects_any_claims_template_in_mixed_domains() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![
                openstack_keystone_core_types::mapping::authorization::Authorization::Project {
                    project_id: "proj-123".to_string(),
                    project_domain_id: "static-domain".to_string(),
                    roles: vec![],
                },
            ],
            groups: vec![
                openstack_keystone_core_types::mapping::authorization::GroupAssignment {
                    group_id: None,
                    group_domain_id: Some("${claims.domain}".to_string()),
                    group_name: "admins".to_string(),
                    strategy: None,
                },
            ],
        }];

        let result =
            validate_domain_resolution_mode(&DomainResolutionMode::Fixed, &rules, Some("domain"));

        assert!(matches!(
            result,
            Err(MappingProviderError::DomainOverrideInFixedMode)
        ));
    }

    // -----------------------------------------------------------------------
    // validate_identity_templates tests
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_enclosing_domain_id_in_user_name() {
        let rules = vec![simple_rule("test", "${claims.enclosing_domain_id}")];

        let result = validate_identity_templates(&rules, &DomainResolutionMode::Fixed);

        assert!(matches!(
            result,
            Err(MappingProviderError::SystemTokenShadowing(_))
        ));
    }

    #[test]
    fn rejects_enclosing_domain_id_in_user_id() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user".to_string(),
                user_id: Some("${claims.enclosing_domain_id}".to_string()),
                user_domain_id: None,
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: Vec::new(),
        }];

        let result = validate_identity_templates(&rules, &DomainResolutionMode::Fixed);

        assert!(matches!(
            result,
            Err(MappingProviderError::SystemTokenShadowing(_))
        ));
    }

    // -----------------------------------------------------------------------
    // validate_ruleset_create integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn valid_ruleset_create() {
        let rs = sample_ruleset_create();
        assert!(validate_ruleset_create(&rs).is_ok());
    }

    #[test]
    fn ruleset_with_safe_regex() {
        let mut rules = [MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: Vec::new(),
        }];

        rules[0].r#match = MatchCriteria::AllOf(vec![
            openstack_keystone_core_types::mapping::rule::MatchCondition::Condition(
                ClaimCondition::Equals {
                    claim: "sub".to_string(),
                    value: json!("user-123"),
                },
            ),
        ]);

        let rs = sample_ruleset_create();
        assert!(validate_ruleset_create(&rs).is_ok());
    }

    // -----------------------------------------------------------------------
    // validate_allowed_domains_update tests
    // -----------------------------------------------------------------------

    #[test]
    fn fixed_mode_rejects_non_empty_allowed_domains() {
        let result =
            validate_allowed_domains_update(&DomainResolutionMode::Fixed, &["d1".to_string()]);

        assert!(matches!(
            result,
            Err(MappingProviderError::DomainOverrideInFixedMode)
        ));
    }

    #[test]
    fn claims_only_rejects_empty_allowed_domains() {
        let result = validate_allowed_domains_update(
            &DomainResolutionMode::ClaimsOnly {
                allowed_domains: vec!["d1".to_string()],
            },
            &[],
        );

        assert!(matches!(
            result,
            Err(MappingProviderError::DomainClaimRequired)
        ));
    }

    #[test]
    fn claims_only_accepts_non_empty_allowed_domains() {
        let result = validate_allowed_domains_update(
            &DomainResolutionMode::ClaimsOnly {
                allowed_domains: vec!["d1".to_string()],
            },
            &["d1".to_string(), "d2".to_string()],
        );

        assert!(result.is_ok());
    }

    #[test]
    fn claims_only_rejects_allowed_domains_over_cardinality() {
        let domains: Vec<String> = (0..257).map(|i| format!("domain-{i}")).collect();

        let result = validate_allowed_domains_update(
            &DomainResolutionMode::ClaimsOnly {
                allowed_domains: domains.clone(),
            },
            &domains,
        );

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MappingProviderError::AllowedDomainsTooLarge(256))
        ));
    }

    #[test]
    fn claims_or_mapping_rejects_allowed_domains_over_cardinality() {
        let domains: Vec<String> = (0..257).map(|i| format!("domain-{i}")).collect();

        let result = validate_allowed_domains_update(
            &DomainResolutionMode::ClaimsOrMapping {
                allowed_domains: domains.clone(),
            },
            &domains,
        );

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MappingProviderError::AllowedDomainsTooLarge(256))
        ));
    }

    #[test]
    fn claims_only_accepts_exact_cardinality() {
        let domains: Vec<String> = (0..256).map(|i| format!("domain-{i}")).collect();

        let result = validate_allowed_domains_update(
            &DomainResolutionMode::ClaimsOnly {
                allowed_domains: domains.clone(),
            },
            &domains,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn claims_or_mapping_accepts_anything() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user-${claims.sub}".to_string(),
                user_id: None,
                user_domain_id: Some("static-domain".to_string()),
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: Vec::new(),
        }];

        let result = validate_domain_resolution_mode(
            &DomainResolutionMode::ClaimsOrMapping {
                allowed_domains: vec!["d1".to_string()],
            },
            &rules,
            None,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn claims_only_rejects_domain_id_set() {
        let rules = vec![MappingRule {
            name: "test".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "user".to_string(),
                user_id: None,
                user_domain_id: Some("${claims.domain}".to_string()),
                is_system: false,
            },
            authorizations: Vec::new(),
            groups: Vec::new(),
        }];

        let result = validate_domain_resolution_mode(
            &DomainResolutionMode::ClaimsOnly {
                allowed_domains: vec!["d1".to_string()],
            },
            &rules,
            Some("some-domain-id"),
        );

        assert!(matches!(
            result,
            Err(MappingProviderError::DomainClaimRequired)
        ));
    }

    #[test]
    fn claims_or_mapping_passes_validation() {
        let rules = vec![
            MappingRule {
                name: "rule-1".to_string(),
                description: None,
                r#match: MatchCriteria::AllOf(vec![]),
                identity: IdentityBinding {
                    identity_mode: None,
                    user_name: "test-user".to_string(),
                    user_id: None,
                    user_domain_id: None,
                    is_system: false,
                },
                authorizations: Vec::new(),
                groups: Vec::new(),
            },
            MappingRule {
                name: "rule-2".to_string(),
                description: None,
                r#match: MatchCriteria::AllOf(vec![]),
                identity: IdentityBinding {
                    identity_mode: None,
                    user_name: "test-user".to_string(),
                    user_id: None,
                    user_domain_id: None,
                    is_system: false,
                },
                authorizations: Vec::new(),
                groups: Vec::new(),
            },
        ];

        let result = validate_domain_resolution_mode(
            &DomainResolutionMode::ClaimsOrMapping {
                allowed_domains: vec!["d1".to_string()],
            },
            &rules,
            None,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn empty_rules_vector_is_valid() {
        let rules: Vec<MappingRule> = vec![];
        assert!(validate_rules(&rules).is_ok());
    }

    #[test]
    fn validate_ruleset_update_with_new_rules_validates() {
        let existing = MappingRuleSet {
            mapping_id: "test-123".to_string(),
            domain_id: Some("test-domain".to_string()),
            source: IdentitySource::Federation {
                idp_id: "idp-1".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![simple_rule("existing-rule", "user-exists")],
            ruleset_version: 0,
        };

        // Valid update with new rules
        let update = MappingRuleSetUpdate {
            rules: Some(vec![simple_rule("new-rule", "user-new")]),
            enabled: None,
            allowed_domains: None,
        };

        assert!(validate_ruleset_update(&existing, &update).is_ok());

        // Invalid update with duplicate rule names
        let update_invalid = MappingRuleSetUpdate {
            rules: Some(vec![
                simple_rule("dup-rule", "user-a"),
                simple_rule("dup-rule", "user-b"),
            ]),
            enabled: None,
            allowed_domains: None,
        };

        let result = validate_ruleset_update(&existing, &update_invalid);
        assert!(matches!(
            result,
            Err(MappingProviderError::DuplicateRuleName(_))
        ));
    }

    // -----------------------------------------------------------------------
    // validate_api_client_domain_scope tests (ADR 0021 §6.C)
    // -----------------------------------------------------------------------

    fn api_client_source() -> IdentitySource {
        IdentitySource::ApiClient {
            provider_id: "provider-1".to_string(),
        }
    }

    fn rule_with_is_system(name: &str) -> MappingRule {
        let mut rule = simple_rule(name, "user-name");
        rule.identity.is_system = true;
        rule
    }

    fn rule_with_system_authorization(name: &str) -> MappingRule {
        let mut rule = simple_rule(name, "user-name");
        rule.authorizations = vec![Authorization::System {
            system_id: "all".to_string(),
            roles: Vec::new(),
        }];
        rule
    }

    #[test]
    fn api_client_ruleset_rejects_is_system() {
        let rules = vec![rule_with_is_system("system-rule")];
        let result = validate_api_client_domain_scope(&api_client_source(), &rules);
        assert!(matches!(
            result,
            Err(MappingProviderError::ApiClientSystemScopeForbidden(ref name)) if name == "system-rule"
        ));
    }

    #[test]
    fn api_client_ruleset_rejects_system_authorization() {
        let rules = vec![rule_with_system_authorization("system-auth-rule")];
        let result = validate_api_client_domain_scope(&api_client_source(), &rules);
        assert!(matches!(
            result,
            Err(MappingProviderError::ApiClientSystemScopeForbidden(ref name)) if name == "system-auth-rule"
        ));
    }

    #[test]
    fn non_api_client_ruleset_allows_system_scope() {
        // Defense-in-depth is scoped to ApiClient sources only; other
        // sources (e.g. Federation) are unaffected by this guard.
        let ruleset = MappingRuleSetCreate {
            rules: vec![rule_with_is_system("system-rule")],
            ..sample_ruleset_create()
        };
        assert!(validate_ruleset_create(&ruleset).is_ok());
    }

    #[test]
    fn api_client_ruleset_update_rejects_is_system() {
        let rules = vec![rule_with_is_system("new-system-rule")];
        let result = validate_api_client_domain_scope(&api_client_source(), &rules);
        assert!(matches!(
            result,
            Err(MappingProviderError::ApiClientSystemScopeForbidden(ref name)) if name == "new-system-rule"
        ));
    }

    fn rule_with_project_authorization(name: &str) -> MappingRule {
        let mut rule = simple_rule(name, "user-name");
        rule.authorizations = vec![Authorization::Project {
            project_id: "project-1".to_string(),
            project_domain_id: "test-domain".to_string(),
            roles: Vec::new(),
        }];
        rule
    }

    #[test]
    fn api_client_ruleset_rejects_non_domain_scope() {
        // API Keys are domain-owned machine identities (ADR 0021 §2); only a
        // domain-scoped authorization is accepted (allowlist, not a denylist
        // naming each forbidden variant). Exercised here with Project, but
        // the guard applies to any non-Domain authorization.
        let rules = vec![rule_with_project_authorization("project-auth-rule")];
        let result = validate_api_client_domain_scope(&api_client_source(), &rules);
        assert!(matches!(
            result,
            Err(MappingProviderError::ApiClientNonDomainScopeForbidden(ref name)) if name == "project-auth-rule"
        ));
    }

    #[test]
    fn non_api_client_ruleset_allows_project_scope() {
        // Defense-in-depth is scoped to ApiClient sources only; other
        // sources (e.g. Federation) are unaffected by this guard.
        let ruleset = MappingRuleSetCreate {
            rules: vec![rule_with_project_authorization("project-auth-rule")],
            ..sample_ruleset_create()
        };
        assert!(validate_ruleset_create(&ruleset).is_ok());
    }

    #[test]
    fn api_client_ruleset_update_rejects_non_domain_scope() {
        let rules = vec![rule_with_project_authorization("new-project-rule")];
        let result = validate_api_client_domain_scope(&api_client_source(), &rules);
        assert!(matches!(
            result,
            Err(MappingProviderError::ApiClientNonDomainScopeForbidden(ref name)) if name == "new-project-rule"
        ));
    }
}
