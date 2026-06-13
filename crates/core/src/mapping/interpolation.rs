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
//! Template interpolation for mapping rules.
//!
//! Resolves template strings like `${claims.preferred_username}` and
//! `${enclosing_domain_id}` against a claims map and enclosing ruleset domain.

use std::collections::HashMap;

use crate::mapping::error::MappingProviderError;

/// Maximum length of an interpolated result string.
///
/// Per ADR §5.4, interpolated values exceeding this limit are rejected to
/// prevent runaway template expansion and memory pressure.
#[allow(dead_code)]
const MAX_INTERPOLATED_LEN: usize = 256;

/// Reserved claim keys that must not appear in templates.
///
/// The key `enclosing_domain_id` is handled specially by the engine and
/// references the ruleset's domain context, not a user claim. Templates
/// referencing it can shadow domain context boundaries.
#[allow(dead_code)]
const RESERVED_KEYS: &[&str] = &["enclosing_domain_id"];

/// Resolve all template tokens in a single string against a claims map.
///
/// Template syntax:
/// - `${claims.<key>}` — look up `<key>` in the claims map; use the first value
///   if the claim resolves to a list.
/// - `${enclosing_domain_id}` — replace with the ruleset's enclosing domain ID.
///
/// Unresolved tokens (claim key not present in claims map) leave the original
/// token intact in the output string.
///
/// # Parameters
/// - `template`: Template string to evaluate.
/// - `claims`: Flattened claims map from the ingress adapter.
/// - `domain_id`: Enclosing ruleset domain ID for `${enclosing_domain_id}`.
///
/// # Returns
/// Resolved string, or `MappingProviderError` if:
/// - A reserved key is referenced in `${claims.<key>}` syntax.
/// - The resolved string exceeds `MAX_INTERPOLATED_LEN` characters.
#[allow(dead_code)]
pub fn interpolate(
    template: &str,
    claims: &HashMap<String, Vec<String>>,
    domain_id: &str,
) -> Result<String, MappingProviderError> {
    let mut result = String::with_capacity(template.len().min(MAX_INTERPOLATED_LEN));
    let mut chars = template.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'

            // Collect token until we find closing '}'
            let mut token = String::new();
            let mut found_close = false;
            for ch in chars.by_ref() {
                if ch == '}' {
                    found_close = true;
                    break;
                }
                token.push(ch);
            }

            if !found_close {
                // No closing brace found — treat as literal
                result.push('$');
                result.push('{');
                result.push_str(&token);
                continue;
            }

            let resolved = resolve_token(&token, claims, domain_id)?;
            result.push_str(&resolved);

            // Check length limit incrementally
            if result.len() > MAX_INTERPOLATED_LEN {
                return Err(MappingProviderError::InterpolatedValueTooLong);
            }
        } else {
            result.push(c);
        }
    }

    if result.len() > MAX_INTERPOLATED_LEN {
        return Err(MappingProviderError::InterpolatedValueTooLong);
    }

    Ok(result)
}

/// Resolve a single token (the content between `${` and `}`).
///
/// # Parameters
/// - `token`: Token string inside `${...}`.
/// - `claims`: Claims map.
/// - `_domain_id`: Enclosing domain ID (unused by this function).
///
/// # Returns
/// Resolved value string. Unresolved claim keys return the original token
/// `${key}` unchanged (deferred to runtime).
fn resolve_token(
    token: &str,
    claims: &HashMap<String, Vec<String>>,
    domain_id: &str,
) -> Result<String, MappingProviderError> {
    if let Some(key) = token.strip_prefix("claims.") {
        // Check for reserved keys that could shadow domain context
        if RESERVED_KEYS.contains(&key) {
            return Err(MappingProviderError::SystemTokenShadowing(key.to_string()));
        }

        // Look up in claims; if not found, return unresolved token
        match claims.get(key) {
            Some(values) if !values.is_empty() => {
                // Use the first value for claims that resolve to a list
                Ok(values[0].clone())
            }
            Some(_) => {
                // Claim exists but is empty — return empty string
                Ok(String::new())
            }
            None => {
                // Claim not present in the map — return unresolved token
                // This will be caught at runtime if the claim is required
                Ok(format!("${{{token}}}"))
            }
        }
    } else if token == "enclosing_domain_id" {
        // Direct access to enclosing_domain_id resolves to domain_id
        Ok(domain_id.to_string())
    } else {
        // Unknown token syntax — return unresolved
        Ok(format!("${{{token}}}"))
    }
}

/// Check if a template string contains any `${claims.<key>}` interpolation
/// tokens.
///
/// # Parameters
/// - `template`: Template string to inspect.
///
/// # Returns
/// `true` if the template contains at least one `${claims.<key>}` token.
pub fn contains_claims_template(template: &str) -> bool {
    let mut chars = template.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut token = String::new();
            let mut found_close = false;

            for ch in chars.by_ref() {
                if ch == '}' {
                    found_close = true;
                    break;
                }
                token.push(ch);
            }

            if found_close && token.starts_with("claims.") {
                return true;
            }
        }
    }

    false
}

/// Extract all `${claims.<key>}` token names from a template string.
///
/// Useful for validation to verify that all referenced claim keys exist in
/// a given claims map, or to detect reserved key usage early.
///
/// # Parameters
/// - `template`: Template string to inspect.
///
/// # Returns
/// Vec of claim key names found in the template.
pub fn extract_claims_keys(template: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut chars = template.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut token = String::new();
            let mut found_close = false;

            for ch in chars.by_ref() {
                if ch == '}' {
                    found_close = true;
                    break;
                }
                token.push(ch);
            }

            if found_close && let Some(key) = token.strip_prefix("claims.") {
                keys.push(key.to_string());
            }
        }
    }

    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_claims() -> HashMap<String, Vec<String>> {
        let mut claims = HashMap::new();
        claims.insert("sub".to_string(), vec!["user-123".to_string()]);
        claims.insert(
            "preferred_username".to_string(),
            vec!["johndoe".to_string()],
        );
        claims.insert(
            "groups".to_string(),
            vec!["HR-Team".to_string(), "Engineering".to_string()],
        );
        claims
    }

    #[test]
    fn resolves_simple_claim() {
        let claims = test_claims();
        let result = interpolate("${claims.sub}", &claims, "default-domain").unwrap();
        assert_eq!(result, "user-123");
    }

    #[test]
    fn resolves_multiple_claims() {
        let claims = test_claims();
        let result = interpolate(
            "user-${claims.sub}@${claims.preferred_username}",
            &claims,
            "default-domain",
        )
        .unwrap();
        assert_eq!(result, "user-user-123@johndoe");
    }

    #[test]
    fn resolves_enclosing_domain() {
        let claims = test_claims();
        let result = interpolate(
            "${claims.sub}@${enclosing_domain_id}",
            &claims,
            "admin-domain",
        )
        .unwrap();
        assert_eq!(result, "user-123@admin-domain");
    }

    #[test]
    fn rejects_reserved_key_in_claims() {
        let claims = test_claims();
        let result = interpolate("${claims.enclosing_domain_id}", &claims, "default-domain");
        assert!(matches!(
            result,
            Err(MappingProviderError::SystemTokenShadowing(_))
        ));
    }

    #[test]
    fn rejects_reserved_key_direct() {
        let claims = test_claims();
        let result = interpolate("${enclosing_domain_id}", &claims, "default-domain");
        // Direct access is resolved, not shadowed
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "default-domain");
    }

    #[test]
    fn unresolved_claim_returns_literal() {
        let claims = test_claims();
        let result = interpolate("${claims.nonexistent}", &claims, "default-domain").unwrap();
        assert_eq!(result, "${claims.nonexistent}");
    }

    #[test]
    fn exceeds_max_length() {
        let _claims = test_claims();
        // Build a template that will exceed 256 chars when resolved
        let long_claim = "a".repeat(200);
        let mut extended_claims = test_claims();
        extended_claims.insert("long".to_string(), vec![long_claim]);

        // "prefix" + 200 + "suffix" + 200 > 256
        let template = format!("${{claims.long}}prefix{}${{claims.long}}", "b".repeat(60));
        let result = interpolate(&template, &extended_claims, "default-domain");

        // The interpolated result exceeds limit
        assert!(matches!(
            result,
            Err(MappingProviderError::InterpolatedValueTooLong)
        ));
    }

    #[test]
    fn plain_string_no_tokens() {
        let claims = test_claims();
        let result = interpolate("plain string", &claims, "default-domain").unwrap();
        assert_eq!(result, "plain string");
    }

    #[test]
    fn incomplete_token_left_as_literal() {
        let claims = test_claims();
        let result = interpolate("${claims.sub", &claims, "default-domain").unwrap();
        assert_eq!(result, "${claims.sub");
    }

    #[test]
    fn uses_first_value_for_list_claim() {
        let claims = test_claims();
        let result = interpolate("${claims.groups}", &claims, "default-domain").unwrap();
        assert_eq!(result, "HR-Team");
    }

    // -----------------------------------------------------------------------
    // contains_claims_template tests
    // -----------------------------------------------------------------------

    #[test]
    fn detects_claims_template() {
        assert!(contains_claims_template("${claims.sub}"));
        assert!(contains_claims_template("prefix-${claims.sub}-suffix"));
        assert!(!contains_claims_template("no template here"));
        assert!(!contains_claims_template("${enclosing_domain_id}"));
    }

    #[test]
    fn detects_multiple_templates() {
        assert!(contains_claims_template(
            "${claims.sub}-${claims.preferred_username}"
        ));
    }

    // -----------------------------------------------------------------------
    // extract_claims_keys tests
    // -----------------------------------------------------------------------

    #[test]
    fn extracts_single_key() {
        let keys = extract_claims_keys("${claims.sub}");
        assert_eq!(keys, vec!["sub"]);
    }

    #[test]
    fn extracts_multiple_keys() {
        let keys = extract_claims_keys("${claims.sub}-${claims.preferred_username}");
        assert_eq!(keys, vec!["sub", "preferred_username"]);
    }

    #[test]
    fn ignores_non_claims_tokens() {
        let keys = extract_claims_keys("${enclosing_domain_id}-${claims.sub}-${unknown}");
        assert_eq!(keys, vec!["sub"]);
    }

    #[test]
    fn no_keys_found() {
        let keys = extract_claims_keys("no templates");
        assert!(keys.is_empty());
    }

    #[test]
    fn test_empty_claim_value_returns_empty_string() {
        let mut claims = HashMap::new();
        claims.insert("empty_claim".to_string(), vec![]);
        let result = interpolate("${claims.empty_claim}", &claims, "default-domain").unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_unknown_token_returns_literal() {
        let claims = test_claims();
        let result = interpolate("${some.unknown.token}", &claims, "default-domain").unwrap();
        assert_eq!(result, "${some.unknown.token}");
    }

    #[test]
    fn test_multiple_unresolved_tokens() {
        let claims = test_claims();
        let result = interpolate(
            "${claims.a}-${claims.b}-${claims.c}",
            &claims,
            "default-domain",
        )
        .unwrap();
        assert_eq!(result, "${claims.a}-${claims.b}-${claims.c}");
    }

    #[test]
    fn test_claim_value_with_dollar_signs() {
        let mut claims = HashMap::new();
        claims.insert(
            "dollar_claim".to_string(),
            vec!["prefix${claims.fake}suffix".to_string()],
        );
        let result = interpolate("${claims.dollar_claim}", &claims, "default-domain").unwrap();
        assert_eq!(result, "prefix${claims.fake}suffix");
    }
}
