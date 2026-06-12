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
//! Content-aware ruleset version computation.
//!
//! Per ADR §5.4, the `ruleset_version` is a SHA-256 hash (first 16 bytes,
//! interpreted as u128) of the canonical serialized ruleset. This detects
//! reordering, renaming, authorization swaps, and any content change — not
//! just addition/deletion of rules.

use sha2::{Digest, Sha256};

use crate::mapping::ruleset::MappingRuleSetCreate;

/// Compute a content-aware version hash for a ruleset.
///
/// The ruleset is serialized to canonical JSON (sorted keys), then hashed
/// with SHA-256. The first 16 bytes of the digest are reinterpreted as a
/// `u128` value.
///
/// # Parameters
/// - `ruleset`: Ruleset creation data to hash.
///
/// # Returns
/// `u128` value representing the content hash of the ruleset.
pub fn compute_ruleset_version(ruleset: &MappingRuleSetCreate) -> u128 {
    // Serialize to canonical JSON with sorted keys for deterministic hashing
    let serialized =
        serde_json::to_string(ruleset).expect("ruleset serialization should never fail");
    let hash = Sha256::digest(serialized.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    u128::from_be_bytes(bytes)
}

/// Compute a content-aware version hash for an existing ruleset.
///
/// Same as [`compute_ruleset_version`] but operates on the stored
/// `MappingRuleSet` type (which includes `mapping_id` and `ruleset_version`).
/// The `ruleset_version` field is excluded from the hash to avoid circular
/// dependency.
///
/// # Parameters
/// - `mapping_id`: Ruleset identifier.
/// - `domain_id`: Owned domain ID.
/// - `source`: Identity source.
/// - `domain_resolution_mode`: Domain resolution mode.
/// - `enabled`: Whether the ruleset is enabled.
/// - `rules`: Rules vector.
///
/// # Returns
/// `u128` value representing the content hash.
pub fn compute_ruleset_version_from_parts(
    mapping_id: &str,
    domain_id: Option<&str>,
    source: &crate::mapping::resolution::IdentitySource,
    domain_resolution_mode: &crate::mapping::resolution::DomainResolutionMode,
    enabled: bool,
    rules: &[crate::mapping::rule::MappingRule],
) -> u128 {
    let payload = serde_json::json!({
        "mapping_id": mapping_id,
        "domain_id": domain_id,
        "source": source,
        "domain_resolution_mode": domain_resolution_mode,
        "enabled": enabled,
        "rules": rules,
    });
    let hash = Sha256::digest(payload.to_string().as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    u128::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::resolution::DomainResolutionMode;
    use crate::mapping::resolution::IdentitySource;
    use crate::mapping::rule::ClaimCondition;
    use crate::mapping::rule::IdentityBinding;
    use crate::mapping::rule::MappingRule;
    use crate::mapping::rule::MatchCondition;
    use crate::mapping::rule::MatchCriteria;
    use serde_json::json;

    fn sample_ruleset_create() -> MappingRuleSetCreate {
        let rules = vec![MappingRule {
            name: "test-rule".to_string(),
            description: Some("test description".to_string()),
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::Equals {
                    claim: "sub".to_string(),
                    value: json!("user-123"),
                },
            )]),
            identity: IdentityBinding {
                user_name: "${claims.sub}".to_string(),
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

    #[test]
    fn version_is_deterministic() {
        let ruleset = sample_ruleset_create();
        let v1 = compute_ruleset_version(&ruleset);
        let v2 = compute_ruleset_version(&ruleset);
        assert_eq!(v1, v2);
    }

    #[test]
    fn version_changes_when_rules_change() {
        let ruleset1 = sample_ruleset_create();
        let v1 = compute_ruleset_version(&ruleset1);

        let mut ruleset2 = sample_ruleset_create();
        ruleset2.rules[0].name = "different-name".to_string();
        let v2 = compute_ruleset_version(&ruleset2);

        assert_ne!(v1, v2);
    }

    #[test]
    fn version_changes_when_rule_order_changes() {
        let rules1 = vec![
            MappingRule {
                name: "rule-a".to_string(),
                description: None,
                r#match: MatchCriteria::AllOf(vec![]),
                identity: IdentityBinding {
                    user_name: "a".to_string(),
                    user_id: None,
                    user_domain_id: None,
                    is_system: false,
                },
                authorizations: Vec::new(),
                groups: Vec::new(),
            },
            MappingRule {
                name: "rule-b".to_string(),
                description: None,
                r#match: MatchCriteria::AllOf(vec![]),
                identity: IdentityBinding {
                    user_name: "b".to_string(),
                    user_id: None,
                    user_domain_id: None,
                    is_system: false,
                },
                authorizations: Vec::new(),
                groups: Vec::new(),
            },
        ];

        let rules2 = vec![rules1[1].clone(), rules1[0].clone()];

        let rs1 = MappingRuleSetCreate {
            rules: rules1,
            ..sample_ruleset_create()
        };
        let rs2 = MappingRuleSetCreate {
            rules: rules2,
            ..sample_ruleset_create()
        };

        let v1 = compute_ruleset_version(&rs1);
        let v2 = compute_ruleset_version(&rs2);
        assert_ne!(v1, v2);
    }

    #[test]
    fn version_is_nonzero() {
        let ruleset = sample_ruleset_create();
        let v = compute_ruleset_version(&ruleset);
        assert!(v > 0);
    }

    #[test]
    fn version_changes_when_enabled_flips() {
        let mut rs = sample_ruleset_create();
        let v1 = compute_ruleset_version(&rs);

        rs.enabled = false;
        let v2 = compute_ruleset_version(&rs);

        assert_ne!(v1, v2);
    }
}
