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
//! # Mapping provider

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::mapping::*;

use crate::keystone::ServiceState;
use crate::mapping::{
    MappingApi, MappingProviderError, backend::MappingBackend, validation, version,
};
use crate::plugin_manager::PluginManagerApi;

/// Mapping Provider service.
pub struct MappingService {
    /// Backend driver.
    pub(super) backend_driver: Arc<dyn MappingBackend>,
}

impl MappingService {
    /// Create a new `MappingService`.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, MappingProviderError> {
        let backend_driver = plugin_manager
            .get_mapping_backend(config.mapping.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }

    /// Create a `MappingService` from a backend driver.
    ///
    /// # Parameters
    /// - `driver`: The backend driver.
    #[cfg(any(test, feature = "mock"))]
    pub fn from_driver<I: MappingBackend + 'static>(driver: I) -> Self {
        Self {
            backend_driver: Arc::new(driver),
        }
    }
}

#[async_trait]
impl MappingApi for MappingService {
    /// Create a mapping ruleset.
    ///
    /// Validates the payload, generates UUID, computes content-aware version,
    /// then delegates to the backend driver.
    async fn create_ruleset(
        &self,
        state: &ServiceState,
        mut ruleset: MappingRuleSetCreate,
    ) -> Result<MappingRuleSet, MappingProviderError> {
        // 1. Write-time validation
        validation::validate_ruleset_create(&ruleset)?;

        // 2. Generate UUID if not provided
        let mapping_id = ruleset
            .mapping_id
            .take()
            .unwrap_or(Uuid::new_v4().simple().to_string());

        // 3. Compute content-aware ruleset version
        let ruleset_version = version::compute_ruleset_version(&ruleset);

        // 4. Build the ruleset object for backend storage
        let ruleset_obj = MappingRuleSet {
            mapping_id: mapping_id.clone(),
            domain_id: ruleset.domain_id,
            source: ruleset.source,
            domain_resolution_mode: ruleset.domain_resolution_mode,
            enabled: ruleset.enabled,
            rules: ruleset.rules,
            ruleset_version,
        };

        // 5. Delegate to backend
        let created = self
            .backend_driver
            .create_ruleset(state, ruleset_obj)
            .await?;

        // 6. Return the created ruleset
        Ok(MappingRuleSet {
            mapping_id: mapping_id.clone(),
            domain_id: created.domain_id,
            source: created.source,
            domain_resolution_mode: created.domain_resolution_mode,
            enabled: created.enabled,
            rules: created.rules,
            ruleset_version: created.ruleset_version,
        })
    }

    /// Delete a mapping ruleset.
    async fn delete_ruleset<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
    ) -> Result<(), MappingProviderError> {
        // Check immutability: if ruleset contains `is_system` rules, reject
        if let Some(existing) = self.backend_driver.get_ruleset(state, mapping_id).await?
            && existing.rules.iter().any(|r| r.identity.is_system)
        {
            return Err(MappingProviderError::RulesetImmutable(
                mapping_id.to_string(),
            ));
        }

        self.backend_driver.delete_ruleset(state, mapping_id).await
    }

    /// Delete a virtual user shadow record.
    async fn delete_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), MappingProviderError> {
        self.backend_driver
            .delete_virtual_user(state, user_id)
            .await
    }

    /// Fetch a mapping ruleset by ID.
    async fn get_ruleset<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
    ) -> Result<Option<MappingRuleSet>, MappingProviderError> {
        self.backend_driver.get_ruleset(state, mapping_id).await
    }

    /// Fetch a virtual user shadow record by user ID.
    async fn get_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<VirtualUser>, MappingProviderError> {
        self.backend_driver.get_virtual_user(state, user_id).await
    }

    /// List mapping rulesets.
    async fn list_rulesets(
        &self,
        state: &ServiceState,
        params: &MappingRuleSetListParameters,
    ) -> Result<Vec<MappingRuleSet>, MappingProviderError> {
        self.backend_driver.list_rulesets(state, params).await
    }

    /// Mutate rules within a mapping ruleset imperatively.
    ///
    /// Fetches the current ruleset, validates immutability, applies mutations
    /// in memory, re-validates, computes new version, then delegates update.
    async fn mutate_rules<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
        mutations: RuleMutations,
    ) -> Result<MappingRuleSet, MappingProviderError> {
        // 1. Fetch current ruleset
        let existing = self
            .backend_driver
            .get_ruleset(state, mapping_id)
            .await?
            .ok_or_else(|| MappingProviderError::NotFound(mapping_id.to_string()))?;

        // 2. Check immutability for system mappings
        if existing.rules.iter().any(|r| r.identity.is_system) {
            return Err(MappingProviderError::RulesetImmutable(
                mapping_id.to_string(),
            ));
        }

        // 3. Apply mutations in memory
        let mut new_rules: Vec<MappingRule> = existing.rules.clone();
        for mut mutation in mutations.mutations {
            match &mut mutation {
                RuleMutation::Insert { rule, position } => {
                    match position {
                        Some(RulePosition::Before { anchor }) => {
                            let idx = new_rules
                                .iter()
                                .position(|r| r.name == *anchor)
                                .ok_or_else(|| {
                                    MappingProviderError::Conflict(format!(
                                        "anchor rule '{}' not found",
                                        anchor
                                    ))
                                })?;
                            new_rules.insert(idx, rule.clone());
                        }
                        Some(RulePosition::After { anchor }) => {
                            let idx = new_rules
                                .iter()
                                .position(|r| r.name == *anchor)
                                .ok_or_else(|| {
                                    MappingProviderError::Conflict(format!(
                                        "anchor rule '{}' not found",
                                        anchor
                                    ))
                                })?;
                            new_rules.insert(idx + 1, rule.clone());
                        }
                        None => {
                            // No position — append to end
                            new_rules.push(rule.clone());
                        }
                    }
                }
                RuleMutation::Update { rule_name, rule } => {
                    let idx = new_rules
                        .iter()
                        .position(|r| r.name == *rule_name)
                        .ok_or_else(|| {
                            MappingProviderError::Conflict(format!(
                                "rule '{}' not found",
                                rule_name
                            ))
                        })?;
                    new_rules[idx] = rule.clone();
                }
                RuleMutation::Delete { rule_name } => {
                    let found = new_rules
                        .iter()
                        .position(|r| r.name == *rule_name)
                        .ok_or_else(|| {
                            MappingProviderError::Conflict(format!(
                                "rule '{}' not found",
                                rule_name
                            ))
                        })?;
                    new_rules.remove(found);
                }
            }
        }

        // 4. Re-validate the resulting ruleset
        let create_payload = MappingRuleSetCreate {
            mapping_id: Some(existing.mapping_id.clone()),
            domain_id: existing.domain_id.clone(),
            source: existing.source.clone(),
            domain_resolution_mode: existing.domain_resolution_mode.clone(),
            enabled: existing.enabled,
            rules: new_rules.clone(),
        };
        validation::validate_ruleset_create(&create_payload)?;

        // 5. Compute new version
        let new_version = version::compute_ruleset_version(&create_payload);

        // 6. Delegate update to backend
        let update_payload = MappingRuleSetUpdate {
            enabled: Some(existing.enabled),
            allowed_domains: None,
            rules: Some(new_rules),
        };

        let updated = self
            .backend_driver
            .update_ruleset(state, mapping_id, update_payload)
            .await?;

        // 7. Return with new version
        Ok(MappingRuleSet {
            mapping_id: existing.mapping_id.clone(),
            domain_id: updated.domain_id,
            source: updated.source,
            domain_resolution_mode: updated.domain_resolution_mode,
            enabled: updated.enabled,
            rules: updated.rules,
            ruleset_version: new_version,
        })
    }

    /// Update a mapping ruleset.
    ///
    /// Validates the update payload against the existing ruleset, computes
    /// new version, then delegates to the backend driver.
    async fn update_ruleset<'a>(
        &self,
        state: &ServiceState,
        mapping_id: &'a str,
        data: MappingRuleSetUpdate,
    ) -> Result<MappingRuleSet, MappingProviderError> {
        // 1. Fetch existing ruleset
        let existing = self
            .backend_driver
            .get_ruleset(state, mapping_id)
            .await?
            .ok_or_else(|| MappingProviderError::NotFound(mapping_id.to_string()))?;

        // 2. Check immutability: reject update if ruleset contains `is_system` rules
        if existing.rules.iter().any(|r| r.identity.is_system) {
            return Err(MappingProviderError::RulesetImmutable(
                mapping_id.to_string(),
            ));
        }

        // 3. Validate update
        validation::validate_ruleset_update(&existing, &data)?;

        // 4. Compute merged ruleset for version calculation
        let merged_rules = data.rules.clone().unwrap_or(existing.rules.clone());
        let new_version = version::compute_ruleset_version_from_parts(
            &existing.mapping_id,
            existing.domain_id.as_deref(),
            &existing.source,
            &existing.domain_resolution_mode,
            existing.enabled,
            &merged_rules,
        );

        // 5. Delegate to backend
        let updated = self
            .backend_driver
            .update_ruleset(state, mapping_id, data)
            .await?;

        // 6. Return with updated version
        Ok(MappingRuleSet {
            mapping_id: existing.mapping_id.clone(),
            domain_id: updated.domain_id,
            source: updated.source,
            domain_resolution_mode: updated.domain_resolution_mode,
            enabled: updated.enabled,
            rules: updated.rules,
            ruleset_version: new_version,
        })
    }

    /// Disable a virtual user shadow record.
    async fn disable_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<VirtualUser, MappingProviderError> {
        self.backend_driver
            .disable_virtual_user(state, user_id)
            .await
    }

    /// Enable (reactivate) a virtual user shadow record.
    async fn enable_virtual_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<VirtualUser, MappingProviderError> {
        self.backend_driver
            .enable_virtual_user(state, user_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::backend::MockMappingBackend;
    use crate::tests::get_mocked_state;

    #[tokio::test]
    async fn test_get_ruleset() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let mapping_id = "test-id";

        let expected_ruleset = MappingRuleSet {
            mapping_id: mapping_id.to_string(),
            domain_id: None,
            source: IdentitySource::Federation {
                idp_id: "test-idp".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![],
            ruleset_version: 1,
        };

        let expected_ruleset_clone = expected_ruleset.clone();
        mock_backend
            .expect_get_ruleset()
            .withf(move |_, id| id == "test-id")
            .returning(move |_, _| Ok(Some(expected_ruleset_clone.clone())));

        let service = MappingService::from_driver(mock_backend);

        let result = service.get_ruleset(&state, mapping_id).await.unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().mapping_id, "test-id");
    }

    #[tokio::test]
    async fn test_create_ruleset() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;

        let ruleset_create = MappingRuleSetCreate {
            mapping_id: None,
            domain_id: None,
            source: IdentitySource::Federation {
                idp_id: "test-idp".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![],
        };

        let expected_ruleset = MappingRuleSet {
            mapping_id: "generated-id".to_string(),
            domain_id: None,
            source: ruleset_create.source.clone(),
            domain_resolution_mode: ruleset_create.domain_resolution_mode.clone(),
            enabled: ruleset_create.enabled,
            rules: ruleset_create.rules.clone(),
            ruleset_version: 1,
        };

        let expected_ruleset_clone = expected_ruleset.clone();
        mock_backend
            .expect_create_ruleset()
            .returning(move |_, _| Ok(expected_ruleset_clone.clone()));

        let service = MappingService::from_driver(mock_backend);

        let result = service
            .create_ruleset(&state, ruleset_create)
            .await
            .unwrap();

        assert_eq!(
            result.source,
            IdentitySource::Federation {
                idp_id: "test-idp".to_string()
            }
        );
    }

    #[tokio::test]
    async fn test_delete_ruleset() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let mapping_id = "test-id";

        mock_backend
            .expect_get_ruleset()
            .withf(move |_, id| id == "test-id")
            .returning(move |_, _| {
                Ok(Some(MappingRuleSet {
                    mapping_id: "test-id".to_string(),
                    domain_id: None,
                    source: IdentitySource::Federation {
                        idp_id: "test-idp".to_string(),
                    },
                    domain_resolution_mode: DomainResolutionMode::Fixed,
                    enabled: true,
                    rules: vec![],
                    ruleset_version: 1,
                }))
            });

        mock_backend
            .expect_delete_ruleset()
            .withf(move |_, id| id == "test-id")
            .returning(|_, _| Ok(()));

        let service = MappingService::from_driver(mock_backend);

        service.delete_ruleset(&state, mapping_id).await.unwrap();
    }

    fn make_ruleset(mapping_id: &str, is_system: bool) -> MappingRuleSet {
        MappingRuleSet {
            mapping_id: mapping_id.to_string(),
            domain_id: None,
            source: IdentitySource::Federation {
                idp_id: "test-idp".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![MappingRule {
                name: "test-rule".to_string(),
                description: None,
                r#match: MatchCriteria::AllOf(vec![]),
                identity: IdentityBinding {
                    user_name: "test".to_string(),
                    user_id: None,
                    user_domain_id: None,
                    is_system,
                },
                authorizations: vec![],
                groups: vec![],
            }],
            ruleset_version: 1,
        }
    }

    fn make_virtual_user(user_id: &str) -> VirtualUser {
        VirtualUser {
            user_id: user_id.to_string(),
            unique_workload_id: "workload-1".to_string(),
            mapping_id: "test-id".to_string(),
            matched_rule_name: "test-rule".to_string(),
            domain_id: None,
            resolved_user_name: "test".to_string(),
            is_system: false,
            resolved_group_bindings: vec![],
            authorizations: vec![],
            ruleset_version: 1,
            enabled: true,
            created_at: 0,
            last_authenticated_at: 0,
        }
    }

    #[tokio::test]
    async fn test_delete_virtual_user() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let user_id = "user-1";

        mock_backend
            .expect_delete_virtual_user()
            .withf(move |_, id| id == "user-1")
            .returning(|_, _| Ok(()));

        let service = MappingService::from_driver(mock_backend);

        service.delete_virtual_user(&state, user_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_virtual_user() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let user_id = "user-1";

        let expected_vu = make_virtual_user(user_id);
        let expected_vu_clone = expected_vu.clone();
        mock_backend
            .expect_get_virtual_user()
            .withf(move |_, id| id == "user-1")
            .returning(move |_, _| Ok(Some(expected_vu_clone.clone())));

        let service = MappingService::from_driver(mock_backend);

        let result = service.get_virtual_user(&state, user_id).await.unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().user_id, user_id);
    }

    #[tokio::test]
    async fn test_list_rulesets() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;

        let rulesets = vec![make_ruleset("id-1", false), make_ruleset("id-2", false)];
        let rulesets_clone = rulesets.clone();
        mock_backend
            .expect_list_rulesets()
            .returning(move |_, _| Ok(rulesets_clone.clone()));

        let service = MappingService::from_driver(mock_backend);

        let result = service
            .list_rulesets(&state, &MappingRuleSetListParameters::default())
            .await
            .unwrap();

        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_ruleset_rejects_system_rules() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let mapping_id = "test-id";

        mock_backend
            .expect_get_ruleset()
            .returning(move |_, _| Ok(Some(make_ruleset(mapping_id, true))));

        mock_backend.expect_delete_ruleset().never();

        let service = MappingService::from_driver(mock_backend);

        let result = service.delete_ruleset(&state, mapping_id).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MappingProviderError::RulesetImmutable(_)
        ));
    }

    #[tokio::test]
    async fn test_update_ruleset() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let mapping_id = "test-id";

        let existing = make_ruleset(mapping_id, false);
        let existing_clone = existing.clone();
        mock_backend
            .expect_get_ruleset()
            .returning(move |_, _| Ok(Some(existing_clone.clone())));

        let updated = make_ruleset(mapping_id, false);
        let updated_clone = updated.clone();
        mock_backend
            .expect_update_ruleset()
            .returning(move |_, _, _| Ok(updated_clone.clone()));

        let service = MappingService::from_driver(mock_backend);

        let result = service
            .update_ruleset(
                &state,
                mapping_id,
                MappingRuleSetUpdate {
                    enabled: Some(true),
                    allowed_domains: None,
                    rules: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(result.mapping_id, mapping_id);
    }

    #[tokio::test]
    async fn test_update_ruleset_rejects_system_rules() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let mapping_id = "test-id";

        mock_backend
            .expect_get_ruleset()
            .returning(move |_, _| Ok(Some(make_ruleset(mapping_id, true))));

        mock_backend.expect_update_ruleset().never();

        let service = MappingService::from_driver(mock_backend);

        let result = service
            .update_ruleset(
                &state,
                mapping_id,
                MappingRuleSetUpdate {
                    enabled: Some(true),
                    allowed_domains: None,
                    rules: None,
                },
            )
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MappingProviderError::RulesetImmutable(_)
        ));
    }

    #[tokio::test]
    async fn test_mutate_rules_insert() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let mapping_id = "test-id";

        let existing_rules = vec![
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
                authorizations: vec![],
                groups: vec![],
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
                authorizations: vec![],
                groups: vec![],
            },
        ];

        let existing = MappingRuleSet {
            mapping_id: mapping_id.to_string(),
            domain_id: None,
            source: IdentitySource::Federation {
                idp_id: "test-idp".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled: true,
            rules: existing_rules.clone(),
            ruleset_version: 1,
        };

        let existing_clone = existing.clone();
        mock_backend
            .expect_get_ruleset()
            .returning(move |_, _| Ok(Some(existing_clone.clone())));

        let updated = MappingRuleSet {
            mapping_id: mapping_id.to_string(),
            domain_id: None,
            source: IdentitySource::Federation {
                idp_id: "test-idp".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![
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
                    authorizations: vec![],
                    groups: vec![],
                },
                MappingRule {
                    name: "rule-x".to_string(),
                    description: None,
                    r#match: MatchCriteria::AllOf(vec![]),
                    identity: IdentityBinding {
                        user_name: "x".to_string(),
                        user_id: None,
                        user_domain_id: None,
                        is_system: false,
                    },
                    authorizations: vec![],
                    groups: vec![],
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
                    authorizations: vec![],
                    groups: vec![],
                },
            ],
            ruleset_version: 2,
        };

        let updated_clone = updated.clone();
        mock_backend
            .expect_update_ruleset()
            .returning(move |_, _, _| Ok(updated_clone.clone()));

        let service = MappingService::from_driver(mock_backend);

        let new_rule = MappingRule {
            name: "rule-x".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                user_name: "x".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        };

        let result = service
            .mutate_rules(
                &state,
                mapping_id,
                RuleMutations {
                    mutations: vec![RuleMutation::Insert {
                        rule: new_rule,
                        position: Some(RulePosition::Before {
                            anchor: "rule-b".to_string(),
                        }),
                    }],
                },
            )
            .await
            .unwrap();

        assert_eq!(result.rules.len(), 3);
    }

    #[tokio::test]
    async fn test_mutate_rules_rejects_system_rules() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let mapping_id = "test-id";

        mock_backend
            .expect_get_ruleset()
            .returning(move |_, _| Ok(Some(make_ruleset(mapping_id, true))));

        mock_backend.expect_update_ruleset().never();

        let service = MappingService::from_driver(mock_backend);

        let result = service
            .mutate_rules(
                &state,
                mapping_id,
                RuleMutations {
                    mutations: vec![RuleMutation::Delete {
                        rule_name: "test-rule".to_string(),
                    }],
                },
            )
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MappingProviderError::RulesetImmutable(_)
        ));
    }

    #[tokio::test]
    async fn test_mutate_rules_not_found() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let mapping_id = "test-id";

        mock_backend.expect_get_ruleset().returning(|_, _| Ok(None));

        let service = MappingService::from_driver(mock_backend);

        let result = service
            .mutate_rules(
                &state,
                mapping_id,
                RuleMutations {
                    mutations: vec![RuleMutation::Delete {
                        rule_name: "some-rule".to_string(),
                    }],
                },
            )
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MappingProviderError::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn test_mutation_insert_invalid_anchor() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let mapping_id = "test-id";

        let existing = make_ruleset(mapping_id, false);
        let existing_clone = existing.clone();
        mock_backend
            .expect_get_ruleset()
            .returning(move |_, _| Ok(Some(existing_clone.clone())));

        let service = MappingService::from_driver(mock_backend);

        let new_rule = MappingRule {
            name: "rule-x".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                user_name: "x".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        };

        let result = service
            .mutate_rules(
                &state,
                mapping_id,
                RuleMutations {
                    mutations: vec![RuleMutation::Insert {
                        rule: new_rule,
                        position: Some(RulePosition::Before {
                            anchor: "nonexistent".to_string(),
                        }),
                    }],
                },
            )
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MappingProviderError::Conflict(_)
        ));
    }
}
