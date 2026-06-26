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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use secrecy::ExposeSecret;
use uuid::Uuid;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::auth::{
    AuthenticationContext, AuthenticationResult, AuthenticationResultBuilder, IdentityInfo,
    OidcContextBuilder, PrincipalIdentityInfoBuilder, PrincipalInfo, UserIdentityInfoBuilder,
};
use openstack_keystone_core_types::identity::{
    FederationBuilder, FederationProtocol, GroupCreate, GroupListParameters, UserCreateBuilder,
    UserResponse,
};
use openstack_keystone_core_types::mapping::*;

use crate::auth::ExecutionContext;
use crate::keystone::ServiceState;
use crate::mapping::{
    MappingApi, MappingProviderError, backend::MappingBackend, engine, hmac, validation, version,
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

    /// Authenticate a principal through the unified mapping engine.
    ///
    /// Evaluates claims against the ruleset, performs a shadow registry upsert,
    /// and emits `AuthenticationResult`.
    pub(super) async fn authenticate_by_mapping_internal<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        req: &MappingAuthRequest,
    ) -> Result<AuthenticationResult, MappingProviderError> {
        let cfg = ctx.state().config_manager.config.read().await;
        let salt = cfg
            .mapping
            .cluster_salt
            .as_ref()
            .map(|s| s.expose_secret().as_bytes().to_vec())
            .filter(|b| !b.is_empty())
            .ok_or_else(|| {
                MappingProviderError::HmacDerivationFailed(
                    "cluster_salt not configured".to_string(),
                )
            })?;

        self.authenticate_by_mapping_with_salt(ctx, req, &salt)
            .await
    }

    /// Authenticate a principal with an explicit salt.
    pub(super) async fn authenticate_by_mapping_with_salt<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        req: &MappingAuthRequest,
        salt: &[u8],
    ) -> Result<AuthenticationResult, MappingProviderError> {
        // 1. Resolve ruleset by (domain_id, source) composite index
        let domain_id = req.domain_id.as_deref().unwrap_or("global");
        let ruleset = self
            .backend_driver
            .get_ruleset_by_source(ctx.state(), domain_id, &req.source)
            .await?
            .ok_or(MappingProviderError::NoMatchingRule)?;

        // 2. Enabled gate
        if !ruleset.enabled {
            return Err(MappingProviderError::DisabledRuleset);
        }

        // 3. Evaluate claims against ruleset — named rule hint is tried first,
        // then standard first-match-wins iteration
        let match_result = engine::evaluate_ruleset(
            &ruleset,
            &req.claims,
            ruleset.domain_id.as_deref(),
            req.rule_name.as_deref(),
        )?
        .ok_or(MappingProviderError::NoMatchingRule)?;

        // 4. Resolve identity mode: explicit rule value > source-based default
        let identity_mode = match_result.identity_mode.clone().unwrap_or({
            if matches!(req.source, IdentitySource::Federation { .. }) {
                IdentityMode::Ephemeral
            } else {
                IdentityMode::Ephemeral
            }
        });

        // 5. Branch on identity mode
        match identity_mode {
            IdentityMode::Local => {
                self.authenticate_local(ctx.state(), &match_result, &ruleset, req)
                    .await
            }
            IdentityMode::Ephemeral => {
                self.authenticate_ephemeral(ctx.state(), &match_result, &ruleset, req, salt)
                    .await
            }
        }
    }

    /// Authenticate with a virtual shadow registry record (ephemeral path).
    async fn authenticate_ephemeral(
        &self,
        state: &ServiceState,
        match_result: &MatchResult,
        ruleset: &MappingRuleSet,
        req: &MappingAuthRequest,
        salt: &[u8],
    ) -> Result<AuthenticationResult, MappingProviderError> {
        let virtual_user_id =
            hmac::derive_virtual_user_id(salt, &req.unique_workload_id, &req.source)?;

        let virtual_user = self
            .upsert_virtual_user_shadow(
                &ExecutionContext::internal(state),
                &virtual_user_id,
                match_result,
                ruleset,
                &req.unique_workload_id,
            )
            .await?;

        let user_name = match_result.user_name.clone();
        let pinfo = if let Some(domain_id) = &virtual_user.domain_id {
            PrincipalIdentityInfoBuilder::default()
                .id(&virtual_user_id)
                .resolved_user_name(&user_name)
                .issuer(req.source.to_string_key())
                .domain(openstack_keystone_core_types::resource::Domain {
                    id: domain_id.clone(),
                    description: None,
                    enabled: true,
                    name: String::new(),
                    extra: HashMap::new(),
                })
                .build()
                .map_err(Box::new)?
        } else {
            PrincipalIdentityInfoBuilder::default()
                .id(&virtual_user_id)
                .resolved_user_name(&user_name)
                .issuer(req.source.to_string_key())
                .build()
                .map_err(Box::new)?
        };

        let principal = PrincipalInfo {
            identity: IdentityInfo::Principal(pinfo),
        };

        Ok(AuthenticationResultBuilder::default()
            .principal(principal)
            .context(AuthenticationContext::Mapping(MappingContext {
                mapping_id: ruleset.mapping_id.clone(),
                matched_rule_name: match_result.rule_name.clone(),
                virtual_user_id: virtual_user_id.clone(),
            }))
            .build()
            .map_err(Box::new)?)
    }

    /// Authenticate with a real federated user row (local path).
    async fn authenticate_local(
        &self,
        state: &ServiceState,
        match_result: &MatchResult,
        ruleset: &MappingRuleSet,
        req: &MappingAuthRequest,
    ) -> Result<AuthenticationResult, MappingProviderError> {
        let IdentitySource::Federation { idp_id } = &req.source else {
            return Err(MappingProviderError::LocalIdentityRequiresFederation(
                req.source.to_string_key(),
            ));
        };

        let domain_id = match_result
            .user_domain_id
            .clone()
            .or_else(|| ruleset.domain_id.clone())
            .ok_or(MappingProviderError::HmacDerivationFailed(
                "domain_id required for local identity mode".to_string(),
            ))?;

        let user = self
            .find_or_create_federated_user(
                state,
                idp_id,
                &domain_id,
                &match_result.user_name,
                &req.unique_workload_id,
            )
            .await?;

        // Always sync group memberships to reflect current claims, not just
        // on first-time creation.
        self.sync_user_groups(state, &user, match_result, idp_id)
            .await?;

        let user_groups = state
            .provider
            .get_identity_provider()
            .list_groups_of_user(&ExecutionContext::internal(state), &user.id)
            .await
            .map_err(MappingProviderError::driver)?;

        let auth_result = AuthenticationResultBuilder::default()
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id(user.id.clone())
                        .user(user.clone())
                        .user_groups(user_groups)
                        .build()
                        .map_err(Box::new)?,
                ),
            })
            .context(AuthenticationContext::Oidc {
                oidc: OidcContextBuilder::default()
                    .idp_id(idp_id.clone())
                    .protocol_id("oidc")
                    .build()
                    .map_err(Box::new)?,
                token: None,
            })
            .build()
            .map_err(Box::new)?;

        Ok(auth_result)
    }

    /// Find existing federated user or create a new one.
    ///
    /// Uses `unique_workload_id` (the raw subject from the IdP) as the
    /// federated user's unique_id, matching the lookup key used by the IdP's
    /// token validation flow.
    async fn find_or_create_federated_user(
        &self,
        state: &ServiceState,
        idp_id: &str,
        domain_id: &str,
        user_name: &str,
        unique_workload_id: &str,
    ) -> Result<UserResponse, MappingProviderError> {
        let ctx = ExecutionContext::internal(state);
        let idp = state
            .provider
            .get_federation_provider()
            .get_identity_provider(&ctx, idp_id)
            .await
            .map_err(MappingProviderError::driver)?
            .ok_or_else(|| {
                MappingProviderError::NotFound(format!("identity provider {}", idp_id))
            })?;

        if !idp.enabled {
            return Err(MappingProviderError::DisabledRuleset);
        }

        let identity_provider = state.provider.get_identity_provider();

        if let Some(existing) = identity_provider
            .find_federated_user(&ctx, idp_id, unique_workload_id)
            .await
            .map_err(MappingProviderError::driver)?
        {
            return Ok(existing);
        }

        let mut federated_builder = FederationBuilder::default();
        federated_builder
            .idp_id(idp_id.to_string())
            .unique_id(unique_workload_id.to_string())
            .protocols(vec![FederationProtocol {
                protocol_id: "oidc".to_string(),
                unique_id: unique_workload_id.to_string(),
            }]);

        let mut user_builder = UserCreateBuilder::default();
        user_builder
            .domain_id(domain_id.to_string())
            .enabled(true)
            .name(user_name.to_string())
            .federated(vec![
                federated_builder
                    .build()
                    .map_err(MappingProviderError::driver)?,
            ]);

        let user = identity_provider
            .create_user(
                &ctx,
                user_builder.build().map_err(MappingProviderError::driver)?,
            )
            .await
            .map_err(MappingProviderError::driver)?;

        Ok(user)
    }

    /// Sync user group memberships based on mapping rule's group bindings.
    async fn sync_user_groups(
        &self,
        state: &ServiceState,
        user: &UserResponse,
        match_result: &MatchResult,
        idp_id: &str,
    ) -> Result<(), MappingProviderError> {
        let ctx = ExecutionContext::internal(state);
        let identity_provider = state.provider.get_identity_provider();

        let domain_groups: HashMap<String, String> = identity_provider
            .list_groups(
                &ctx,
                &GroupListParameters {
                    domain_id: Some(user.domain_id.clone()),
                    ..Default::default()
                },
            )
            .await
            .map_err(MappingProviderError::driver)?
            .into_iter()
            .map(|g| (g.name.clone(), g.id.clone()))
            .collect();

        let mut group_ids = HashSet::new();

        for binding in &match_result.resolved_group_bindings {
            if let Some(group_name) = &binding.name {
                let group_id = if let Some(id) = domain_groups.get(group_name) {
                    id.clone()
                } else {
                    let domain_id = binding
                        .domain_id
                        .clone()
                        .or_else(|| Some(user.domain_id.clone()))
                        .unwrap_or_default();
                    let created = identity_provider
                        .create_group(
                            &ctx,
                            GroupCreate {
                                domain_id,
                                name: group_name.clone(),
                                ..Default::default()
                            },
                        )
                        .await
                        .map_err(MappingProviderError::driver)?;
                    created.id
                };
                group_ids.insert(group_id);
            }
        }

        if !group_ids.is_empty() {
            identity_provider
                .set_user_groups_expiring(
                    &ctx,
                    &user.id,
                    HashSet::from_iter(group_ids.iter().map(|s| s.as_str())),
                    idp_id,
                    Some(&Utc::now()),
                )
                .await
                .map_err(MappingProviderError::driver)?;
        }

        Ok(())
    }

    /// Upsert a virtual user shadow record with CAS-protected retry loop.
    ///
    /// If the record exists, refresh fields while preserving `created_at` and
    /// `is_system` (immutable from initial creation). If new, create fresh.
    /// Retries on `CasConflict` with exponential backoff.
    pub(super) async fn upsert_virtual_user_shadow<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        virtual_user_id: &str,
        match_result: &MatchResult,
        ruleset: &MappingRuleSet,
        unique_workload_id: &str,
    ) -> Result<VirtualUser, MappingProviderError> {
        let now = Utc::now().timestamp();
        let max_retries = 5u64;

        for attempt in 0..max_retries {
            let existing = self
                .backend_driver
                .get_virtual_user(ctx.state(), virtual_user_id)
                .await?;

            let result = if let Some(mut vu) = existing {
                // Update path: refresh fields, preserve created_at and is_system
                vu.mapping_id = ruleset.mapping_id.clone();
                vu.matched_rule_name = match_result.rule_name.clone();
                vu.resolved_user_name = match_result.user_name.clone();
                vu.resolved_group_bindings = match_result.resolved_group_bindings.clone();
                vu.authorizations = match_result.authorizations.clone();
                vu.ruleset_version = ruleset.ruleset_version;
                vu.last_authenticated_at = now;
                vu.enabled = true;
                vu.domain_id = match_result.user_domain_id.clone();
                // is_system is intentionally preserved from initial creation

                // Persist updated record (CAS-protected at storage layer)
                self.backend_driver
                    .update_virtual_user(ctx.state(), virtual_user_id, vu.clone())
                    .await
            } else {
                // Insert path: create fresh record
                let vu = VirtualUser {
                    user_id: virtual_user_id.to_string(),
                    unique_workload_id: unique_workload_id.to_string(),
                    mapping_id: ruleset.mapping_id.clone(),
                    matched_rule_name: match_result.rule_name.clone(),
                    domain_id: match_result.user_domain_id.clone(),
                    resolved_user_name: match_result.user_name.clone(),
                    is_system: match_result.is_system,
                    resolved_group_bindings: match_result.resolved_group_bindings.clone(),
                    authorizations: match_result.authorizations.clone(),
                    ruleset_version: ruleset.ruleset_version,
                    enabled: true,
                    created_at: now,
                    last_authenticated_at: now,
                };

                self.backend_driver
                    .create_virtual_user(ctx.state(), vu.clone())
                    .await
            };

            match result {
                Ok(vu) => return Ok(vu),
                Err(MappingProviderError::CasConflict { .. }) if attempt + 1 < max_retries => {
                    let backoff_ms = 50 * (1u64 << attempt); // exponential: 50, 100, 200, 400, 800
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Err(MappingProviderError::CasConflict {
            subject: virtual_user_id.to_string(),
            description: format!(
                "CAS upsert exceeded {max_retries} retries with exponential backoff"
            ),
        })
    }
}

#[async_trait]
impl MappingApi for MappingService {
    /// Create a mapping ruleset.
    ///
    /// Validates the payload, generates UUID, computes content-aware version,
    /// then delegates to the backend driver.
    async fn create_ruleset<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
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
            .create_ruleset(ctx.state(), ruleset_obj)
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
        ctx: &ExecutionContext<'a>,
        mapping_id: &'a str,
    ) -> Result<(), MappingProviderError> {
        let max_retries = 5u64;
        for attempt in 0..max_retries {
            // Check immutability: if ruleset contains `is_system` rules, reject
            if let Some(existing) = self
                .backend_driver
                .get_ruleset(ctx.state(), mapping_id)
                .await?
                && existing.rules.iter().any(|r| r.identity.is_system)
            {
                return Err(MappingProviderError::RulesetImmutable(
                    mapping_id.to_string(),
                ));
            }

            match self
                .backend_driver
                .delete_ruleset(ctx.state(), mapping_id)
                .await
            {
                Ok(()) => return Ok(()),
                Err(MappingProviderError::CasConflict { .. }) if attempt + 1 < max_retries => {
                    let backoff_ms = 50 * (1u64 << attempt);
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(MappingProviderError::CasConflict {
            subject: mapping_id.to_string(),
            description: format!(
                "CAS delete exceeded {max_retries} retries with exponential backoff"
            ),
        })
    }

    /// Delete a virtual user shadow record.
    async fn delete_virtual_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<(), MappingProviderError> {
        let max_retries = 5u64;
        for attempt in 0..max_retries {
            match self
                .backend_driver
                .delete_virtual_user(ctx.state(), user_id)
                .await
            {
                Ok(()) => return Ok(()),
                Err(MappingProviderError::CasConflict { .. }) if attempt + 1 < max_retries => {
                    let backoff_ms = 50 * (1u64 << attempt);
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(MappingProviderError::CasConflict {
            subject: user_id.to_string(),
            description: format!(
                "CAS delete exceeded {max_retries} retries with exponential backoff"
            ),
        })
    }

    /// Fetch a mapping ruleset by ID.
    async fn get_ruleset<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        mapping_id: &'a str,
    ) -> Result<Option<MappingRuleSet>, MappingProviderError> {
        self.backend_driver
            .get_ruleset(ctx.state(), mapping_id)
            .await
    }

    /// Fetch a ruleset by its (domain_id, source) composite index.
    async fn get_ruleset_by_source<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        source: &'a IdentitySource,
    ) -> Result<Option<MappingRuleSet>, MappingProviderError> {
        self.backend_driver
            .get_ruleset_by_source(ctx.state(), domain_id, source)
            .await
    }

    /// Fetch a virtual user shadow record by user ID.
    async fn get_virtual_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<Option<VirtualUser>, MappingProviderError> {
        self.backend_driver
            .get_virtual_user(ctx.state(), user_id)
            .await
    }

    /// List mapping rulesets.
    async fn list_rulesets<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &MappingRuleSetListParameters,
    ) -> Result<Vec<MappingRuleSet>, MappingProviderError> {
        self.backend_driver.list_rulesets(ctx.state(), params).await
    }

    /// Mutate rules within a mapping ruleset imperatively.
    ///
    /// Fetches the current ruleset, validates immutability, applies mutations
    /// in memory, re-validates, computes new version, then delegates update.
    async fn mutate_rules<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        mapping_id: &'a str,
        mutations: RuleMutations,
    ) -> Result<MappingRuleSet, MappingProviderError> {
        // 1. Fetch current ruleset
        let existing = self
            .backend_driver
            .get_ruleset(ctx.state(), mapping_id)
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
            .update_ruleset(ctx.state(), mapping_id, update_payload)
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
        ctx: &ExecutionContext<'a>,
        mapping_id: &'a str,
        data: MappingRuleSetUpdate,
    ) -> Result<MappingRuleSet, MappingProviderError> {
        // 1. Fetch existing ruleset
        let existing = self
            .backend_driver
            .get_ruleset(ctx.state(), mapping_id)
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
            .update_ruleset(ctx.state(), mapping_id, data)
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
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<VirtualUser, MappingProviderError> {
        self.backend_driver
            .disable_virtual_user(ctx.state(), user_id)
            .await
    }

    /// Enable (reactivate) a virtual user shadow record.
    async fn enable_virtual_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<VirtualUser, MappingProviderError> {
        self.backend_driver
            .enable_virtual_user(ctx.state(), user_id)
            .await
    }

    /// Authenticate a principal through the unified mapping engine.
    async fn authenticate_by_mapping<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        req: &'a MappingAuthRequest,
    ) -> Result<AuthenticationResult, MappingProviderError> {
        self.authenticate_by_mapping_internal(exec, req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::ExecutionContext;
    use crate::keystone::ServiceState;
    use crate::mapping::backend::MockMappingBackend;
    use crate::tests::get_mocked_state;
    use openstack_keystone_config::Config;
    use openstack_keystone_core_types::mapping::rule::{
        ClaimCondition, IdentityBinding, MappingRule, MatchCondition, MatchCriteria,
    };
    use secrecy::SecretString;
    use serde_json::Value;

    /// Helper to create mocked state with a configured cluster_salt.
    async fn get_mocked_state_with_salt() -> ServiceState {
        let mut cfg = Config::default();
        cfg.mapping.cluster_salt = Some(SecretString::from("test-salt-for-hmac-derivation!"));
        get_mocked_state(Some(cfg), None).await
    }

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

        let result = service
            .get_ruleset(&ExecutionContext::internal(&state), mapping_id)
            .await
            .unwrap();

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
            .create_ruleset(&ExecutionContext::internal(&state), ruleset_create)
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

        service
            .delete_ruleset(&ExecutionContext::internal(&state), mapping_id)
            .await
            .unwrap();
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
                    identity_mode: None,
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

        service
            .delete_virtual_user(&ExecutionContext::internal(&state), user_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_delete_ruleset_retries_on_cas_conflict() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let mapping_id = "test-id";

        mock_backend
            .expect_get_ruleset()
            .withf(move |_, id| id == "test-id")
            .times(5) // 5 retries with CAS conflict
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
            .times(5) // 5 retries with CAS conflict
            .returning(|_, _| {
                Err(MappingProviderError::CasConflict {
                    subject: "test-id".to_string(),
                    description: "CAS conflict".to_string(),
                })
            });

        let service = MappingService::from_driver(mock_backend);
        let result = service
            .delete_ruleset(&ExecutionContext::internal(&state), mapping_id)
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MappingProviderError::CasConflict { .. })
        ));
    }

    #[tokio::test]
    async fn test_delete_ruleset_succeeds_after_cas_retry() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let mapping_id = "test-id";

        mock_backend
            .expect_get_ruleset()
            .withf(move |_, id| id == "test-id")
            .times(1)
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
            .times(1)
            .returning(|_, _| Ok(()));

        let service = MappingService::from_driver(mock_backend);
        let result = service
            .delete_ruleset(&ExecutionContext::internal(&state), mapping_id)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_virtual_user_retries_on_cas_conflict() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let user_id = "user-1";

        mock_backend
            .expect_delete_virtual_user()
            .withf(move |_, id| id == "user-1")
            .times(5) // 5 retries with CAS conflict
            .returning(|_, _| {
                Err(MappingProviderError::CasConflict {
                    subject: "user-1".to_string(),
                    description: "CAS conflict".to_string(),
                })
            });

        let service = MappingService::from_driver(mock_backend);
        let result = service
            .delete_virtual_user(&ExecutionContext::internal(&state), user_id)
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(MappingProviderError::CasConflict { .. })
        ));
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

        let result = service
            .get_virtual_user(&ExecutionContext::internal(&state), user_id)
            .await
            .unwrap();

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
            .list_rulesets(
                &ExecutionContext::internal(&state),
                &MappingRuleSetListParameters::default(),
            )
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

        let result = service
            .delete_ruleset(&ExecutionContext::internal(&state), mapping_id)
            .await;

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
                &ExecutionContext::internal(&state),
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
                &ExecutionContext::internal(&state),
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
                    identity_mode: None,
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
                    identity_mode: None,
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
                        identity_mode: None,
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
                        identity_mode: None,
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
                        identity_mode: None,
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
                identity_mode: None,
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
                &ExecutionContext::internal(&state),
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
                &ExecutionContext::internal(&state),
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
                &ExecutionContext::internal(&state),
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
                identity_mode: None,
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
                &ExecutionContext::internal(&state),
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

    #[tokio::test]
    async fn test_authenticate_by_mapping_no_matching_ruleset() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state_with_salt().await;

        let source = IdentitySource::Federation {
            idp_id: "okta".to_string(),
        };

        mock_backend
            .expect_get_ruleset_by_source()
            .returning(move |_, _, _| Ok(None));

        let service = MappingService::from_driver(mock_backend);

        let result = service
            .authenticate_by_mapping(
                &ExecutionContext::internal(&state),
                &MappingAuthRequest {
                    domain_id: Some("default-domain".to_string()),
                    source: source.clone(),
                    unique_workload_id: "workload-1".to_string(),
                    claims: HashMap::new(),
                    rule_name: None,
                },
            )
            .await;

        assert!(matches!(
            result.unwrap_err(),
            MappingProviderError::NoMatchingRule
        ));
    }

    #[tokio::test]
    async fn test_authenticate_by_mapping_disabled_ruleset() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state_with_salt().await;

        let disabled_ruleset = MappingRuleSet {
            mapping_id: "test-id".to_string(),
            domain_id: Some("default-domain".to_string()),
            source: IdentitySource::Federation {
                idp_id: "okta".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled: false,
            rules: vec![],
            ruleset_version: 1,
        };

        let disabled_ruleset_clone = disabled_ruleset.clone();
        mock_backend
            .expect_get_ruleset_by_source()
            .returning(move |_, _, _| Ok(Some(disabled_ruleset_clone.clone())));

        let service = MappingService::from_driver(mock_backend);

        let result = service
            .authenticate_by_mapping(
                &ExecutionContext::internal(&state),
                &MappingAuthRequest {
                    domain_id: Some("default-domain".to_string()),
                    source: IdentitySource::Federation {
                        idp_id: "okta".to_string(),
                    },
                    unique_workload_id: "workload-1".to_string(),
                    claims: HashMap::new(),
                    rule_name: None,
                },
            )
            .await;

        assert!(matches!(
            result.unwrap_err(),
            MappingProviderError::DisabledRuleset
        ));
    }

    #[tokio::test]
    async fn test_authenticate_by_mapping_missing_salt() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;

        let ruleset = MappingRuleSet {
            mapping_id: "test-id".to_string(),
            domain_id: Some("default-domain".to_string()),
            source: IdentitySource::Federation {
                idp_id: "okta".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![],
            ruleset_version: 1,
        };

        let ruleset_clone = ruleset.clone();
        mock_backend
            .expect_get_ruleset_by_source()
            .returning(move |_, _, _| Ok(Some(ruleset_clone.clone())));

        let service = MappingService::from_driver(mock_backend);

        let result = service
            .authenticate_by_mapping(
                &ExecutionContext::internal(&state),
                &MappingAuthRequest {
                    domain_id: Some("default-domain".to_string()),
                    source: IdentitySource::Federation {
                        idp_id: "okta".to_string(),
                    },
                    unique_workload_id: "workload-1".to_string(),
                    claims: HashMap::new(),
                    rule_name: None,
                },
            )
            .await;

        assert!(matches!(
            result.unwrap_err(),
            MappingProviderError::HmacDerivationFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_enable_virtual_user() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let user_id = "user-123";

        let enabled_vu = VirtualUser {
            user_id: user_id.to_string(),
            unique_workload_id: "workload-1".to_string(),
            mapping_id: "test-mapping".to_string(),
            matched_rule_name: "test-rule".to_string(),
            domain_id: None,
            resolved_user_name: "test-user".to_string(),
            is_system: false,
            resolved_group_bindings: vec![],
            authorizations: vec![],
            ruleset_version: 1,
            enabled: true,
            created_at: 0,
            last_authenticated_at: 0,
        };

        let enabled_vu_clone = enabled_vu.clone();
        mock_backend
            .expect_enable_virtual_user()
            .withf(move |_, id| id == user_id)
            .returning(move |_, _| Ok(enabled_vu_clone.clone()));

        let service = MappingService::from_driver(mock_backend);

        let result = service
            .enable_virtual_user(&ExecutionContext::internal(&state), user_id)
            .await
            .unwrap();

        assert_eq!(result.user_id, user_id);
        assert!(result.enabled);
    }

    #[tokio::test]
    async fn test_disable_virtual_user() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;
        let user_id = "user-123";

        let disabled_vu = VirtualUser {
            user_id: user_id.to_string(),
            unique_workload_id: "workload-1".to_string(),
            mapping_id: "test-mapping".to_string(),
            matched_rule_name: "test-rule".to_string(),
            domain_id: None,
            resolved_user_name: "test-user".to_string(),
            is_system: false,
            resolved_group_bindings: vec![],
            authorizations: vec![],
            ruleset_version: 1,
            enabled: false,
            created_at: 0,
            last_authenticated_at: 0,
        };

        let disabled_vu_clone = disabled_vu.clone();
        mock_backend
            .expect_disable_virtual_user()
            .withf(move |_, id| id == user_id)
            .returning(move |_, _| Ok(disabled_vu_clone.clone()));

        let service = MappingService::from_driver(mock_backend);

        let result = service
            .disable_virtual_user(&ExecutionContext::internal(&state), user_id)
            .await
            .unwrap();

        assert_eq!(result.user_id, user_id);
        assert!(!result.enabled);
    }

    #[tokio::test]
    async fn test_get_ruleset_by_source() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state(None, None).await;

        let source = IdentitySource::Federation {
            idp_id: "test-idp".to_string(),
        };

        let expected_ruleset = MappingRuleSet {
            mapping_id: "test-mapping".to_string(),
            domain_id: Some("default-domain".to_string()),
            source: source.clone(),
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![],
            ruleset_version: 1,
        };

        let expected_ruleset_clone = expected_ruleset.clone();
        mock_backend
            .expect_get_ruleset_by_source()
            .returning(move |_, _, _| Ok(Some(expected_ruleset_clone.clone())));

        let service = MappingService::from_driver(mock_backend);

        let result = service
            .get_ruleset_by_source(
                &ExecutionContext::internal(&state),
                "default-domain",
                &source,
            )
            .await
            .unwrap();

        assert!(result.is_some());
        let ruleset = result.unwrap();
        assert_eq!(ruleset.mapping_id, "test-mapping");
        assert_eq!(
            ruleset.source,
            IdentitySource::Federation {
                idp_id: "test-idp".to_string()
            }
        );
    }

    #[tokio::test]
    async fn test_authenticate_by_mapping_success() {
        let mut mock_backend = MockMappingBackend::new();
        let state = get_mocked_state_with_salt().await;

        let mut claims = HashMap::new();
        claims.insert("sub".to_string(), vec!["workload-123".to_string()]);

        let source = IdentitySource::Federation {
            idp_id: "okta".to_string(),
        };

        let rules = vec![MappingRule {
            name: "matching-rule".to_string(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                ClaimCondition::Equals {
                    claim: "sub".to_string(),
                    value: Value::String("workload-123".to_string()),
                },
            )]),
            identity: IdentityBinding {
                identity_mode: Some(IdentityMode::Ephemeral),
                user_name: "${claims.sub}-mapped".to_string(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![],
            groups: vec![],
        }];

        let matching_ruleset = MappingRuleSet {
            mapping_id: "test-mapping".to_string(),
            domain_id: Some("default-domain".to_string()),
            source: source.clone(),
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled: true,
            rules,
            ruleset_version: 1,
        };

        let matching_ruleset_clone = matching_ruleset.clone();

        mock_backend
            .expect_get_ruleset_by_source()
            .returning(move |_, _, _| Ok(Some(matching_ruleset_clone.clone())));

        mock_backend
            .expect_get_virtual_user()
            .returning(|_, _| Ok(None));

        mock_backend
            .expect_create_virtual_user()
            .returning(move |_, vu: VirtualUser| Ok(vu));

        let service = MappingService::from_driver(mock_backend);

        let result = service
            .authenticate_by_mapping(
                &ExecutionContext::internal(&state),
                &MappingAuthRequest {
                    domain_id: Some("default-domain".to_string()),
                    source: source.clone(),
                    unique_workload_id: "workload-123".to_string(),
                    claims: claims.clone(),
                    rule_name: None,
                },
            )
            .await;

        assert!(result.is_ok());
        let auth_result = result.unwrap();
        if let AuthenticationContext::Mapping(ctx) = auth_result.context {
            assert_eq!(ctx.mapping_id, "test-mapping");
            assert_eq!(ctx.matched_rule_name, "matching-rule");
        } else {
            panic!("Expected Mapping context");
        }
    }
}
