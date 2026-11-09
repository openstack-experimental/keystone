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
//! # Role provider
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::role::*;

use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
use crate::plugin_manager::PluginManagerApi;
use crate::request_cache::{cache_get, cache_remove, cache_set};
use crate::role::cache::RoleCache;
use crate::role::{RoleApi, RoleProviderError, backend::RoleBackend};

/// Request-cache namespace for [`Role`] lookups by `role_id`.
const ROLE_CACHE_NS: &str = "role.role";
/// Request-cache namespace for a prior role's direct imply rules
/// (`Vec<RoleImply>`) by `prior_role_id`. The primary consumer is
/// `assignment-driver-sql`'s `SqlBackend::resolve_implied_roles`, whose BFS
/// over the imply graph calls `list_role_imply_rules_by_prior` once per
/// unique role encountered -- caching here helps when
/// `resolve_implied_roles`/`expand_implied_roles` runs more than once
/// within the same request (e.g. listing assignments for several
/// actor/target pairs that share roles).
///
/// Entries are only invalidated by their own `prior_role_id` (on
/// `delete_role`/`create_role_imply_rule`/`delete_role_imply_rule`), not by
/// scanning for it appearing as an *implied* role in someone else's cached
/// list. If role B is deleted while some other prior role A's rule list
/// (containing `A -> B`) is already cached, that stale entry survives until
/// the request ends -- same accepted, request-scoped staleness window as
/// `resource::service::PROJECT_PARENTS_CACHE_NS`'s ancestor-update case.
const ROLE_IMPLY_BY_PRIOR_CACHE_NS: &str = "role.imply_by_prior";
/// Request-cache namespace for roles looked up by `list_roles` with
/// `skip_options` (the name resolution of the assigned roles). Kept apart from
/// [`ROLE_CACHE_NS`], whose entries carry the options.
const ROLE_NAME_CACHE_NS: &str = "role.name";
/// Request-cache namespace for the complete imply rule table (a single
/// `Vec<RoleImply>` under [`ROLE_IMPLY_ALL_CACHE_KEY`]). The rule table is
/// small, so reading all of it once per request and resolving the inference
/// graph in the service is cheaper than a recursive query per set of roles,
/// and every set of roles of the request shares the one read. Invalidated by
/// every change of the rules within the request.
const ROLE_IMPLY_ALL_CACHE_NS: &str = "role.imply_all";
/// Key of the complete rule table in [`ROLE_IMPLY_ALL_CACHE_NS`].
const ROLE_IMPLY_ALL_CACHE_KEY: &str = "all";

/// Role provider service.
///
/// Besides the per-request cache the service keeps a process-wide TTL cache
/// ([`RoleCache`], `[role] cache_time`) of the roles and the imply rules.
pub struct RoleService {
    backend_driver: Arc<dyn RoleBackend>,
    cache: RoleCache,
}

impl RoleService {
    /// Create a new RoleService.
    ///
    /// # Arguments
    /// * `config` - The configuration for the service.
    /// * `plugin_manager` - The plugin manager used to load the backend driver.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, RoleProviderError> {
        let backend_driver = plugin_manager
            .get_role_backend(config.role.driver.clone())?
            .clone();
        let cache = RoleCache::new(if config.role.caching {
            Duration::from_secs(config.role.cache_time)
        } else {
            Duration::ZERO
        });
        Ok(Self {
            backend_driver,
            cache,
        })
    }

    /// Reject the operation when the role is currently immutable and the
    /// request does not itself clear the flag.
    ///
    /// Mirrors Python Keystone: a resource with `options.immutable == true`
    /// rejects update/delete unless the update explicitly sets
    /// `immutable: false` in the same request. Pass `new_options: None` for
    /// delete, which can never clear the flag. When the role does not exist,
    /// this is a no-op -- the caller's own lookup surfaces `RoleNotFound`.
    async fn check_role_mutable<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        role_id: &'a str,
        new_options: Option<&RoleOptions>,
    ) -> Result<(), RoleProviderError> {
        if let Some(current) = self.get_role(ctx, role_id).await?
            && current.options.immutable == Some(true)
            && new_options.and_then(|o| o.immutable) != Some(false)
        {
            return Err(RoleProviderError::Immutable(role_id.to_string()));
        }
        Ok(())
    }
}

#[async_trait]
impl RoleApi for RoleService {
    /// Create role.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `params` - The parameters for creating a role.
    #[tracing::instrument(name = "provider.role.create_role", level = "debug", skip_all)]
    async fn create_role<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: RoleCreate,
    ) -> Result<Role, RoleProviderError> {
        let mut new_params = params;
        let role_id = if let Some(ref rid) = new_params.id {
            rid.clone()
        } else {
            let rid = Uuid::new_v4().simple().to_string();
            new_params.id = Some(rid.clone());
            rid
        };
        new_params.validate()?;
        let role = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            crate::audited_notify_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::Role { id: role_id.clone() },
                ),
                operation: async {
                    backend_driver.create_role(state, new_params).await
                },
                on_audit_error: |_: AuditDispatchError| RoleProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let role = self
                .backend_driver
                .create_role(ctx.state(), new_params)
                .await?;

            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Role {
                        id: role.id.clone(),
                    },
                ))
                .await;

            role
        };

        Ok(role)
    }

    /// Create a role imply rule.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    /// * `implied_role_id` - The ID of the implied role.
    #[tracing::instrument(name = "provider.role.create_role_imply_rule", level = "debug", skip_all, fields(prior_role_id = %prior_role_id, implied_role_id = %implied_role_id))]
    async fn create_role_imply_rule<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<RoleImply, RoleProviderError> {
        let rule = if let Some(vsc) = ctx.ctx() {
            let prior = prior_role_id.to_string();
            let implied = implied_role_id.to_string();
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            crate::audited_notify_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::RoleImply {
                        prior_role_id: prior,
                        implied_role_id: implied,
                    },
                ),
                operation: async {
                    // Invalidate right after the commit so that a late audit failure cannot
                    // leave a committed change hidden behind the cache.
                    let result = backend_driver.create_role_imply_rule(state, prior_role_id, implied_role_id).await;
                    self.cache.invalidate();
                    result
                },
                on_audit_error: |_: AuditDispatchError| RoleProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let rule = self
                .backend_driver
                .create_role_imply_rule(ctx.state(), prior_role_id, implied_role_id)
                .await;
            self.cache.invalidate();
            let rule = rule?;

            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::RoleImply {
                        prior_role_id: prior_role_id.to_string(),
                        implied_role_id: implied_role_id.to_string(),
                    },
                ))
                .await;

            rule
        };

        cache_remove(ROLE_IMPLY_BY_PRIOR_CACHE_NS, prior_role_id);
        cache_remove(ROLE_IMPLY_ALL_CACHE_NS, ROLE_IMPLY_ALL_CACHE_KEY);
        Ok(rule)
    }

    /// Check if a role imply rule exists.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    /// * `implied_role_id` - The ID of the implied role.
    #[tracing::instrument(name = "provider.role.check_role_imply_rule", level = "debug", skip_all, fields(prior_role_id = %prior_role_id, implied_role_id = %implied_role_id))]
    async fn check_role_imply_rule<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<bool, RoleProviderError> {
        self.backend_driver
            .check_role_imply_rule(ctx.state(), prior_role_id, implied_role_id)
            .await
    }

    /// Update a role.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `role_id` - The ID of the role to update.
    /// * `role` - The fields to change.
    #[tracing::instrument(name = "provider.role.update_role", level = "debug", skip_all, fields(role_id = %role_id))]
    async fn update_role<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        role_id: &'a str,
        role: RoleUpdate,
    ) -> Result<Role, RoleProviderError> {
        role.validate()?;
        self.check_role_mutable(ctx, role_id, role.options.as_ref())
            .await?;
        let role = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            let role_id_clone = role_id.to_string();
            crate::audited_notify_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::Role { id: role_id_clone },
                ),
                operation: async {
                    // Invalidate right after the commit so that a late audit failure cannot
                    // leave a committed change hidden behind the cache.
                    let result = backend_driver.update_role(state, role_id, role).await;
                    self.cache.invalidate();
                    result
                },
                on_audit_error: |_: AuditDispatchError| RoleProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let role = self
                .backend_driver
                .update_role(ctx.state(), role_id, role)
                .await;
            self.cache.invalidate();
            let role = role?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::Role {
                        id: role.id.clone(),
                    },
                ))
                .await;
            role
        };

        cache_set(ROLE_CACHE_NS, role_id, role.clone());
        cache_remove(ROLE_NAME_CACHE_NS, role_id);
        Ok(role)
    }

    /// Delete a role by the ID.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `id` - The ID of the role to delete.
    #[tracing::instrument(name = "provider.role.delete_role", level = "debug", skip_all, fields(id = %id))]
    async fn delete_role<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), RoleProviderError> {
        self.check_role_mutable(ctx, id, None).await?;
        let result = crate::audited_if_ctx! {
            ctx: ctx,
            event: Event::new(
                Operation::Delete,
                EventPayload::Role { id: id.to_string() },
            ),
            operation: async {
                // The role row goes first; an earlier attempt that already
                // deleted it still gets its assignments revoked, then the
                // NotFound is returned (ADR 0042).
                let driver_result = self.backend_driver.delete_role(ctx.state(), id).await;
                // Invalidate right after the commit so that a late audit
                // failure cannot leave a committed change hidden behind
                // the process-wide cache.
                self.cache.invalidate();
                let deleted = match driver_result {
                    Ok(()) => Ok(()),
                    Err(err @ RoleProviderError::RoleNotFound(_)) => Err(err),
                    Err(err) => return Err(err),
                };
                ctx.state()
                    .provider
                    .get_assignment_provider()
                    .delete_assignments_for_role(ctx, id)
                    .await?;
                ctx.state()
                    .provider
                    .get_application_credential_provider()
                    .delete_application_credentials_for_role(ctx, id)
                    .await?;
                self.cache.invalidate();
                deleted
            },
            on_audit_error: |_: AuditDispatchError| RoleProviderError::Driver("audit dispatch failed".into()),
        };

        // The role row may be gone even when a cascade step failed: drop the
        // cached entries before the result is returned.
        cache_remove(ROLE_CACHE_NS, id);
        cache_remove(ROLE_NAME_CACHE_NS, id);
        cache_remove(ROLE_IMPLY_BY_PRIOR_CACHE_NS, id);
        cache_remove(ROLE_IMPLY_ALL_CACHE_NS, ROLE_IMPLY_ALL_CACHE_KEY);
        result
    }

    /// Delete a role imply rule.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    /// * `implied_role_id` - The ID of the implied role.
    #[tracing::instrument(name = "provider.role.delete_role_imply_rule", level = "debug", skip_all, fields(prior_role_id = %prior_role_id, implied_role_id = %implied_role_id))]
    async fn delete_role_imply_rule<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<(), RoleProviderError> {
        if let Some(vsc) = ctx.ctx() {
            let prior = prior_role_id.to_string();
            let implied = implied_role_id.to_string();
            crate::audited_notify_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::RoleImply {
                        prior_role_id: prior,
                        implied_role_id: implied,
                    },
                ),
                operation: async {
                    // Invalidate right after the commit so that a late audit failure cannot
                    // leave a committed change hidden behind the cache.
                    let result = self.backend_driver.delete_role_imply_rule(ctx.state(), prior_role_id, implied_role_id).await;
                    self.cache.invalidate();
                    result?;
                    Ok::<(), RoleProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| RoleProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            let result = self
                .backend_driver
                .delete_role_imply_rule(ctx.state(), prior_role_id, implied_role_id)
                .await;
            self.cache.invalidate();
            result?;

            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::RoleImply {
                        prior_role_id: prior_role_id.to_string(),
                        implied_role_id: implied_role_id.to_string(),
                    },
                ))
                .await;
        }

        cache_remove(ROLE_IMPLY_BY_PRIOR_CACHE_NS, prior_role_id);
        cache_remove(ROLE_IMPLY_ALL_CACHE_NS, ROLE_IMPLY_ALL_CACHE_KEY);
        Ok(())
    }

    /// Expand implied roles.
    ///
    /// Return list of the roles with the imply rules being considered.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `roles` - The list of roles to expand.
    #[tracing::instrument(name = "provider.role.expand_implied_roles", level = "debug", skip_all)]
    async fn expand_implied_roles<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        roles: &mut Vec<RoleRef>,
    ) -> Result<(), RoleProviderError> {
        // In most of the cases a logic for expanding the roles may be
        // implemented by the provider itself, but some backend drivers
        // may have more efficient methods.
        self.backend_driver
            .expand_implied_roles(ctx.state(), roles)
            .await?;
        Ok(())
    }

    /// Get single role.
    ///
    /// * `state` - The current service state.
    /// * `id` - The ID of the role to retrieve.
    ///
    /// A `Result` containing an `Option` with the `Role` if found, or an
    /// `Error`.
    #[tracing::instrument(name = "provider.role.get_role", level = "debug", skip_all, fields(id = %id))]
    async fn get_role<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<Role>, RoleProviderError> {
        if let Some(role) = cache_get::<Role>(ROLE_CACHE_NS, id) {
            return Ok(Some(role));
        }
        if let Some(role) = self.cache.get_role(id) {
            cache_set(ROLE_CACHE_NS, id, role.clone());
            return Ok(Some(role));
        }
        let loaded = self.cache.begin_role();
        let role = self.backend_driver.get_role(ctx.state(), id).await?;
        if let Some(role) = &role {
            self.cache.put_role(role, &loaded);
            cache_set(ROLE_CACHE_NS, id, role.clone());
        }
        Ok(role)
    }

    /// Get a role imply rule.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    /// * `implied_role_id` - The ID of the implied role.
    #[tracing::instrument(name = "provider.role.get_role_imply_rule", level = "debug", skip_all, fields(prior_role_id = %prior_role_id, implied_role_id = %implied_role_id))]
    async fn get_role_imply_rule<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<Option<RoleImply>, RoleProviderError> {
        self.backend_driver
            .get_role_imply_rule(ctx.state(), prior_role_id, implied_role_id)
            .await
    }

    /// List role imply rules.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    #[tracing::instrument(
        name = "provider.role.list_role_imply_rules",
        level = "debug",
        skip_all
    )]
    async fn list_role_imply_rules<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
    ) -> Result<Vec<RoleImply>, RoleProviderError> {
        if let Some(rules) =
            cache_get::<Vec<RoleImply>>(ROLE_IMPLY_ALL_CACHE_NS, ROLE_IMPLY_ALL_CACHE_KEY)
        {
            return Ok(rules);
        }
        if let Some(rules) = self.cache.get_imply_all() {
            cache_set(
                ROLE_IMPLY_ALL_CACHE_NS,
                ROLE_IMPLY_ALL_CACHE_KEY,
                rules.clone(),
            );
            return Ok(rules);
        }
        let loaded = self.cache.begin_imply_all();
        let rules = self
            .backend_driver
            .list_role_imply_rules(ctx.state())
            .await?;
        self.cache.put_imply_all(rules.clone(), &loaded);
        cache_set(
            ROLE_IMPLY_ALL_CACHE_NS,
            ROLE_IMPLY_ALL_CACHE_KEY,
            rules.clone(),
        );
        Ok(rules)
    }

    /// List role imply rules for a specific prior role.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    #[tracing::instrument(name = "provider.role.list_role_imply_rules_by_prior", level = "trace", skip_all, fields(prior_role_id = %prior_role_id))]
    async fn list_role_imply_rules_by_prior<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        prior_role_id: &'a str,
    ) -> Result<Vec<RoleImply>, RoleProviderError> {
        if let Some(rules) =
            cache_get::<Vec<RoleImply>>(ROLE_IMPLY_BY_PRIOR_CACHE_NS, prior_role_id)
        {
            return Ok(rules);
        }
        if let Some(rules) = self.cache.get_imply_by_prior(prior_role_id) {
            cache_set(ROLE_IMPLY_BY_PRIOR_CACHE_NS, prior_role_id, rules.clone());
            return Ok(rules);
        }
        let loaded = self.cache.begin_imply_by_prior();
        let rules = self
            .backend_driver
            .list_role_imply_rules_by_prior(ctx.state(), prior_role_id)
            .await?;
        self.cache
            .put_imply_by_prior(prior_role_id, rules.clone(), &loaded);
        cache_set(ROLE_IMPLY_BY_PRIOR_CACHE_NS, prior_role_id, rules.clone());
        Ok(rules)
    }

    /// List role imply rules for any of the given prior roles.
    ///
    /// Roles already in the request cache are served from it; the rest are
    /// fetched with a single backend call and cached per role, including the
    /// roles that have no rules.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_ids` - The IDs of the prior roles.
    #[tracing::instrument(name = "provider.role.list_role_imply_rules_by_priors", level = "debug", skip_all, fields(count = prior_role_ids.len()))]
    async fn list_role_imply_rules_by_priors<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        prior_role_ids: &[&'a str],
    ) -> Result<Vec<RoleImply>, RoleProviderError> {
        let mut rules: Vec<RoleImply> = Vec::new();
        let mut missing: Vec<&'a str> = Vec::new();
        for id in prior_role_ids {
            match cache_get::<Vec<RoleImply>>(ROLE_IMPLY_BY_PRIOR_CACHE_NS, id)
                .or_else(|| self.cache.get_imply_by_prior(id))
            {
                Some(cached) => rules.extend(cached),
                None => missing.push(id),
            }
        }
        if !missing.is_empty() {
            let loaded = self.cache.begin_imply_by_prior();
            let fetched = self
                .backend_driver
                .list_role_imply_rules_by_priors(ctx.state(), &missing)
                .await?;
            for id in &missing {
                let own: Vec<RoleImply> = fetched
                    .iter()
                    .filter(|rule| rule.prior_role.id == *id)
                    .cloned()
                    .collect();
                self.cache.put_imply_by_prior(id, own.clone(), &loaded);
                cache_set(ROLE_IMPLY_BY_PRIOR_CACHE_NS, id, own);
            }
            rules.extend(fetched);
        }
        Ok(rules)
    }

    /// List roles.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `params` - The parameters for listing roles.
    #[tracing::instrument(name = "provider.role.list_roles", level = "debug", skip_all, fields(params = ?params))]
    async fn list_roles<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, RoleProviderError> {
        params.validate()?;
        // The lookup of the names of the assigned roles: serve the known IDs
        // from the request cache and fetch the rest with one backend call.
        if let Some(ids) = &params.ids
            && params.skip_options
            && params.domain_id.is_none()
            && params.name.is_none()
            && params.pagination == Default::default()
        {
            let mut roles = Vec::new();
            let mut missing = Vec::new();
            for id in ids {
                match cache_get::<Role>(ROLE_NAME_CACHE_NS, id).or_else(|| self.cache.get_name(id))
                {
                    Some(role) => roles.push(role),
                    None => missing.push(id.clone()),
                }
            }
            if !missing.is_empty() {
                let loaded = self.cache.begin_name();
                let fetched = self
                    .backend_driver
                    .list_roles(
                        ctx.state(),
                        &RoleListParameters {
                            ids: Some(missing),
                            skip_options: true,
                            ..Default::default()
                        },
                    )
                    .await?;
                for role in fetched {
                    self.cache.put_name(&role, &loaded);
                    cache_set(ROLE_NAME_CACHE_NS, &role.id, role.clone());
                    roles.push(role);
                }
            }
            return Ok(roles);
        }
        self.backend_driver.list_roles(ctx.state(), params).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::auth::ExecutionContext;
    use crate::mocks::{MockApplicationCredentialProvider, MockAssignmentProvider};
    use crate::provider::Provider;
    use crate::role::backend::MockRoleBackend;
    use crate::tests::get_mocked_state;
    use openstack_keystone_core_types::application_credential::ApplicationCredentialProviderError;
    use openstack_keystone_core_types::assignment::AssignmentProviderError;

    fn make_role(id: &str, name: &str) -> Role {
        RoleBuilder::default().id(id).name(name).build().unwrap()
    }

    fn make_immutable_role(id: &str, name: &str) -> Role {
        let mut role = make_role(id, name);
        role.options.immutable = Some(true);
        role
    }

    #[tokio::test]
    async fn test_update_role_blocked_when_immutable() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_get_role()
            .withf(|_, id: &'_ str| id == "rid")
            .returning(|_, _| Ok(Some(make_immutable_role("rid", "admin"))));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        let err = provider
            .update_role(
                &ExecutionContext::internal(&state),
                "rid",
                RoleUpdate {
                    name: Some("new_name".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, RoleProviderError::Immutable(id) if id == "rid"));
    }

    #[tokio::test]
    async fn test_update_role_allowed_when_clearing_immutable() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_get_role()
            .withf(|_, id: &'_ str| id == "rid")
            .returning(|_, _| Ok(Some(make_immutable_role("rid", "admin"))));
        backend
            .expect_update_role()
            .withf(|_, id: &'_ str, _| id == "rid")
            .returning(|_, _, _| Ok(make_role("rid", "admin")));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        let result = provider
            .update_role(
                &ExecutionContext::internal(&state),
                "rid",
                RoleUpdate {
                    options: Some(RoleOptions {
                        immutable: Some(false),
                    }),
                    ..Default::default()
                },
            )
            .await;
        assert!(
            result.is_ok(),
            "clearing immutable in the same request must be allowed: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_delete_role_blocked_when_immutable() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_get_role()
            .withf(|_, id: &'_ str| id == "rid")
            .returning(|_, _| Ok(Some(make_immutable_role("rid", "admin"))));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        let err = provider
            .delete_role(&ExecutionContext::internal(&state), "rid")
            .await
            .unwrap_err();
        assert!(matches!(err, RoleProviderError::Immutable(id) if id == "rid"));
    }

    /// Assignment provider expecting exactly one cascade for `role_id`.
    fn assignment_mock_for(role_id: &'static str) -> MockAssignmentProvider {
        let mut mock = MockAssignmentProvider::default();
        mock.expect_delete_assignments_for_role()
            .times(1)
            .withf(move |_, id: &'_ str| id == role_id)
            .returning(|_, _| Ok(()));
        mock
    }

    /// Application credential provider expecting one cascade for `role_id`.
    fn appcred_mock_for(role_id: &'static str) -> MockApplicationCredentialProvider {
        let mut mock = MockApplicationCredentialProvider::default();
        mock.expect_delete_application_credentials_for_role()
            .times(1)
            .withf(move |_, id: &'_ str| id == role_id)
            .returning(|_, _| Ok(()));
        mock
    }

    #[tokio::test]
    async fn test_delete_role_application_credential_failure_is_returned() {
        let mut appcred = MockApplicationCredentialProvider::default();
        appcred
            .expect_delete_application_credentials_for_role()
            .returning(|_, _| Err(ApplicationCredentialProviderError::Driver("boom".into())));
        let mut assignment = MockAssignmentProvider::default();
        assignment
            .expect_delete_assignments_for_role()
            .returning(|_, _| Ok(()));
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_assignment(assignment)
                    .mock_application_credential(appcred),
            ),
        )
        .await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_get_role()
            .returning(|_, _| Ok(Some(make_role("rid", "admin"))));
        backend.expect_delete_role().returning(|_, _| Ok(()));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        let err = provider
            .delete_role(&ExecutionContext::internal(&state), "rid")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            RoleProviderError::ApplicationCredentialProvider { .. }
        ));
    }

    #[tokio::test]
    async fn test_delete_role_cascade_failure_still_invalidates_cache() {
        let mut assignment = MockAssignmentProvider::default();
        assignment
            .expect_delete_assignments_for_role()
            .returning(|_, _| Err(AssignmentProviderError::Driver("boom".into())));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment)),
        )
        .await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_get_role()
            .times(2)
            .returning(|_, _| Ok(Some(make_role("rid", "admin"))));
        backend.expect_delete_role().returning(|_, _| Ok(()));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.get_role(&ctx, "rid").await.unwrap();
            provider.delete_role(&ctx, "rid").await.unwrap_err();
            // Served by the backend again, not by the stale cache.
            provider.get_role(&ctx, "rid").await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn test_delete_role_already_gone_still_revokes_assignments() {
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_assignment(assignment_mock_for("rid"))
                    .mock_application_credential(appcred_mock_for("rid")),
            ),
        )
        .await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_get_role()
            .returning(|_, _| Ok(Some(make_role("rid", "admin"))));
        backend
            .expect_delete_role()
            .returning(|_, _| Err(RoleProviderError::RoleNotFound("rid".into())));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        let err = provider
            .delete_role(&ExecutionContext::internal(&state), "rid")
            .await
            .unwrap_err();
        assert!(matches!(err, RoleProviderError::RoleNotFound(id) if id == "rid"));
    }

    #[tokio::test]
    async fn test_delete_role_revocation_failure_is_returned() {
        let mut assignment = MockAssignmentProvider::default();
        assignment
            .expect_delete_assignments_for_role()
            .returning(|_, _| Err(AssignmentProviderError::Driver("boom".into())));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_assignment(assignment)),
        )
        .await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_get_role()
            .returning(|_, _| Ok(Some(make_role("rid", "admin"))));
        backend.expect_delete_role().returning(|_, _| Ok(()));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        let err = provider
            .delete_role(&ExecutionContext::internal(&state), "rid")
            .await
            .unwrap_err();
        assert!(matches!(err, RoleProviderError::AssignmentProvider { .. }));
    }

    #[tokio::test]
    async fn test_delete_role_not_immutable_proceeds() {
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_assignment(assignment_mock_for("rid"))
                    .mock_application_credential(appcred_mock_for("rid")),
            ),
        )
        .await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_get_role()
            .withf(|_, id: &'_ str| id == "rid")
            .returning(|_, _| Ok(Some(make_role("rid", "admin"))));
        backend
            .expect_delete_role()
            .withf(|_, id: &'_ str| id == "rid")
            .returning(|_, _| Ok(()));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        assert!(
            provider
                .delete_role(&ExecutionContext::internal(&state), "rid")
                .await
                .is_ok()
        );
    }

    // --- Per-request cache (ADR 0030) -------------------------------------

    fn make_role_ref(id: &str) -> RoleRef {
        RoleRefBuilder::default().id(id).build().unwrap()
    }

    fn make_imply(prior: &str, implied: &str) -> RoleImply {
        RoleImplyBuilder::default()
            .prior_role(make_role_ref(prior))
            .implied_role(make_role_ref(implied))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_get_role_hits_backend_once_across_repeated_calls() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_get_role()
            .times(1)
            .withf(|_, id: &'_ str| id == "rid")
            .returning(|_, _| Ok(Some(make_role("rid", "admin"))));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            let first = provider.get_role(&ctx, "rid").await.unwrap().unwrap();
            let second = provider.get_role(&ctx, "rid").await.unwrap().unwrap();
            assert_eq!(first, second);
        })
        .await;
    }

    #[tokio::test]
    async fn test_get_role_not_cached_outside_request_scope() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_get_role()
            .times(2)
            .withf(|_, id: &'_ str| id == "rid")
            .returning(|_, _| Ok(Some(make_role("rid", "admin"))));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        let ctx = ExecutionContext::internal(&state);
        provider.get_role(&ctx, "rid").await.unwrap();
        provider.get_role(&ctx, "rid").await.unwrap();
    }

    #[tokio::test]
    async fn test_update_role_refreshes_cache_instead_of_refetching() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_get_role()
            .times(1)
            .withf(|_, id: &'_ str| id == "rid")
            .returning(|_, _| Ok(Some(make_role("rid", "admin"))));
        backend
            .expect_update_role()
            .withf(|_, id: &'_ str, _| id == "rid")
            .returning(|_, _, update| {
                let mut r = make_role("rid", "admin");
                if let Some(name) = update.name {
                    r.name = name;
                }
                Ok(r)
            });
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.get_role(&ctx, "rid").await.unwrap();

            let updated = provider
                .update_role(
                    &ctx,
                    "rid",
                    RoleUpdate {
                        name: Some("renamed".into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(updated.name, "renamed");

            let refetched = provider.get_role(&ctx, "rid").await.unwrap().unwrap();
            assert_eq!(refetched.name, "renamed");
        })
        .await;
    }

    #[tokio::test]
    async fn test_delete_role_invalidates_cache() {
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_assignment(assignment_mock_for("rid"))
                    .mock_application_credential(appcred_mock_for("rid")),
            ),
        )
        .await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_get_role()
            .times(2)
            .withf(|_, id: &'_ str| id == "rid")
            .returning(|_, _| Ok(Some(make_role("rid", "admin"))));
        backend
            .expect_delete_role()
            .withf(|_, id: &'_ str| id == "rid")
            .returning(|_, _| Ok(()));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.get_role(&ctx, "rid").await.unwrap();
            provider.delete_role(&ctx, "rid").await.unwrap();
            provider.get_role(&ctx, "rid").await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn test_list_role_imply_rules_by_prior_hits_backend_once_across_repeated_calls() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_list_role_imply_rules_by_prior()
            .times(1)
            .withf(|_, id: &'_ str| id == "rid")
            .returning(|_, _| Ok(vec![make_imply("rid", "implied")]));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            let first = provider
                .list_role_imply_rules_by_prior(&ctx, "rid")
                .await
                .unwrap();
            let second = provider
                .list_role_imply_rules_by_prior(&ctx, "rid")
                .await
                .unwrap();
            assert_eq!(first, second);
        })
        .await;
    }

    #[tokio::test]
    async fn test_list_role_imply_rules_by_priors_one_backend_call_for_missing_only() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_list_role_imply_rules_by_priors()
            .times(1)
            .withf(|_, ids: &[&str]| ids == ["a", "b"])
            .returning(|_, _| Ok(vec![make_imply("a", "x")]));
        backend
            .expect_list_role_imply_rules_by_priors()
            .times(1)
            .withf(|_, ids: &[&str]| ids == ["c"])
            .returning(|_, _| Ok(vec![make_imply("c", "y")]));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            let first = provider
                .list_role_imply_rules_by_priors(&ctx, &["a", "b"])
                .await
                .unwrap();
            assert_eq!(first, vec![make_imply("a", "x")]);
            // "a" and "b" (which has no rules) are cached, only "c" is fetched.
            let second = provider
                .list_role_imply_rules_by_priors(&ctx, &["a", "b", "c"])
                .await
                .unwrap();
            assert_eq!(second, vec![make_imply("a", "x"), make_imply("c", "y")]);
            // The single-role lookup shares the cache.
            let single = provider
                .list_role_imply_rules_by_prior(&ctx, "c")
                .await
                .unwrap();
            assert_eq!(single, vec![make_imply("c", "y")]);
        })
        .await;
    }

    #[tokio::test]
    async fn test_list_role_imply_rules_by_prior_caches_empty_result() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_list_role_imply_rules_by_prior()
            .times(1)
            .withf(|_, id: &'_ str| id == "rid")
            .returning(|_, _| Ok(vec![]));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            assert!(
                provider
                    .list_role_imply_rules_by_prior(&ctx, "rid")
                    .await
                    .unwrap()
                    .is_empty()
            );
            // A leaf role with no imply rules is itself a stable answer --
            // must not force a second backend call.
            assert!(
                provider
                    .list_role_imply_rules_by_prior(&ctx, "rid")
                    .await
                    .unwrap()
                    .is_empty()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_list_role_imply_rules_by_prior_not_cached_outside_request_scope() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_list_role_imply_rules_by_prior()
            .times(2)
            .withf(|_, id: &'_ str| id == "rid")
            .returning(|_, _| Ok(vec![make_imply("rid", "implied")]));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        let ctx = ExecutionContext::internal(&state);
        provider
            .list_role_imply_rules_by_prior(&ctx, "rid")
            .await
            .unwrap();
        provider
            .list_role_imply_rules_by_prior(&ctx, "rid")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_create_role_imply_rule_invalidates_by_prior_cache() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_list_role_imply_rules_by_prior()
            .times(2)
            .withf(|_, id: &'_ str| id == "rid")
            .returning(|_, _| Ok(vec![make_imply("rid", "implied")]));
        backend
            .expect_create_role_imply_rule()
            .withf(|_, prior: &'_ str, implied: &'_ str| prior == "rid" && implied == "new-implied")
            .returning(|_, prior, implied| Ok(make_imply(prior, implied)));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider
                .list_role_imply_rules_by_prior(&ctx, "rid")
                .await
                .unwrap();
            provider
                .create_role_imply_rule(&ctx, "rid", "new-implied")
                .await
                .unwrap();
            // Cache entry for "rid" was invalidated by the create -- this
            // call must reach the backend again rather than serve the
            // stale pre-create list.
            provider
                .list_role_imply_rules_by_prior(&ctx, "rid")
                .await
                .unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn test_delete_role_imply_rule_invalidates_by_prior_cache() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_list_role_imply_rules_by_prior()
            .times(2)
            .withf(|_, id: &'_ str| id == "rid")
            .returning(|_, _| Ok(vec![make_imply("rid", "implied")]));
        backend
            .expect_delete_role_imply_rule()
            .withf(|_, prior: &'_ str, implied: &'_ str| prior == "rid" && implied == "implied")
            .returning(|_, _, _| Ok(()));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider
                .list_role_imply_rules_by_prior(&ctx, "rid")
                .await
                .unwrap();
            provider
                .delete_role_imply_rule(&ctx, "rid", "implied")
                .await
                .unwrap();
            provider
                .list_role_imply_rules_by_prior(&ctx, "rid")
                .await
                .unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn test_list_roles_by_ids_fetches_each_role_once_per_request() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend.expect_list_roles().times(2).returning(|_, params| {
            Ok(params
                .ids
                .iter()
                .flatten()
                .filter(|id| *id != "zzz")
                .map(|id| make_role(id, &format!("name-{id}")))
                .collect())
        });
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };
        let params = |ids: &[&str]| RoleListParameters {
            ids: Some(ids.iter().map(|s| s.to_string()).collect()),
            skip_options: true,
            ..Default::default()
        };

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            assert_eq!(
                provider
                    .list_roles(&ctx, &params(&["a"]))
                    .await
                    .unwrap()
                    .len(),
                1
            );
            // "a" is cached, only "b" is fetched.
            let roles = provider
                .list_roles(&ctx, &params(&["a", "b"]))
                .await
                .unwrap();
            assert_eq!(roles.len(), 2);
            // Everything cached: no backend call (the mock allows two).
            assert_eq!(
                provider
                    .list_roles(&ctx, &params(&["b", "a"]))
                    .await
                    .unwrap()
                    .len(),
                2
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_list_roles_with_filters_bypasses_the_request_cache() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_list_roles()
            .times(2)
            .returning(|_, _| Ok(vec![make_role("r", "reader")]));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };
        let params = RoleListParameters {
            name: Some("reader".into()),
            skip_options: true,
            ..Default::default()
        };

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.list_roles(&ctx, &params).await.unwrap();
            provider.list_roles(&ctx, &params).await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn test_all_rules_hit_backend_once_per_request() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_list_role_imply_rules()
            .times(1)
            .returning(|_| Ok(vec![make_imply("a", "b")]));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            let first = provider.list_role_imply_rules(&ctx).await.unwrap();
            let second = provider.list_role_imply_rules(&ctx).await.unwrap();
            assert_eq!(first, second);
        })
        .await;
    }

    #[tokio::test]
    async fn test_all_rules_cache_dropped_on_rule_change() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_list_role_imply_rules()
            .times(2)
            .returning(|_| Ok(vec![make_imply("a", "b")]));
        backend
            .expect_delete_role_imply_rule()
            .returning(|_, _, _| Ok(()));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::ZERO),
        };

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.list_role_imply_rules(&ctx).await.unwrap();
            provider
                .delete_role_imply_rule(&ctx, "a", "b")
                .await
                .unwrap();
            provider.list_role_imply_rules(&ctx).await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn test_process_cache_serves_get_role_across_requests() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_get_role()
            .times(1)
            .returning(|_, _| Ok(Some(make_role("rid", "admin"))));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::from_secs(60)),
        };
        let ctx = ExecutionContext::internal(&state);

        for _ in 0..3 {
            // Each iteration is a separate request scope.
            let role = crate::request_cache::RequestCache::scope(provider.get_role(&ctx, "rid"))
                .await
                .unwrap();
            assert_eq!("admin", role.unwrap().name);
        }
    }

    #[tokio::test]
    async fn test_process_cache_serves_imply_rules_across_requests() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockRoleBackend::default();
        backend
            .expect_list_role_imply_rules()
            .times(1)
            .returning(|_| Ok(Vec::new()));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::from_secs(60)),
        };
        let ctx = ExecutionContext::internal(&state);

        for _ in 0..3 {
            crate::request_cache::RequestCache::scope(provider.list_role_imply_rules(&ctx))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn test_delete_role_invalidates_process_cache() {
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_assignment(assignment_mock_for("rid"))
                    .mock_application_credential(appcred_mock_for("rid")),
            ),
        )
        .await;
        let mut backend = MockRoleBackend::default();
        let mut seq = mockall::Sequence::new();
        backend
            .expect_get_role()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Ok(Some(make_role("rid", "admin"))));
        backend
            .expect_delete_role()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Ok(()));
        backend
            .expect_get_role()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Ok(None));
        let provider = RoleService {
            backend_driver: Arc::new(backend),
            cache: RoleCache::new(Duration::from_secs(60)),
        };
        let ctx = ExecutionContext::internal(&state);

        // The first lookup fills the cache; delete_role's immutability check
        // is then served from it.
        provider.get_role(&ctx, "rid").await.unwrap();
        provider.delete_role(&ctx, "rid").await.unwrap();
        assert!(provider.get_role(&ctx, "rid").await.unwrap().is_none());
    }
}
