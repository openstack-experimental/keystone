// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! # Assignments provider
//!
//! Per ADR 0034 the assignment provider routes each operation to a backend
//! chosen from the assignment's **target**: `system` targets and every
//! unconfigured domain use the global `[assignment] driver`; a domain that
//! stores an `assignment/driver` binding and is mapped by `[assignment.domains]`
//! to a matching `[assignment.backends.<name>]` block uses that block's shared
//! instance. Untargeted listings fan out over every active backend and union
//! the results (§5). The routing table is an immutable [`AssignmentBundle`]
//! swapped in whole on every config / binding change (§9).
use async_trait::async_trait;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use arc_swap::{ArcSwap, ArcSwapOption};
use tokio::sync::RwLock;
use tracing::{error, warn};

use openstack_keystone_config::{AssignmentBackendConfig, Config};
use openstack_keystone_core_types::assignment::*;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::revoke::RevocationEventCreate;
use openstack_keystone_core_types::role::{Role, RoleListParameters};

use crate::assignment::{AssignmentApi, AssignmentProviderError, backend::AssignmentBackend};
use crate::auth::ExecutionContext;
use crate::domain_config::DomainConfigResolver;
use crate::domain_config::backend::DomainConfigBackend;
use crate::domain_config::resolver::effective_domain_config_sources;
use crate::events::AuditDispatchError;
use crate::keystone::ServiceState;
use crate::plugin_manager::{
    PluginManagerApi, build_global_assignment_backend, build_named_assignment_backend,
};
use crate::resource::error::ResourceProviderError;

/// Which target partition an assignment falls in. The partition is closed under
/// Keystone's assignment hierarchy, so routing on it alone is sufficient
/// (ADR 0034 §1).
#[derive(Clone, Copy)]
enum TargetKind {
    Domain,
    Project,
    System,
}

/// The [`TargetKind`] an [`AssignmentType`] targets.
fn target_kind(assignment_type: &AssignmentType) -> TargetKind {
    match assignment_type {
        AssignmentType::UserDomain | AssignmentType::GroupDomain => TargetKind::Domain,
        AssignmentType::UserProject | AssignmentType::GroupProject => TargetKind::Project,
        AssignmentType::UserSystem | AssignmentType::GroupSystem => TargetKind::System,
    }
}

/// An immutable snapshot of everything routing needs: the global backend, the
/// per-instance named backends and the untargeted fan-out set. Rebuilt whole
/// and swapped in behind an [`ArcSwap`] on every config / binding change
/// (ADR 0034 §9); a read never locks.
struct AssignmentBundle {
    /// The global backend: `system` targets, every unconfigured domain and
    /// every resolution fallback (ADR 0034 §4).
    global: Arc<dyn AssignmentBackend>,
    /// `[assignment] driver` — the name [`Self::global`] was built from.
    global_driver_name: String,
    /// Whether per-domain dispatch is live (`[assignment]
    /// domain_specific_drivers_enabled` plus a wired resolver). When off, every
    /// operation uses [`Self::global`].
    dispatch_enabled: bool,
    /// `[assignment.domains]`: domain id → backend block name.
    domains: HashMap<String, String>,
    /// `[assignment.backends.*]`: block name → driver configuration. Retained so
    /// a later rebuild can tell a changed block from an unchanged one and reuse
    /// the live instance in the latter case.
    backend_blocks: HashMap<String, AssignmentBackendConfig>,
    /// Built named instances, block name → backend. One entry per block a
    /// currently bound domain maps to; several domains may share one.
    instances: HashMap<String, Arc<dyn AssignmentBackend>>,
    /// [`Self::global`] plus every distinct [`Self::instances`] value — the set
    /// an untargeted listing fans out over (ADR 0034 §5).
    fanout: Vec<Arc<dyn AssignmentBackend>>,
}

impl AssignmentBundle {
    /// The backend serving `domain_id`'s assignments given its resolved
    /// `assignment/driver` `name` (empty = no binding).
    ///
    /// Mirrors ADR 0034 §4 step 3: an empty or global name resolves cleanly to
    /// the global backend; a *stale* binding — a non-empty, non-global name with
    /// no matching live `[assignment.backends.*]` block (gone / renamed / now a
    /// different driver) — also falls back to the global backend but returns
    /// `true` so the caller can log it once per resolution rather than once per
    /// request.
    fn resolve_named(&self, domain_id: &str, name: &str) -> (Arc<dyn AssignmentBackend>, bool) {
        if name.is_empty() || name == self.global_driver_name {
            return (self.global.clone(), false);
        }
        if let Some(block_name) = self.domains.get(domain_id)
            && let Some(block) = self.backend_blocks.get(block_name)
            && block.driver_name() == name
            && let Some(instance) = self.instances.get(block_name)
        {
            return (instance.clone(), false);
        }
        (self.global.clone(), true)
    }
}

pub struct AssignmentService {
    /// Resolves a domain's effective stored configuration. `Some` only when
    /// `[assignment] domain_specific_drivers_enabled` and at least one
    /// domain-config source is active; `None` disables per-domain dispatch
    /// entirely. Rebuilt from the live configuration on every reload (ADR 0034
    /// §9) from the backend handles in [`Self::dc_file_backend`] /
    /// [`Self::dc_sql_backend`], so flipping the dispatch switch or the source
    /// set takes effect without a restart.
    resolver: ArcSwapOption<DomainConfigResolver>,
    /// The `fs` domain-config backend, captured once at construction so a
    /// reload can re-wire the resolver without a plugin manager. `None` when no
    /// `fs` domain-config driver is registered.
    dc_file_backend: Option<Arc<dyn DomainConfigBackend>>,
    /// The `sql` domain-config backend, same rationale as
    /// [`Self::dc_file_backend`].
    dc_sql_backend: Option<Arc<dyn DomainConfigBackend>>,
    /// The live routing table (ADR 0034 §9).
    bundle: ArcSwap<AssignmentBundle>,
    /// Cache of `domain_id` → resolved `assignment/driver` name (empty string =
    /// no binding, use the global backend). Mirrors
    /// `IdentityService::resolved_driver_cache`; cleared whole on every reload
    /// and every `assignment`-group config write.
    binding_cache: RwLock<HashMap<String, String>>,
}

impl AssignmentService {
    /// Create a new instance of `AssignmentService`.
    ///
    /// # Parameters
    /// - `config`: The system configuration.
    /// - `plugin_manager`: The plugin manager used to resolve the assignment
    ///   backends.
    ///
    /// # Returns
    /// - `Result<Self, AssignmentProviderError>` - The new service instance or
    ///   an error.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, AssignmentProviderError> {
        let global = plugin_manager
            .get_assignment_backend(config.assignment.driver.clone())?
            .clone();

        // Domain-config backend handles for later resolver rebuilds. Captured
        // unconditionally (independent of the current switches, which a reload
        // may flip on) and best-effort — a driver that is not registered is
        // simply unavailable as a source.
        let dc_file_backend = plugin_manager.get_domain_config_backend("fs").ok().cloned();
        let dc_sql_backend = plugin_manager
            .get_domain_config_backend("sql")
            .ok()
            .cloned();

        let (from_files, from_database) = effective_domain_config_sources(config);
        let resolver =
            if config.assignment.domain_specific_drivers_enabled && (from_files || from_database) {
                Some(Arc::new(
                    DomainConfigResolver::new(config, plugin_manager)
                        .map_err(|e| AssignmentProviderError::Driver(e.to_string()))?,
                ))
            } else {
                None
            };

        // `resolver` is built only when the dispatch switch is on and a source
        // is active, so its presence alone is the gate here.
        let dispatch_enabled = resolver.is_some();

        // Bootstrap bundle: the global backend only. The named
        // `[assignment.backends.*]` instances and the fan-out set are populated
        // by the first `reload` — the startup config-reload reactor triggers
        // one, as does every later `[assignment]` / domain-config change.
        // Building them here would need a `ServiceState` to enumerate the bound
        // domains, which does not exist yet at provider construction; until the
        // first reload every operation routes to the global backend, i.e.
        // exactly the pre-ADR-0034 behaviour.
        let bundle = AssignmentBundle {
            global_driver_name: config.assignment.driver.clone(),
            fanout: vec![global.clone()],
            global,
            dispatch_enabled,
            domains: config.assignment.domains.clone(),
            backend_blocks: config.assignment.backends.clone(),
            instances: HashMap::new(),
        };

        Ok(Self {
            resolver: ArcSwapOption::new(resolver),
            dc_file_backend,
            dc_sql_backend,
            bundle: ArcSwap::from_pointee(bundle),
            binding_cache: RwLock::new(HashMap::new()),
        })
    }

    /// Build a service that routes every operation to one backend, with
    /// per-domain dispatch off. Keeps the in-file unit tests that drive a
    /// single mock backend working unchanged.
    #[cfg(test)]
    pub(crate) fn from_backend(backend: Arc<dyn AssignmentBackend>) -> Self {
        let bundle = AssignmentBundle {
            global_driver_name: String::new(),
            dispatch_enabled: false,
            domains: HashMap::new(),
            backend_blocks: HashMap::new(),
            instances: HashMap::new(),
            fanout: vec![backend.clone()],
            global: backend,
        };
        Self {
            resolver: ArcSwapOption::empty(),
            dc_file_backend: None,
            dc_sql_backend: None,
            bundle: ArcSwap::from_pointee(bundle),
            binding_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Build a service with an explicit routing bundle and resolver, bypassing
    /// [`Self::new`]'s plugin-manager backend build. Test-only: lets a
    /// dispatch test wire mock backends straight into the bundle. Per-domain
    /// dispatch is on whenever `resolver` is `Some`. The fan-out set is
    /// derived (global plus every distinct named instance), matching
    /// [`Self::rebuild`].
    #[cfg(test)]
    pub(crate) fn from_parts(
        global_driver_name: impl Into<String>,
        global: Arc<dyn AssignmentBackend>,
        domains: HashMap<String, String>,
        backend_blocks: HashMap<String, AssignmentBackendConfig>,
        instances: HashMap<String, Arc<dyn AssignmentBackend>>,
        resolver: Option<Arc<DomainConfigResolver>>,
    ) -> Self {
        let mut fanout = vec![global.clone()];
        for instance in instances.values() {
            if !fanout.iter().any(|b| Arc::ptr_eq(b, instance)) {
                fanout.push(instance.clone());
            }
        }
        let bundle = AssignmentBundle {
            global,
            global_driver_name: global_driver_name.into(),
            dispatch_enabled: resolver.is_some(),
            domains,
            backend_blocks,
            instances,
            fanout,
        };
        Self {
            resolver: ArcSwapOption::new(resolver),
            dc_file_backend: None,
            dc_sql_backend: None,
            bundle: ArcSwap::from_pointee(bundle),
            binding_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Attach a `sql` domain-config backend handle so [`Self::rebuild`] treats
    /// this service as one that can re-wire its resolver on reload (the
    /// production path). Test-only.
    #[cfg(test)]
    pub(crate) fn with_dc_sql_backend(mut self, backend: Arc<dyn DomainConfigBackend>) -> Self {
        self.dc_sql_backend = Some(backend);
        self
    }

    /// The backend that serves an assignment on `(kind, target_id)`.
    ///
    /// `system` targets and every operation while dispatch is off use the
    /// global backend. Otherwise the dispatch domain is `target_id` for a
    /// domain target, or the owning domain for a project target, and the
    /// domain's resolved `assignment/driver` name selects the backend
    /// (per-domain cached).
    async fn driver_for_target(
        &self,
        ctx: &ExecutionContext<'_>,
        bundle: &AssignmentBundle,
        kind: TargetKind,
        target_id: &str,
    ) -> Result<Arc<dyn AssignmentBackend>, AssignmentProviderError> {
        if !bundle.dispatch_enabled {
            return Ok(bundle.global.clone());
        }
        let resolver = self.resolver.load_full();
        let Some(resolver) = resolver.as_deref() else {
            return Ok(bundle.global.clone());
        };

        let domain_id = match kind {
            // ADR 0034 §1: `system` targets are a closed set with no owning
            // domain; they always use the global backend (which also bounds the
            // §6 escalation blast radius).
            TargetKind::System => return Ok(bundle.global.clone()),
            TargetKind::Domain => target_id.to_string(),
            TargetKind::Project => {
                ctx.state()
                    .provider
                    .get_resource_provider()
                    .get_project(ctx, target_id)
                    .await?
                    .ok_or_else(|| {
                        AssignmentProviderError::from(ResourceProviderError::ProjectNotFound(
                            target_id.to_string(),
                        ))
                    })?
                    .domain_id
            }
        };

        // Read into an owned value in its own statement: a guard held as a
        // `match` scrutinee temporary would still be live in the `None` arm and
        // deadlock the `write().await` below (edition 2024 rescopes `if let`
        // temporaries but not `match` ones).
        let cached = self.binding_cache.read().await.get(&domain_id).cloned();
        let (name, newly_resolved) = match cached {
            Some(name) => (name, false),
            None => {
                let name = match resolver.effective_config(ctx.state(), &domain_id).await {
                    Ok(config) => config.resolve_assignment_driver_name().unwrap_or_default(),
                    Err(error) => {
                        warn!(
                            %domain_id,
                            %error,
                            "assignment domain config resolution failed; using the global driver"
                        );
                        String::new()
                    }
                };
                self.binding_cache
                    .write()
                    .await
                    .insert(domain_id.clone(), name.clone());
                (name, true)
            }
        };

        let (backend, stale) = bundle.resolve_named(&domain_id, &name);
        // Log a stale binding only on the resolution that populated the cache
        // (or the first after a reload clears it), not on every request.
        if stale && newly_resolved {
            warn!(
                %domain_id,
                %name,
                "stale assignment binding: no matching [assignment.backends.*] block; \
                 using the global driver"
            );
        }
        Ok(backend)
    }

    /// Rebuild the routing bundle from the current configuration and the stored
    /// bindings, then clear the binding cache and swap it in (ADR 0034 §9).
    ///
    /// The config read guard is dropped (via an owned clone) before any async
    /// backend build, matching `reconnect_db_on_config_change`. The bundle is
    /// stored only once every fallible step has succeeded, so a failure leaves
    /// the previous bundle in service.
    ///
    /// # Returns
    /// - `Ok(true)` when the swapped-in bundle differs from the previous one.
    async fn rebuild(&self, state: &ServiceState) -> Result<bool, AssignmentProviderError> {
        let config = state.config_manager.config.read().await.clone();
        let prev = self.bundle.load_full();

        let global_driver_name = config.assignment.driver.clone();
        let global = if global_driver_name == prev.global_driver_name {
            prev.global.clone()
        } else {
            build_global_assignment_backend(&config, &global_driver_name).await?
        };

        // Re-wire the resolver from the live configuration (ADR 0034 §9): the
        // dispatch switch and the two source switches can all change across a
        // reload, and a DB-sourced binding written on another node only becomes
        // visible once the resolver is consulted again. The backend handles
        // themselves are stable, captured at construction.
        //
        // A service with no captured handles (the test constructors, and any
        // deployment with neither domain-config driver registered) keeps the
        // resolver it was built with, re-gated on the dispatch switch alone.
        let resolver = if self.dc_file_backend.is_some() || self.dc_sql_backend.is_some() {
            config
                .assignment
                .domain_specific_drivers_enabled
                .then(|| {
                    DomainConfigResolver::from_backends(
                        &config,
                        self.dc_file_backend.clone(),
                        self.dc_sql_backend.clone(),
                    )
                })
                .filter(DomainConfigResolver::has_source)
                .map(Arc::new)
        } else {
            self.resolver
                .load_full()
                .filter(|_| config.assignment.domain_specific_drivers_enabled)
        };
        self.resolver.store(resolver.clone());

        let dispatch_enabled = resolver.is_some();

        let domains = config.assignment.domains.clone();
        let backend_blocks = config.assignment.backends.clone();

        // The blocks a currently bound domain maps to and that actually exist.
        let mut active: HashSet<String> = HashSet::new();
        if let Some(resolver) = &resolver {
            let bound = resolver
                .bound_domains(state)
                .await
                .map_err(|e| AssignmentProviderError::Driver(e.to_string()))?;
            for domain_id in &bound {
                if let Some(block_name) = domains.get(domain_id)
                    && backend_blocks.contains_key(block_name)
                {
                    active.insert(block_name.clone());
                }
            }
        }

        // Reuse a previous instance whenever its block config is byte-for-byte
        // unchanged; otherwise (re)build it from the named block.
        let mut instances: HashMap<String, Arc<dyn AssignmentBackend>> = HashMap::new();
        for block_name in &active {
            let block_cfg = &backend_blocks[block_name];
            let reused = prev
                .instances
                .get(block_name)
                .filter(|_| prev.backend_blocks.get(block_name) == Some(block_cfg));
            let instance = match reused {
                Some(existing) => existing.clone(),
                None => {
                    build_named_assignment_backend(&config, block_cfg.driver_name(), block_name)
                        .await?
                }
            };
            instances.insert(block_name.clone(), instance);
        }

        // Fan-out set (ADR 0034 §5): the global backend plus every distinct
        // active named instance.
        let mut fanout: Vec<Arc<dyn AssignmentBackend>> = vec![global.clone()];
        for instance in instances.values() {
            if !fanout.iter().any(|b| Arc::ptr_eq(b, instance)) {
                fanout.push(instance.clone());
            }
        }

        let changed = !Arc::ptr_eq(&global, &prev.global)
            || dispatch_enabled != prev.dispatch_enabled
            || domains != prev.domains
            || backend_blocks != prev.backend_blocks
            || instances.len() != prev.instances.len()
            || instances.iter().any(|(name, instance)| {
                prev.instances
                    .get(name)
                    .is_none_or(|p| !Arc::ptr_eq(p, instance))
            });

        // Clear the name cache before swapping the bundle in: a request landing
        // in the gap re-resolves against the live domain config and the new
        // bundle, never a stale cached name against the new bundle.
        self.binding_cache.write().await.clear();
        self.bundle.store(Arc::new(AssignmentBundle {
            global,
            global_driver_name,
            dispatch_enabled,
            domains,
            backend_blocks,
            instances,
            fanout,
        }));

        Ok(changed)
    }
}

#[async_trait]
impl AssignmentApi for AssignmentService {
    /// Create assignment grant.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `grant`: The assignment creation parameters.
    ///
    /// # Returns
    /// - `Result<Assignment, AssignmentProviderError>` - The created assignment
    ///   or an error.
    async fn create_grant<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        grant: AssignmentCreate,
    ) -> Result<Assignment, AssignmentProviderError> {
        let bundle = self.bundle.load_full();
        let backend_driver = self
            .driver_for_target(ctx, &bundle, target_kind(&grant.r#type), &grant.target_id)
            .await?;

        let assignment = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &backend_driver;
            let grant_clone = grant.clone();
            let grant_type = grant.r#type;
            let grant_role_id = grant.role_id.clone();
            let grant_actor_id = grant.actor_id.clone();
            let grant_target_id = grant.target_id.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::RoleAssignment {
                        role_id: grant_role_id.clone(),
                        user_id: match grant_type {
                            AssignmentType::UserDomain
                            | AssignmentType::UserProject
                            | AssignmentType::UserSystem => Some(grant_actor_id.clone()),
                            _ => None,
                        },
                        group_id: match grant_type {
                            AssignmentType::GroupDomain
                            | AssignmentType::GroupProject
                            | AssignmentType::GroupSystem => Some(grant_actor_id.clone()),
                            _ => None,
                        },
                        domain_id: match grant_type {
                            AssignmentType::UserDomain | AssignmentType::GroupDomain => {
                                Some(grant_target_id.clone())
                            }
                            _ => None,
                        },
                        project_id: match grant_type {
                            AssignmentType::UserProject | AssignmentType::GroupProject => {
                                Some(grant_target_id.clone())
                            }
                            _ => None,
                        },
                        system_id: match grant_type {
                            AssignmentType::UserSystem | AssignmentType::GroupSystem => {
                                Some(grant_target_id.clone())
                            }
                            _ => None,
                        },
                    },
                ),
                operation: async {
                    backend_driver.create_grant(ctx.state(), grant_clone).await
                },
                on_audit_error: |_: AuditDispatchError| AssignmentProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let assignment = backend_driver.create_grant(ctx.state(), grant).await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::RoleAssignment {
                        role_id: assignment.role_id.clone(),
                        user_id: match &assignment.r#type {
                            AssignmentType::UserDomain
                            | AssignmentType::UserProject
                            | AssignmentType::UserSystem => Some(assignment.actor_id.clone()),
                            _ => None,
                        },
                        group_id: match &assignment.r#type {
                            AssignmentType::GroupDomain
                            | AssignmentType::GroupProject
                            | AssignmentType::GroupSystem => Some(assignment.actor_id.clone()),
                            _ => None,
                        },
                        domain_id: match &assignment.r#type {
                            AssignmentType::UserDomain | AssignmentType::GroupDomain => {
                                Some(assignment.target_id.clone())
                            }
                            _ => None,
                        },
                        project_id: match &assignment.r#type {
                            AssignmentType::UserProject | AssignmentType::GroupProject => {
                                Some(assignment.target_id.clone())
                            }
                            _ => None,
                        },
                        system_id: match &assignment.r#type {
                            AssignmentType::UserSystem | AssignmentType::GroupSystem => {
                                Some(assignment.target_id.clone())
                            }
                            _ => None,
                        },
                    },
                ))
                .await;
            assignment
        };

        Ok(assignment)
    }

    /// List role assignments.
    ///
    /// Target precedence, narrowest first: a `system_id` filter uses the global
    /// backend; a `project_id` filter routes on the owning domain's driver; a
    /// `domain_id` filter routes on that domain's driver. A request carrying
    /// both a project and a domain routes on the project's (narrower) domain.
    /// A fully untargeted listing fans out over every active backend and unions
    /// the results, failing the whole call on the first backend error and
    /// paginating the deduplicated union once (ADR 0034 §5).
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: The parameters for listing assignments.
    ///
    /// # Returns
    /// - `Result<Vec<Assignment>, AssignmentProviderError>` - A list of
    ///   assignments or an error.
    async fn list_role_assignments<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        let bundle = self.bundle.load_full();

        let backends: Vec<Arc<dyn AssignmentBackend>> = if params.system_id.is_some() {
            vec![bundle.global.clone()]
        } else if let Some(project_id) = &params.project_id {
            vec![
                self.driver_for_target(ctx, &bundle, TargetKind::Project, project_id)
                    .await?,
            ]
        } else if let Some(domain_id) = &params.domain_id {
            vec![
                self.driver_for_target(ctx, &bundle, TargetKind::Domain, domain_id)
                    .await?,
            ]
        } else {
            bundle.fanout.clone()
        };

        let mut assignments = if backends.len() == 1 {
            backends[0].list_assignments(ctx.state(), params).await?
        } else {
            let mut seen: HashSet<Assignment> = HashSet::new();
            let mut merged: Vec<Assignment> = Vec::new();
            for backend in &backends {
                for assignment in backend.list_assignments(ctx.state(), params).await? {
                    if seen.insert(assignment.clone()) {
                        merged.push(assignment);
                    }
                }
            }
            paginate_in_memory(&mut merged, &params.pagination);
            merged
        };

        if !assignments.is_empty() && params.include_names.is_some_and(|x| x) {
            let roles: BTreeMap<String, Role> = ctx
                .state()
                .provider
                .get_role_provider()
                .list_roles(ctx, &RoleListParameters::default())
                .await?
                .into_iter()
                .map(|x| (x.id.clone(), x))
                .collect();
            for assignment in assignments.iter_mut() {
                assignment.role_name = roles.get(&assignment.role_id).map(|role| role.name.clone());
            }
        }

        Ok(assignments)
    }

    /// Revoke grant.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `grant`: The assignment to revoke.
    ///
    /// # Returns
    /// - `Result<(), AssignmentProviderError>` - Ok on success, or an error.
    async fn revoke_grant<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        grant: Assignment,
    ) -> Result<(), AssignmentProviderError> {
        let user_id = match &grant.r#type {
            AssignmentType::UserDomain
            | AssignmentType::UserProject
            | AssignmentType::UserSystem => Some(grant.actor_id.clone()),
            AssignmentType::GroupDomain
            | AssignmentType::GroupProject
            | AssignmentType::GroupSystem => None,
        };

        let (project_id, domain_id) = match &grant.r#type {
            AssignmentType::UserProject | AssignmentType::GroupProject => {
                (Some(grant.target_id.clone()), None)
            }
            AssignmentType::UserDomain | AssignmentType::GroupDomain => {
                (None, Some(grant.target_id.clone()))
            }
            AssignmentType::UserSystem | AssignmentType::GroupSystem => (None, None),
        };

        let role_id = grant.role_id.clone();

        let bundle = self.bundle.load_full();
        let backend_driver = self
            .driver_for_target(ctx, &bundle, target_kind(&grant.r#type), &grant.target_id)
            .await?;

        if let Some(vsc) = ctx.ctx() {
            let backend_driver = &backend_driver;
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::RoleAssignment {
                        role_id: role_id.clone(),
                        user_id: match &grant.r#type {
                            AssignmentType::UserDomain
                            | AssignmentType::UserProject
                            | AssignmentType::UserSystem => Some(grant.actor_id.clone()),
                            _ => None,
                        },
                        group_id: match &grant.r#type {
                            AssignmentType::GroupDomain
                            | AssignmentType::GroupProject
                            | AssignmentType::GroupSystem => Some(grant.actor_id.clone()),
                            _ => None,
                        },
                        domain_id: match &grant.r#type {
                            AssignmentType::UserDomain | AssignmentType::GroupDomain => {
                                Some(grant.target_id.clone())
                            }
                            _ => None,
                        },
                        project_id: match &grant.r#type {
                            AssignmentType::UserProject | AssignmentType::GroupProject => {
                                Some(grant.target_id.clone())
                            }
                            _ => None,
                        },
                        system_id: match &grant.r#type {
                            AssignmentType::UserSystem | AssignmentType::GroupSystem => {
                                Some(grant.target_id.clone())
                            }
                            _ => None,
                        },
                    },
                ),
                operation: async {
                    backend_driver.revoke_grant(ctx.state(), &grant).await
                },
                on_audit_error: |_: AuditDispatchError| AssignmentProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            backend_driver.revoke_grant(ctx.state(), &grant).await?;
        }

        let revocation_event = RevocationEventCreate {
            domain_id,
            project_id,
            user_id,
            role_id: Some(role_id),
            trust_id: None,
            consumer_id: None,
            access_token_id: None,
            issued_before: chrono::Utc::now(),
            expires_at: None,
            audit_id: None,
            audit_chain_id: None,
            revoked_at: chrono::Utc::now(),
        };

        // ADR 0034 §4: the central revocation event stays on the global revoke
        // provider, unrouted — it is not an assignment-backend operation.
        ctx.state()
            .provider
            .get_revoke_provider()
            .create_revocation_event(ctx, revocation_event)
            .await?;
        // ADR 0031 "Tokens": revoking a grant cascades revocation of every
        // token carrying that role - `"cascade"`, not a direct user request.
        crate::token::TOKEN_METRICS.revoked_total.inc(["cascade"]);

        Ok(())
    }

    async fn reload(&self, state: &ServiceState) -> Result<bool, AssignmentProviderError> {
        match self.rebuild(state).await {
            Ok(changed) => Ok(changed),
            Err(error) => {
                error!(
                    %error,
                    "assignment driver reload failed; retaining last-known-good bundle"
                );
                Ok(false)
            }
        }
    }

    async fn refresh_bindings(&self, state: &ServiceState) -> Result<(), AssignmentProviderError> {
        if let Err(error) = self.rebuild(state).await {
            warn!(
                %error,
                "assignment binding refresh failed; fan-out set will self-heal on the next reload"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "service/tests.rs"]
mod tests;
