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
//! # Resource provider
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::identity::{
    GroupListParameters, IdentityProviderError, UserListParameters,
};
use openstack_keystone_core_types::resource::*;

use crate::auth::{ExecutionContext, scope_domain_id};
use crate::events::AuditDispatchError;
use crate::plugin_manager::PluginManagerApi;
use crate::request_cache::{cache_get, cache_remove, cache_set};
use crate::resource::{ResourceApi, ResourceProviderError, backend::ResourceBackend};

/// Request-cache namespace for [`Domain`] lookups by `domain_id`.
const DOMAIN_CACHE_NS: &str = "resource.domain";
/// Request-cache namespace for [`Project`] lookups by `project_id`.
const PROJECT_CACHE_NS: &str = "resource.project";
/// Request-cache namespace for [`DomainRef`] lookups by `domain_id`. Kept
/// apart from [`DOMAIN_CACHE_NS`], which holds the full domain.
const DOMAIN_REF_CACHE_NS: &str = "resource.domain_ref";
/// Request-cache namespace for [`ProjectRef`] lookups by `project_id`. Kept
/// apart from [`PROJECT_CACHE_NS`]: the short form is what the authentication
/// and authorization code reads, and is dropped together with the full entry
/// on every change of the project.
const PROJECT_REF_CACHE_NS: &str = "resource.project_ref";
/// Request-cache namespace for a project's ancestor chain
/// (`Vec<Project>`) by `project_id`. Safe to cache because `parent_id` is
/// immutable after creation (`ProjectUpdate` has no `parent_id` field), so
/// the ancestor *chain* for a given project never changes -- only the
/// individual ancestor `Project` rows within it could go stale if one of
/// them is updated later in the same request. That's the same accepted,
/// request-scoped staleness window as ADR 0030's "known, accepted race";
/// this cache is not reverse-indexed by ancestor id to invalidate on their
/// updates too, since that's real complexity for a risk this narrow.
const PROJECT_PARENTS_CACHE_NS: &str = "resource.project_parents";
/// Request-scoped namespace for the project parent IDs.
const PROJECT_PARENT_IDS_CACHE_NS: &str = "resource.project_parent_ids";
/// Request-scoped namespace for the project domain ID.
const PROJECT_DOMAIN_ID_CACHE_NS: &str = "resource.project_domain_id";

/// Upper bound of the entries of each process-wide cache. The caches are
/// emptied when they reach it, which keeps the memory bounded without an
/// eviction policy.
const PROCESS_CACHE_MAX_ENTRIES: usize = 100_000;

pub struct ResourceService {
    backend_driver: Arc<dyn ResourceBackend>,
    /// Caching flag (`[resource] caching`). When enabled the facts that never
    /// change for a project are kept in the process memory.
    caching: bool,
    /// `project_id` to `domain_id`. The domain of a project cannot be updated.
    project_domain_id_cache: RwLock<HashMap<String, String>>,
    /// `project_id` to the IDs of its parents, the closest first. `parent_id`
    /// cannot be updated, so the chain is fixed for the life of the project.
    project_parent_ids_cache: RwLock<HashMap<String, Vec<String>>>,
}

impl ResourceService {
    /// Create a new `ResourceService`.
    ///
    /// # Parameters
    /// - `config`: The service configuration.
    /// - `plugin_manager`: The plugin manager used to resolve the backend
    ///   driver.
    ///
    /// # Returns
    /// - `Result<Self, ResourceProviderError>` - The initialized
    ///   `ResourceService` or an error.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, ResourceProviderError> {
        let backend_driver = plugin_manager
            .get_resource_backend(config.resource.driver.clone())?
            .clone();
        Ok(Self::with_backend(backend_driver, config.resource.caching))
    }

    /// Create the service on top of the backend driver.
    pub(crate) fn with_backend(backend_driver: Arc<dyn ResourceBackend>, caching: bool) -> Self {
        Self {
            backend_driver,
            caching,
            project_domain_id_cache: RwLock::new(HashMap::new()),
            project_parent_ids_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Resolve the `domain_id` a new project should be created in.
    ///
    /// Mirrors python-keystone's project-create semantics:
    /// - `is_domain=true`: the project is its own domain, `domain_id` must not
    ///   be given.
    /// - `domain_id` and `parent_id` both given: they must agree (parent's
    ///   domain).
    /// - only `parent_id` given: inherit the parent's domain.
    /// - only `domain_id` given: use it as-is.
    /// - neither given: fall back to the domain the caller's token is scoped
    ///   to.
    async fn resolve_project_domain_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        new_project: &ProjectCreate,
        project_id: &str,
    ) -> Result<String, ResourceProviderError> {
        if new_project.is_domain {
            return if new_project.domain_id.is_some() {
                Err(ResourceProviderError::InvalidProjectDomain(
                    "domain_id must not be specified when is_domain is true".into(),
                ))
            } else {
                Ok(project_id.to_string())
            };
        }

        match (&new_project.domain_id, &new_project.parent_id) {
            (Some(domain_id), Some(parent_id)) => {
                let parent_domain_id = self.parent_domain_id(ctx, parent_id).await?;
                if &parent_domain_id != domain_id {
                    return Err(ResourceProviderError::InvalidProjectDomain(format!(
                        "domain_id {domain_id} does not match parent project's domain {parent_domain_id}"
                    )));
                }
                Ok(domain_id.clone())
            }
            (Some(domain_id), None) => Ok(domain_id.clone()),
            (None, Some(parent_id)) => self.parent_domain_id(ctx, parent_id).await,
            (None, None) => scope_domain_id(ctx).ok_or_else(|| {
                ResourceProviderError::InvalidProjectDomain(
                    "domain_id could not be determined: not specified, no parent_id, and no scoped token domain".into(),
                )
            }),
        }
    }

    /// Resolve the `domain_id` that `parent_id` belongs to.
    ///
    /// `parent_id` may be a regular project or a domain's root (`is_domain`)
    /// project -- the latter is how a project is created directly under a
    /// domain, matching python-keystone where domains are themselves
    /// projects.
    async fn parent_domain_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        parent_id: &str,
    ) -> Result<String, ResourceProviderError> {
        if let Some(parent) = self.get_project(ctx, parent_id).await? {
            return Ok(parent.domain_id);
        }
        if self.get_domain(ctx, parent_id).await?.is_some() {
            return Ok(parent_id.to_string());
        }
        Err(ResourceProviderError::ProjectNotFound(
            parent_id.to_string(),
        ))
    }

    /// Reject the operation when the project is currently immutable and the
    /// request does not itself clear the flag.
    ///
    /// Mirrors Python Keystone: a resource with `options.immutable == true`
    /// rejects update/delete unless the update explicitly sets
    /// `immutable: false` in the same request. Pass `new_options: None` for
    /// delete, which can never clear the flag. When the project does not
    /// exist, this is a no-op -- the caller's own lookup surfaces
    /// `ProjectNotFound`.
    async fn check_project_mutable<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
        new_options: Option<&ProjectOptions>,
    ) -> Result<(), ResourceProviderError> {
        if let Some(current) = self.get_project(ctx, project_id).await?
            && current.options.immutable == Some(true)
            && new_options.and_then(|o| o.immutable) != Some(false)
        {
            return Err(ResourceProviderError::Immutable(project_id.to_string()));
        }
        Ok(())
    }

    /// Delete everything the domain owns before the domain itself.
    ///
    /// Projects go leaf first, then the users and groups, then the grants on
    /// the domain. Every deletion goes through the owning provider, so the
    /// per-entity cascades (credentials, application credentials, trusts,
    /// assignments) and audit events run as for a direct delete. Users and
    /// groups of a read-only identity backend are not ours to remove and are
    /// skipped. The cascade is idempotent: a failure leaves the domain in
    /// place and a retry resumes with what is left. The same holds for each
    /// entity: deleting one that is already gone still runs its cascade.
    async fn delete_domain_contents<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
    ) -> Result<(), ResourceProviderError> {
        let projects = self
            .backend_driver
            .list_projects(
                ctx.state(),
                &ProjectListParameters {
                    domain_id: Some(domain_id.to_string()),
                    ..Default::default()
                },
            )
            .await?;
        let identity = ctx.state().provider.get_identity_provider();
        let users = identity
            .list_users(
                ctx,
                &UserListParameters {
                    domain_id: Some(domain_id.to_string()),
                    ..Default::default()
                },
            )
            .await?;
        let groups = identity
            .list_groups(
                ctx,
                &GroupListParameters {
                    domain_id: Some(domain_id.to_string()),
                    ..Default::default()
                },
            )
            .await?;
        // The cascade is destructive: an enabled domain is only deleted when
        // there is nothing to cascade into. Existing callers that delete an
        // empty domain are unaffected.
        let has_contents =
            projects.iter().any(|x| x.id != domain_id) || !users.is_empty() || !groups.is_empty();
        if has_contents
            && self
                .get_domain(ctx, domain_id)
                .await?
                .is_some_and(|x| x.enabled)
        {
            return Err(ResourceProviderError::DomainEnabled(domain_id.to_string()));
        }
        let parents: HashMap<&str, &str> = projects
            .iter()
            .filter_map(|x| x.parent_id.as_deref().map(|p| (x.id.as_str(), p)))
            .collect();
        // Children before their parents: the deeper the project, the earlier.
        let depth = |id: &str| {
            let mut depth = 0usize;
            let mut cur = id;
            // Bounded by the number of projects: a corrupt parent loop must
            // not hang the delete.
            while let Some(parent) = parents.get(cur) {
                depth += 1;
                cur = parent;
                if depth > projects.len() {
                    break;
                }
            }
            depth
        };
        let mut ordered: Vec<(usize, &str)> = projects
            .iter()
            .filter(|x| x.id != domain_id)
            .map(|x| (depth(&x.id), x.id.as_str()))
            .collect();
        ordered.sort_by_key(|a| std::cmp::Reverse(a.0));
        for (_, id) in ordered {
            match self.delete_project(ctx, id).await {
                Ok(()) | Err(ResourceProviderError::ProjectNotFound(_)) => {}
                Err(err) => return Err(err),
            }
        }

        for user in &users {
            match identity.delete_user(ctx, &user.id).await {
                Ok(())
                | Err(IdentityProviderError::UserNotFound(_))
                | Err(IdentityProviderError::Readonly(_)) => {}
                Err(err) => return Err(err.into()),
            }
        }
        for group in &groups {
            match identity.delete_group(ctx, &group.id).await {
                Ok(())
                | Err(IdentityProviderError::GroupNotFound(_))
                | Err(IdentityProviderError::Readonly(_)) => {}
                Err(err) => return Err(err.into()),
            }
        }

        ctx.state()
            .provider
            .get_assignment_provider()
            .delete_assignments_for_domain(ctx, domain_id)
            .await?;
        Ok(())
    }

    /// Reject the operation when the domain is currently immutable and the
    /// request does not itself clear the flag. See
    /// [`check_project_mutable`](Self::check_project_mutable) -- a domain is
    /// a project row with `is_domain = true` sharing the same semantics.
    async fn check_domain_mutable<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        new_options: Option<&ProjectOptions>,
    ) -> Result<(), ResourceProviderError> {
        if let Some(current) = self.get_domain(ctx, domain_id).await?
            && current.options.immutable == Some(true)
            && new_options.and_then(|o| o.immutable) != Some(false)
        {
            return Err(ResourceProviderError::Immutable(domain_id.to_string()));
        }
        Ok(())
    }
}

#[async_trait]
impl ResourceApi for ResourceService {
    /// Create a new domain.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain`: The domain details to create.
    ///
    /// # Returns
    /// - `Result<Domain, ResourceProviderError>` - The created `Domain` or an
    ///   error.
    #[tracing::instrument(name = "provider.resource.create_domain", level = "debug", skip_all)]
    async fn create_domain<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain: DomainCreate,
    ) -> Result<Domain, ResourceProviderError> {
        let mut new_domain = domain;
        let domain_id = if let Some(ref did) = new_domain.id {
            did.clone()
        } else {
            let did = Uuid::new_v4().simple().to_string();
            new_domain.id = Some(did.clone());
            did
        };
        new_domain.validate()?;
        let domain = crate::audited_if_ctx! {
            ctx: ctx,
            event: Event::new(
                Operation::Create,
                EventPayload::Domain { id: domain_id.clone() },
            ),
            operation: async {
                self.backend_driver.create_domain(ctx.state(), new_domain).await
            },
            on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
        }?;

        Ok(domain)
    }

    /// Create a new project.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `project`: The project details to create.
    ///
    /// # Returns
    /// - `Result<Project, ResourceProviderError>` - The created `Project` or an
    ///   error.
    #[tracing::instrument(name = "provider.resource.create_project", level = "debug", skip_all)]
    async fn create_project<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project: ProjectCreate,
    ) -> Result<Project, ResourceProviderError> {
        let mut new_project = project;
        let project_id = if let Some(ref pid) = new_project.id {
            pid.clone()
        } else {
            let pid = Uuid::new_v4().simple().to_string();
            new_project.id = Some(pid.clone());
            pid
        };
        new_project.domain_id = Some(
            self.resolve_project_domain_id(ctx, &new_project, &project_id)
                .await?,
        );
        new_project.validate()?;
        let project = crate::audited_if_ctx! {
            ctx: ctx,
            event: Event::new(
                Operation::Create,
                EventPayload::Project { id: project_id.clone() },
            ),
            operation: async {
                self.backend_driver.create_project(ctx.state(), new_project).await
            },
            on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
        }?;

        Ok(project)
    }

    /// Add a single tag to a project.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `project_id`: The ID of the project.
    /// - `tag`: The tag to add.
    #[tracing::instrument(name = "provider.resource.create_project_tag", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn create_project_tag<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
        tag: &'a str,
    ) -> Result<(), ResourceProviderError> {
        validate_project_tag(tag).map_err(|e| {
            let mut errors = validator::ValidationErrors::new();
            errors.add("tag", e);
            errors
        })?;
        self.check_project_mutable(ctx, project_id, None).await?;
        crate::audited_if_ctx! {
            ctx: ctx,
            event: Event::new(
                Operation::Update,
                EventPayload::Project { id: project_id.to_string() },
            ),
            operation: async {
                self.backend_driver.create_project_tag(ctx.state(), project_id, tag).await
            },
            on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
        }?;
        cache_remove(PROJECT_CACHE_NS, project_id);
        cache_remove(PROJECT_REF_CACHE_NS, project_id);
        Ok(())
    }

    /// Delete a domain by the ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The ID of the domain to delete.
    ///
    /// # Returns
    /// - `Result<(), ResourceProviderError>` - `Ok(())` if successful, or an
    ///   error.
    #[tracing::instrument(name = "provider.resource.delete_domain", level = "debug", skip_all, fields(domain_id = %id))]
    async fn delete_domain<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), ResourceProviderError> {
        self.check_domain_mutable(ctx, id, None).await?;
        crate::audited_if_ctx! {
            ctx: ctx,
            event: Event::new(
                Operation::Delete,
                EventPayload::Domain { id: id.to_string() },
            ),
            operation: async {
                self.delete_domain_contents(ctx, id).await?;
                self.backend_driver.delete_domain(ctx.state(), id).await?;
                ctx.state()
                    .provider
                    .get_idmapping_provider()
                    .delete_mappings_for_domain(ctx, id)
                    .await?;
                Ok::<(), ResourceProviderError>(())
            },
            on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
        }?;

        cache_remove(DOMAIN_CACHE_NS, id);
        cache_remove(DOMAIN_REF_CACHE_NS, id);
        if self.caching {
            // The projects of the domain are deleted with it: forget them.
            self.project_domain_id_cache
                .write()
                .await
                .retain(|_, domain_id| domain_id != id);
            // The chains are keyed by project and carry no domain: drop all.
            self.project_parent_ids_cache.write().await.clear();
        }
        Ok(())
    }

    /// Delete a project by the ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The ID of the project to delete.
    ///
    /// # Returns
    /// - `Result<(), ResourceProviderError>` - `Ok(())` if successful, or an
    ///   error.
    #[tracing::instrument(name = "provider.resource.delete_project", level = "debug", skip_all, fields(project_id = %id))]
    async fn delete_project<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), ResourceProviderError> {
        self.check_project_mutable(ctx, id, None).await?;
        let result = crate::audited_if_ctx! {
            ctx: ctx,
            event: Event::new(
                Operation::Delete,
                EventPayload::Project { id: id.to_string() },
            ),
            operation: async {
                // See `IdentityService::delete_user`: a project that an
                // earlier attempt already deleted still gets its dependents
                // removed, then the NotFound is returned.
                let deleted = match self.backend_driver.delete_project(ctx.state(), id).await {
                    Ok(()) => Ok(()),
                    Err(err @ ResourceProviderError::ProjectNotFound(_)) => Err(err),
                    Err(err) => return Err(err),
                };
                ctx.state()
                    .provider
                    .get_credential_provider()
                    .delete_credentials_for_project(ctx, id)
                    .await?;
                ctx.state()
                    .provider
                    .get_application_credential_provider()
                    .delete_application_credentials_for_project(ctx, id)
                    .await?;
                ctx.state()
                    .provider
                    .get_assignment_provider()
                    .delete_assignments_for_project(ctx, id)
                    .await?;
                deleted
            },
            on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
        };

        // The project row may be gone even when a cascade step failed: drop
        // the cached entries before the result is returned.
        cache_remove(PROJECT_CACHE_NS, id);

        cache_remove(PROJECT_REF_CACHE_NS, id);
        cache_remove(PROJECT_PARENTS_CACHE_NS, id);
        cache_remove(PROJECT_PARENT_IDS_CACHE_NS, id);
        cache_remove(PROJECT_DOMAIN_ID_CACHE_NS, id);
        if self.caching {
            self.project_domain_id_cache.write().await.remove(id);
            // A chain that passes through the deleted project goes too.
            self.project_parent_ids_cache
                .write()
                .await
                .retain(|key, parents| key != id && !parents.iter().any(|parent| parent == id));
        }
        result
    }

    /// Delete a single tag from a project.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `project_id`: The ID of the project.
    /// - `tag`: The tag to delete.
    #[tracing::instrument(name = "provider.resource.delete_project_tag", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn delete_project_tag<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
        tag: &'a str,
    ) -> Result<(), ResourceProviderError> {
        self.check_project_mutable(ctx, project_id, None).await?;
        crate::audited_if_ctx! {
            ctx: ctx,
            event: Event::new(
                Operation::Update,
                EventPayload::Project { id: project_id.to_string() },
            ),
            operation: async {
                self.backend_driver.delete_project_tag(ctx.state(), project_id, tag).await
            },
            on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
        }?;
        cache_remove(PROJECT_CACHE_NS, project_id);
        cache_remove(PROJECT_REF_CACHE_NS, project_id);
        Ok(())
    }

    /// Find a single domain by its name.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_name`: The name of the domain.
    ///
    /// # Returns
    /// - A `Result` containing an `Option` with the `Domain` if found, or an
    ///   `Error`.
    #[tracing::instrument(
        name = "provider.resource.find_domain_by_name",
        level = "debug",
        skip_all
    )]
    async fn find_domain_by_name<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_name: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        self.backend_driver
            .get_domain_by_name(ctx.state(), domain_name)
            .await
    }

    /// Get a single domain.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain.
    ///
    /// # Returns
    /// - A `Result` containing an `Option` with the `Domain` if found, or an
    ///   `Error`.
    #[tracing::instrument(name = "provider.resource.get_domain", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn get_domain<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        if let Some(domain) = cache_get::<Domain>(DOMAIN_CACHE_NS, domain_id) {
            return Ok(Some(domain));
        }
        let domain = self
            .backend_driver
            .get_domain(ctx.state(), domain_id)
            .await?;
        if let Some(domain) = &domain {
            cache_set(DOMAIN_CACHE_NS, domain_id, domain.clone());
        }
        Ok(domain)
    }

    /// Get the short representation of a domain.
    ///
    /// Served from the full domain when the request already loaded one,
    /// otherwise from the short-domain request cache or the backend, which
    /// does not load the domain options.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `domain_id`: The ID of the domain.
    ///
    /// # Returns
    /// - A `Result` containing an `Option` with the `DomainRef` if found, or an
    ///   `Error`.
    #[tracing::instrument(name = "provider.resource.get_domain_ref", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn get_domain_ref<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
    ) -> Result<Option<DomainRef>, ResourceProviderError> {
        if let Some(domain) = cache_get::<Domain>(DOMAIN_CACHE_NS, domain_id) {
            return Ok(Some(DomainRef::from(domain)));
        }
        if let Some(domain) = cache_get::<DomainRef>(DOMAIN_REF_CACHE_NS, domain_id) {
            return Ok(Some(domain));
        }
        let domain = self
            .backend_driver
            .get_domain_ref(ctx.state(), domain_id)
            .await?;
        if let Some(domain) = &domain {
            cache_set(DOMAIN_REF_CACHE_NS, domain_id, domain.clone());
        }
        Ok(domain)
    }

    /// Check whether the domain is enabled.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain.
    ///
    /// # Returns
    /// - `Result<bool, ResourceProviderError>` - Whether the domain is enabled
    ///   or an error.
    #[tracing::instrument(name = "provider.resource.get_domain_enabled", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn get_domain_enabled<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
    ) -> Result<bool, ResourceProviderError> {
        self.backend_driver
            .get_domain_enabled(ctx.state(), domain_id)
            .await
    }

    /// Get a single project.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `project_id`: The ID of the project.
    ///
    /// # Returns
    /// - A `Result` containing an `Option` with the `Project` if found, or an
    ///   `Error`.
    #[tracing::instrument(name = "provider.resource.get_project", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn get_project<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        if let Some(project) = cache_get::<Project>(PROJECT_CACHE_NS, project_id) {
            return Ok(Some(project));
        }
        let project = self
            .backend_driver
            .get_project(ctx.state(), project_id)
            .await?;
        if let Some(project) = &project {
            cache_set(PROJECT_CACHE_NS, project_id, project.clone());
        }
        Ok(project)
    }

    /// Get the short representation of a project (no options and tags).
    ///
    /// Served from the request cache: a full [`Project`] already fetched in
    /// the request is reused, and the short form itself is cached, so the
    /// repeated project lookups of an authorization (the caller and the
    /// subject) cost one query on the project row at most.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `project_id`: The ID of the project.
    ///
    /// # Returns
    /// - A `Result` containing an `Option` with the `ProjectRef` if found, or
    ///   an `Error`.
    #[tracing::instrument(name = "provider.resource.get_project_ref", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn get_project_ref<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<Option<ProjectRef>, ResourceProviderError> {
        if let Some(project) = cache_get::<Project>(PROJECT_CACHE_NS, project_id) {
            return Ok(Some(ProjectRef::from(project)));
        }
        if let Some(project) = cache_get::<ProjectRef>(PROJECT_REF_CACHE_NS, project_id) {
            return Ok(Some(project));
        }
        let project = self
            .backend_driver
            .get_project_ref(ctx.state(), project_id)
            .await?;
        if let Some(project) = &project {
            cache_set(PROJECT_REF_CACHE_NS, project_id, project.clone());
        }
        Ok(project)
    }

    /// Get a single project by name and domain ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `name`: The name of the project.
    /// - `domain_id`: The ID of the domain.
    ///
    /// # Returns
    /// - A `Result` containing an `Option` with the `Project` if found, or an
    ///   `Error`.
    #[tracing::instrument(name = "provider.resource.get_project_by_name", level = "debug", skip_all, fields(name = %name, domain_id = %domain_id))]
    async fn get_project_by_name<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        name: &'a str,
        domain_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        self.backend_driver
            .get_project_by_name(ctx.state(), name, domain_id)
            .await
    }

    /// Get the ID of the domain a project belongs to.
    ///
    /// With `[resource] caching` the value is kept in the process memory: the
    /// domain of a project never changes.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `project_id`: The ID of the project.
    ///
    /// # Returns
    /// - A `Result` containing an `Option` with the domain ID if the project
    ///   exists, or an `Error`.
    #[tracing::instrument(name = "provider.resource.get_project_domain_id", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn get_project_domain_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<Option<String>, ResourceProviderError> {
        if let Some(project) = cache_get::<Project>(PROJECT_CACHE_NS, project_id) {
            return Ok(Some(project.domain_id));
        }
        if let Some(project) = cache_get::<ProjectRef>(PROJECT_REF_CACHE_NS, project_id) {
            return Ok(Some(project.domain_id));
        }
        if let Some(domain_id) = cache_get::<String>(PROJECT_DOMAIN_ID_CACHE_NS, project_id) {
            return Ok(Some(domain_id));
        }
        if self.caching
            && let Some(domain_id) = self.project_domain_id_cache.read().await.get(project_id)
        {
            return Ok(Some(domain_id.clone()));
        }
        let domain_id = self
            .backend_driver
            .get_project_domain_id(ctx.state(), project_id)
            .await?;
        if let Some(domain_id) = &domain_id {
            cache_set(PROJECT_DOMAIN_ID_CACHE_NS, project_id, domain_id.clone());
            if self.caching {
                let mut cache = self.project_domain_id_cache.write().await;
                if cache.len() >= PROCESS_CACHE_MAX_ENTRIES {
                    cache.clear();
                }
                cache.insert(project_id.to_string(), domain_id.clone());
            }
        }
        Ok(domain_id)
    }

    /// Get the IDs of the project parents.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `project_id`: The ID of the project.
    ///
    /// # Returns
    /// - A `Result` containing an `Option` with the parent IDs, the closest
    ///   first, if the project exists, or an `Error`.
    #[tracing::instrument(name = "provider.resource.get_project_parent_ids", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn get_project_parent_ids<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<Option<Vec<String>>, ResourceProviderError> {
        // Request scope first: whatever the request already loaded is as
        // fresh as the request itself, no matter the `caching` setting.
        if let Some(parents) = cache_get::<Vec<String>>(PROJECT_PARENT_IDS_CACHE_NS, project_id) {
            return Ok(Some(parents));
        }
        if let Some(parents) = cache_get::<Vec<Project>>(PROJECT_PARENTS_CACHE_NS, project_id) {
            return Ok(Some(parents.into_iter().map(|parent| parent.id).collect()));
        }
        if self.caching
            && let Some(parents) = self.project_parent_ids_cache.read().await.get(project_id)
        {
            return Ok(Some(parents.clone()));
        }
        let parents = self
            .backend_driver
            .get_project_parent_ids(ctx.state(), project_id)
            .await?;
        if let Some(parents) = &parents {
            cache_set(PROJECT_PARENT_IDS_CACHE_NS, project_id, parents.clone());
            if self.caching {
                let mut cache = self.project_parent_ids_cache.write().await;
                if cache.len() >= PROCESS_CACHE_MAX_ENTRIES {
                    cache.clear();
                }
                cache.insert(project_id.to_string(), parents.clone());
            }
        }
        Ok(parents)
    }

    /// Get project parents.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `project_id`: The ID of the project.
    ///
    /// # Returns
    /// - A `Result` containing an `Option` with the `Vec<Project>` if found, or
    ///   an `Error`.
    #[tracing::instrument(name = "provider.resource.get_project_parents", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn get_project_parents<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<Option<Vec<Project>>, ResourceProviderError> {
        if let Some(parents) = cache_get::<Vec<Project>>(PROJECT_PARENTS_CACHE_NS, project_id) {
            return Ok(Some(parents));
        }
        let parents = self
            .backend_driver
            .get_project_parents(ctx.state(), project_id)
            .await?;
        if let Some(parents) = &parents {
            cache_set(PROJECT_PARENTS_CACHE_NS, project_id, parents.clone());
        }
        Ok(parents)
    }

    /// Get project subtree (all descendants).
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `project_id`: The ID of the project.
    ///
    /// # Returns
    /// - A `Result` containing an `Option` with the descendants of the project
    ///   ordered breadth first if the project exists, or an `Error`.
    #[tracing::instrument(name = "provider.resource.get_project_subtree", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn get_project_subtree<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<Option<Vec<Project>>, ResourceProviderError> {
        self.backend_driver
            .get_project_subtree(ctx.state(), project_id)
            .await
    }

    /// List domains.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: The list parameters.
    ///
    /// # Returns
    /// - `Result<Vec<Domain>, ResourceProviderError>` - A list of domains or an
    ///   error.
    #[tracing::instrument(name = "provider.resource.list_domains", level = "debug", skip_all, fields(params = ?params))]
    async fn list_domains<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &DomainListParameters,
    ) -> Result<Vec<Domain>, ResourceProviderError> {
        self.backend_driver.list_domains(ctx.state(), params).await
    }

    /// List the tags of a project.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `project_id`: The ID of the project.
    ///
    /// # Returns
    /// - The sorted tags, or `ProjectNotFound`.
    #[tracing::instrument(name = "provider.resource.list_project_tags", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn list_project_tags<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<Vec<String>, ResourceProviderError> {
        self.backend_driver
            .list_project_tags(ctx.state(), project_id)
            .await
    }

    /// List projects.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: The list parameters.
    ///
    /// # Returns
    /// - `Result<Vec<Project>, ResourceProviderError>` - A list of projects or
    ///   an error.
    #[tracing::instrument(name = "provider.resource.list_projects", level = "debug", skip_all, fields(params = ?params))]
    async fn list_projects<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &ProjectListParameters,
    ) -> Result<Vec<Project>, ResourceProviderError> {
        self.backend_driver.list_projects(ctx.state(), params).await
    }

    /// Replace all tags of a project.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `project_id`: The ID of the project.
    /// - `tags`: The new set of tags.
    ///
    /// # Returns
    /// - The resulting sorted tags, or an error.
    #[tracing::instrument(name = "provider.resource.replace_project_tags", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn replace_project_tags<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
        tags: Vec<String>,
    ) -> Result<Vec<String>, ResourceProviderError> {
        validate_project_tags(&tags).map_err(|e| {
            let mut errors = validator::ValidationErrors::new();
            errors.add("tags", e);
            errors
        })?;
        self.check_project_mutable(ctx, project_id, None).await?;
        let tags = crate::audited_if_ctx! {
            ctx: ctx,
            event: Event::new(
                Operation::Update,
                EventPayload::Project { id: project_id.to_string() },
            ),
            operation: async {
                self.backend_driver.replace_project_tags(ctx.state(), project_id, tags).await
            },
            on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
        }?;
        cache_remove(PROJECT_CACHE_NS, project_id);
        cache_remove(PROJECT_REF_CACHE_NS, project_id);
        Ok(tags)
    }

    /// Update a domain.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain to update.
    /// - `domain`: The fields to change.
    ///
    /// # Returns
    /// - `Result<Domain, ResourceProviderError>` - The updated `Domain` or an
    ///   error.
    #[tracing::instrument(name = "provider.resource.update_domain", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn update_domain<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        domain: DomainUpdate,
    ) -> Result<Domain, ResourceProviderError> {
        domain.validate()?;
        self.check_domain_mutable(ctx, domain_id, domain.options.as_ref())
            .await?;
        // Disabling gets its own operation so subscribers (the OAuth2
        // session hook) can revoke what the domain's users hold.
        let operation = if domain.enabled == Some(false) {
            Operation::Disable
        } else {
            Operation::Update
        };
        let domain = crate::audited_if_ctx! {
            ctx: ctx,
            event: Event::new(
                operation,
                EventPayload::Domain { id: domain_id.to_string() },
            ),
            operation: async {
                self.backend_driver.update_domain(ctx.state(), domain_id, domain).await
            },
            on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
        }?;

        cache_set(DOMAIN_CACHE_NS, domain_id, domain.clone());
        cache_remove(DOMAIN_REF_CACHE_NS, domain_id);
        Ok(domain)
    }

    /// Update a project.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `project_id`: The ID of the project to update.
    /// - `project`: The fields to change.
    ///
    /// # Returns
    /// - `Result<Project, ResourceProviderError>` - The updated `Project` or an
    ///   error.
    #[tracing::instrument(name = "provider.resource.update_project", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn update_project<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
        project: ProjectUpdate,
    ) -> Result<Project, ResourceProviderError> {
        project.validate()?;
        self.check_project_mutable(ctx, project_id, project.options.as_ref())
            .await?;
        let project = crate::audited_if_ctx! {
            ctx: ctx,
            event: Event::new(
                Operation::Update,
                EventPayload::Project { id: project_id.to_string() },
            ),
            operation: async {
                self.backend_driver.update_project(ctx.state(), project_id, project).await
            },
            on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
        }?;

        cache_set(PROJECT_CACHE_NS, project_id, project.clone());
        cache_remove(PROJECT_REF_CACHE_NS, project_id);
        Ok(project)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait as async_trait_hook;

    use crate::auth::ValidatedSecurityContext;
    use crate::credential::MockCredentialProvider;
    use crate::events::ProviderHooks;
    use crate::idmapping::MockIdMappingProvider;
    use crate::provider::Provider;
    use crate::resource::backend::MockResourceBackend;
    use crate::tests::get_mocked_state;

    /// Mocks for a domain that owns nothing, so the contents cascade is a
    /// no-op.
    fn empty_domain_builder(idmapping: MockIdMappingProvider) -> crate::provider::ProviderBuilder {
        let mut identity = crate::identity::MockIdentityProvider::default();
        identity.expect_list_users().returning(|_, _| Ok(vec![]));
        identity.expect_list_groups().returning(|_, _| Ok(vec![]));
        let mut assignment = crate::assignment::MockAssignmentProvider::default();
        assignment
            .expect_delete_assignments_for_domain()
            .returning(|_, _| Ok(()));
        Provider::mocked_builder()
            .mock_idmapping(idmapping)
            .mock_identity(identity)
            .mock_assignment(assignment)
    }

    fn project_appcred_mock() -> crate::application_credential::MockApplicationCredentialProvider {
        let mut mock = crate::application_credential::MockApplicationCredentialProvider::default();
        mock.expect_delete_application_credentials_for_project()
            .returning(|_, _| Ok(()));
        mock
    }

    fn project_assignment_mock() -> crate::assignment::MockAssignmentProvider {
        let mut mock = crate::assignment::MockAssignmentProvider::default();
        mock.expect_delete_assignments_for_project()
            .returning(|_, _| Ok(()));
        mock
    }
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalInfo, ScopeInfo,
        SecurityContext, UserIdentityInfoBuilder,
    };
    use openstack_keystone_core_types::resource::DomainBuilder;

    fn make_vsc() -> ValidatedSecurityContext {
        let user = UserIdentityInfoBuilder::default()
            .user_id("test-user-id".to_string())
            .build()
            .unwrap();
        let sc = SecurityContext::test_build()
            .authentication_context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(user),
            })
            .build();
        ValidatedSecurityContext::test_new(sc)
    }

    fn make_vsc_scoped(scope: ScopeInfo) -> ValidatedSecurityContext {
        let user = UserIdentityInfoBuilder::default()
            .user_id("test-user-id".to_string())
            .build()
            .unwrap();
        let authz = AuthzInfoBuilder::default().scope(scope).build().unwrap();
        let sc = SecurityContext::test_build()
            .authentication_context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(user),
            })
            .authorization(authz)
            .build();
        ValidatedSecurityContext::test_new(sc)
    }

    struct CountingHook {
        count: Arc<AtomicUsize>,
    }

    #[async_trait_hook]
    impl ProviderHooks for CountingHook {
        async fn on_event(&self, _event: &Event) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn test_create_domain_succeeds() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend.expect_create_domain().returning(|_, _| {
            Ok(DomainBuilder::default()
                .id("did")
                .name("dname")
                .enabled(true)
                .build()
                .unwrap())
        });
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let created = provider
            .create_domain(
                &ExecutionContext::internal(&state),
                DomainCreate {
                    id: Some("did".to_string()),
                    name: "dname".to_string(),
                    enabled: true,
                    description: None,
                    extra: Default::default(),
                    options: Default::default(),
                },
            )
            .await
            .unwrap();
        assert_eq!(created.id, "did");
    }

    /// `audited_op!` (ADR 0023) only dispatches to `AuditHook` subscribers --
    /// it never notifies `ProviderHooks` subscribers like `Oauth2KeyHook`
    /// (ADR 0026 §3, provisions a domain's OAuth2 signing keys). Real,
    /// authenticated domain creation (`ctx.ctx()` is `Some`) must still emit
    /// a `ProviderHooks` event, same as the internal/no-context branch does.
    #[tokio::test]
    async fn test_create_domain_with_authenticated_context_notifies_provider_hooks() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let count = Arc::new(AtomicUsize::new(0));
        state
            .event_dispatcher
            .subscribe(Arc::new(CountingHook {
                count: Arc::clone(&count),
            }))
            .await;

        let mut backend = MockResourceBackend::default();
        backend.expect_create_domain().returning(|_, _| {
            Ok(DomainBuilder::default()
                .id("did")
                .name("dname")
                .enabled(true)
                .build()
                .unwrap())
        });
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let vsc = make_vsc();
        let ctx = ExecutionContext::from_auth(&state, &vsc);
        provider
            .create_domain(
                &ctx,
                DomainCreate {
                    id: Some("did".to_string()),
                    name: "dname".to_string(),
                    enabled: true,
                    description: None,
                    extra: Default::default(),
                    options: Default::default(),
                },
            )
            .await
            .unwrap();

        // `emit()` spawns the hook dispatch; give it a beat to run.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "ProviderHooks must be notified for domain creation through the authenticated path"
        );
    }

    /// Same as for the creation: the authenticated deletion must notify the
    /// `ProviderHooks` (e.g. `LimitHook` removing the limits).
    #[tokio::test]
    async fn test_delete_project_with_authenticated_context_notifies_provider_hooks() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_delete_credentials_for_project()
            .returning(|_, _| Ok(()));
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_credential(credential_mock)
                    .mock_application_credential(project_appcred_mock())
                    .mock_assignment(project_assignment_mock()),
            ),
        )
        .await;
        let count = Arc::new(AtomicUsize::new(0));
        state
            .event_dispatcher
            .subscribe(Arc::new(CountingHook {
                count: Arc::clone(&count),
            }))
            .await;
        let mut backend = MockResourceBackend::default();
        backend.expect_get_project().returning(|_, _| Ok(None));
        backend.expect_delete_project().returning(|_, _| Ok(()));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let vsc = make_vsc();
        let ctx = ExecutionContext::from_auth(&state, &vsc);
        provider.delete_project(&ctx, "pid").await.unwrap();

        // `emit()` spawns the hook dispatch; give it a beat to run.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "ProviderHooks must be notified for project deletion through the authenticated path"
        );
    }

    #[tokio::test]
    async fn test_delete_domain_with_authenticated_context_notifies_provider_hooks() {
        let mut idmapping = MockIdMappingProvider::default();
        idmapping
            .expect_delete_mappings_for_domain()
            .returning(|_, _| Ok(()));
        let state = get_mocked_state(None, Some(empty_domain_builder(idmapping))).await;
        let count = Arc::new(AtomicUsize::new(0));
        state
            .event_dispatcher
            .subscribe(Arc::new(CountingHook {
                count: Arc::clone(&count),
            }))
            .await;
        let mut backend = MockResourceBackend::default();
        backend.expect_list_projects().returning(|_, _| Ok(vec![]));
        backend.expect_get_domain().returning(|_, _| Ok(None));
        backend.expect_delete_domain().returning(|_, _| Ok(()));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let vsc = make_vsc();
        let ctx = ExecutionContext::from_auth(&state, &vsc);
        provider.delete_domain(&ctx, "did").await.unwrap();

        // `emit()` spawns the hook dispatch; give it a beat to run.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "ProviderHooks must be notified for domain deletion through the authenticated path"
        );
    }

    #[tokio::test]
    async fn test_delete_domain_deletes_contents_children_first() {
        use openstack_keystone_core_types::identity::{
            GroupBuilder, IdentityProviderError, UserResponseBuilder,
        };
        use std::sync::Mutex;

        let deleted: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        let mut identity = crate::identity::MockIdentityProvider::default();
        identity.expect_list_users().times(1).returning(|_, _| {
            Ok(["u1", "ldap"]
                .into_iter()
                .map(|id| {
                    UserResponseBuilder::default()
                        .id(id)
                        .domain_id("did")
                        .enabled(true)
                        .name(id)
                        .build()
                        .unwrap()
                })
                .collect())
        });
        let log = Arc::clone(&deleted);
        identity
            .expect_delete_user()
            .times(2)
            .returning(move |_, id: &'_ str| {
                if id == "ldap" {
                    return Err(IdentityProviderError::Readonly("ldap".into()));
                }
                log.lock().unwrap().push(format!("user:{id}"));
                Ok(())
            });
        identity.expect_list_groups().times(1).returning(|_, _| {
            Ok(vec![
                GroupBuilder::default()
                    .id("g1")
                    .domain_id("did")
                    .name("g1")
                    .build()
                    .unwrap(),
            ])
        });
        let log = Arc::clone(&deleted);
        identity
            .expect_delete_group()
            .times(1)
            .returning(move |_, id: &'_ str| {
                log.lock().unwrap().push(format!("group:{id}"));
                Ok(())
            });
        let mut assignment = crate::assignment::MockAssignmentProvider::default();
        assignment
            .expect_delete_assignments_for_project()
            .times(2)
            .returning(|_, _| Ok(()));
        assignment
            .expect_delete_assignments_for_domain()
            .times(1)
            .withf(|_, id: &'_ str| id == "did")
            .returning(|_, _| Ok(()));
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_delete_credentials_for_project()
            .returning(|_, _| Ok(()));
        let mut idmapping = MockIdMappingProvider::default();
        idmapping
            .expect_delete_mappings_for_domain()
            .returning(|_, _| Ok(()));
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_idmapping(idmapping)
                    .mock_identity(identity)
                    .mock_assignment(assignment)
                    .mock_credential(credential_mock)
                    .mock_application_credential(project_appcred_mock()),
            ),
        )
        .await;

        let mut backend = MockResourceBackend::default();
        backend.expect_get_domain().returning(|_, _| Ok(None));
        backend.expect_get_project().returning(|_, _| Ok(None));
        backend.expect_list_projects().returning(|_, _| {
            // Listed parent first on purpose: the cascade must reorder.
            let mut child = make_project("child", "did");
            child.parent_id = Some("parent".into());
            Ok(vec![make_project("parent", "did"), child])
        });
        let log = Arc::clone(&deleted);
        backend
            .expect_delete_project()
            .times(2)
            .returning(move |_, id: &'_ str| {
                log.lock().unwrap().push(format!("project:{id}"));
                Ok(())
            });
        let log = Arc::clone(&deleted);
        backend
            .expect_delete_domain()
            .times(1)
            .returning(move |_, id: &'_ str| {
                log.lock().unwrap().push(format!("domain:{id}"));
                Ok(())
            });
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        provider
            .delete_domain(&ExecutionContext::internal(&state), "did")
            .await
            .unwrap();

        assert_eq!(
            *deleted.lock().unwrap(),
            [
                "project:child",
                "project:parent",
                "user:u1",
                "group:g1",
                "domain:did"
            ]
        );
    }

    #[tokio::test]
    async fn test_delete_enabled_domain_with_contents_is_refused() {
        use openstack_keystone_core_types::identity::UserResponseBuilder;

        let mut identity = crate::identity::MockIdentityProvider::default();
        identity.expect_list_users().returning(|_, _| {
            Ok(vec![
                UserResponseBuilder::default()
                    .id("u1")
                    .domain_id("did")
                    .enabled(true)
                    .name("u1")
                    .build()
                    .unwrap(),
            ])
        });
        identity.expect_list_groups().returning(|_, _| Ok(vec![]));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_identity(identity)),
        )
        .await;
        let mut backend = MockResourceBackend::default();
        // Enabled domain: the cascade must stop before deleting anything
        // (no delete_user / delete_project / delete_domain expectations).
        backend
            .expect_get_domain()
            .returning(|_, _| Ok(Some(make_domain("did"))));
        backend.expect_list_projects().returning(|_, _| Ok(vec![]));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let res = provider
            .delete_domain(&ExecutionContext::internal(&state), "did")
            .await;
        assert!(
            matches!(res, Err(ResourceProviderError::DomainEnabled(_))),
            "{res:?}"
        );
    }

    #[tokio::test]
    async fn test_delete_project_cascades_credentials() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_delete_credentials_for_project()
            .withf(|_, pid: &'_ str| pid == "pid")
            .returning(|_, _| Ok(()));
        let mut appcred_mock =
            crate::application_credential::MockApplicationCredentialProvider::default();
        appcred_mock
            .expect_delete_application_credentials_for_project()
            .times(1)
            .withf(|_, pid: &'_ str| pid == "pid")
            .returning(|_, _| Ok(()));
        let mut assignment_mock = crate::assignment::MockAssignmentProvider::default();
        assignment_mock
            .expect_delete_assignments_for_project()
            .times(1)
            .withf(|_, pid: &'_ str| pid == "pid")
            .returning(|_, _| Ok(()));
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_credential(credential_mock)
                    .mock_application_credential(appcred_mock)
                    .mock_assignment(assignment_mock),
            ),
        )
        .await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(None));
        backend
            .expect_delete_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(()));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        assert!(
            provider
                .delete_project(&ExecutionContext::internal(&state), "pid")
                .await
                .is_ok()
        );
    }

    fn base_project_create() -> ProjectCreate {
        ProjectCreate {
            tags: Default::default(),
            description: None,
            domain_id: None,
            enabled: true,
            extra: Default::default(),
            id: None,
            is_domain: false,
            name: "pname".into(),
            parent_id: None,
            options: Default::default(),
        }
    }

    fn make_domain(id: &str) -> openstack_keystone_core_types::resource::Domain {
        DomainBuilder::default()
            .id(id)
            .name(format!("{id}-name"))
            .enabled(true)
            .build()
            .unwrap()
    }

    fn make_project(id: &str, domain_id: &str) -> Project {
        ProjectBuilder::default()
            .id(id)
            .domain_id(domain_id)
            .name(format!("{id}-name"))
            .enabled(true)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_resolve_project_domain_id_is_domain_self() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let provider =
            ResourceService::with_backend(Arc::new(MockResourceBackend::default()), false);
        let mut project = base_project_create();
        project.is_domain = true;

        let resolved = provider
            .resolve_project_domain_id(&ExecutionContext::internal(&state), &project, "genid")
            .await
            .unwrap();
        assert_eq!(resolved, "genid");
    }

    #[tokio::test]
    async fn test_resolve_project_domain_id_is_domain_rejects_domain_id() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let provider =
            ResourceService::with_backend(Arc::new(MockResourceBackend::default()), false);
        let mut project = base_project_create();
        project.is_domain = true;
        project.domain_id = Some("did".into());

        let err = provider
            .resolve_project_domain_id(&ExecutionContext::internal(&state), &project, "genid")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ResourceProviderError::InvalidProjectDomain(_)
        ));
    }

    #[tokio::test]
    async fn test_resolve_project_domain_id_explicit() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let provider =
            ResourceService::with_backend(Arc::new(MockResourceBackend::default()), false);
        let mut project = base_project_create();
        project.domain_id = Some("did".into());

        let resolved = provider
            .resolve_project_domain_id(&ExecutionContext::internal(&state), &project, "genid")
            .await
            .unwrap();
        assert_eq!(resolved, "did");
    }

    #[tokio::test]
    async fn test_resolve_project_domain_id_inherits_from_parent() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(make_project("pid", "parent-did"))));
        let provider = ResourceService::with_backend(Arc::new(backend), false);
        let mut project = base_project_create();
        project.parent_id = Some("pid".into());

        let resolved = provider
            .resolve_project_domain_id(&ExecutionContext::internal(&state), &project, "genid")
            .await
            .unwrap();
        assert_eq!(resolved, "parent-did");
    }

    #[tokio::test]
    async fn test_resolve_project_domain_id_matches_parent() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(make_project("pid", "did"))));
        let provider = ResourceService::with_backend(Arc::new(backend), false);
        let mut project = base_project_create();
        project.parent_id = Some("pid".into());
        project.domain_id = Some("did".into());

        let resolved = provider
            .resolve_project_domain_id(&ExecutionContext::internal(&state), &project, "genid")
            .await
            .unwrap();
        assert_eq!(resolved, "did");
    }

    #[tokio::test]
    async fn test_resolve_project_domain_id_mismatch_with_parent_errors() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(make_project("pid", "parent-did"))));
        let provider = ResourceService::with_backend(Arc::new(backend), false);
        let mut project = base_project_create();
        project.parent_id = Some("pid".into());
        project.domain_id = Some("other-did".into());

        let err = provider
            .resolve_project_domain_id(&ExecutionContext::internal(&state), &project, "genid")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ResourceProviderError::InvalidProjectDomain(_)
        ));
    }

    #[tokio::test]
    async fn test_resolve_project_domain_id_falls_back_to_domain_scope() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let provider =
            ResourceService::with_backend(Arc::new(MockResourceBackend::default()), false);
        let vsc = make_vsc_scoped(ScopeInfo::Domain(make_domain("scoped-did").into()));
        let ctx = ExecutionContext::from_auth(&state, &vsc);
        let project = base_project_create();

        let resolved = provider
            .resolve_project_domain_id(&ctx, &project, "genid")
            .await
            .unwrap();
        assert_eq!(resolved, "scoped-did");
    }

    #[tokio::test]
    async fn test_resolve_project_domain_id_falls_back_to_project_scope_domain() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let provider =
            ResourceService::with_backend(Arc::new(MockResourceBackend::default()), false);
        let vsc = make_vsc_scoped(ScopeInfo::Project {
            project: make_project("scope-pid", "scoped-did").into(),
            project_domain: make_domain("scoped-did").into(),
        });
        let ctx = ExecutionContext::from_auth(&state, &vsc);
        let project = base_project_create();

        let resolved = provider
            .resolve_project_domain_id(&ctx, &project, "genid")
            .await
            .unwrap();
        assert_eq!(resolved, "scoped-did");
    }

    #[tokio::test]
    async fn test_resolve_project_domain_id_no_domain_no_scope_errors() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let provider =
            ResourceService::with_backend(Arc::new(MockResourceBackend::default()), false);
        let project = base_project_create();

        let err = provider
            .resolve_project_domain_id(&ExecutionContext::internal(&state), &project, "genid")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ResourceProviderError::InvalidProjectDomain(_)
        ));
    }

    fn make_immutable_project(id: &str, domain_id: &str) -> Project {
        let mut project = make_project(id, domain_id);
        project.options.immutable = Some(true);
        project
    }

    fn make_immutable_domain(id: &str) -> openstack_keystone_core_types::resource::Domain {
        let mut domain = make_domain(id);
        domain.options.immutable = Some(true);
        domain
    }

    #[tokio::test]
    async fn test_update_project_blocked_when_immutable() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(make_immutable_project("pid", "did"))));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let err = provider
            .update_project(
                &ExecutionContext::internal(&state),
                "pid",
                ProjectUpdate {
                    name: Some("new_name".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ResourceProviderError::Immutable(id) if id == "pid"));
    }

    #[tokio::test]
    async fn test_replace_project_tags_blocked_when_immutable() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(make_immutable_project("pid", "did"))));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let err = provider
            .replace_project_tags(&ExecutionContext::internal(&state), "pid", vec!["a".into()])
            .await
            .unwrap_err();
        assert!(matches!(err, ResourceProviderError::Immutable(id) if id == "pid"));
    }

    #[tokio::test]
    async fn test_replace_project_tags_rejects_invalid_tags() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let provider =
            ResourceService::with_backend(Arc::new(MockResourceBackend::default()), false);

        for tags in [
            vec!["a/b".to_string()],
            vec!["a,b".to_string()],
            vec![String::new()],
            vec!["x".to_string(), "x".to_string()],
        ] {
            let err = provider
                .replace_project_tags(&ExecutionContext::internal(&state), "pid", tags)
                .await
                .unwrap_err();
            assert!(matches!(err, ResourceProviderError::Validation { .. }));
        }
        let err = provider
            .create_project_tag(&ExecutionContext::internal(&state), "pid", "a,b")
            .await
            .unwrap_err();
        assert!(matches!(err, ResourceProviderError::Validation { .. }));
    }

    #[tokio::test]
    async fn test_update_project_allowed_when_clearing_immutable() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(make_immutable_project("pid", "did"))));
        backend
            .expect_update_project()
            .withf(|_, id: &'_ str, _| id == "pid")
            .returning(|_, _, _| Ok(make_project("pid", "did")));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let result = provider
            .update_project(
                &ExecutionContext::internal(&state),
                "pid",
                ProjectUpdate {
                    options: Some(openstack_keystone_core_types::resource::ProjectOptions {
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
    async fn test_delete_project_blocked_when_immutable() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(make_immutable_project("pid", "did"))));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let err = provider
            .delete_project(&ExecutionContext::internal(&state), "pid")
            .await
            .unwrap_err();
        assert!(matches!(err, ResourceProviderError::Immutable(id) if id == "pid"));
    }

    #[tokio::test]
    async fn test_update_domain_blocked_when_immutable() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "did")
            .returning(|_, _| Ok(Some(make_immutable_domain("did"))));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let err = provider
            .update_domain(
                &ExecutionContext::internal(&state),
                "did",
                DomainUpdate {
                    name: Some("new_name".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ResourceProviderError::Immutable(id) if id == "did"));
    }

    #[tokio::test]
    async fn test_delete_domain_blocked_when_immutable() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "did")
            .returning(|_, _| Ok(Some(make_immutable_domain("did"))));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let err = provider
            .delete_domain(&ExecutionContext::internal(&state), "did")
            .await
            .unwrap_err();
        assert!(matches!(err, ResourceProviderError::Immutable(id) if id == "did"));
    }

    #[tokio::test]
    async fn test_update_project_not_immutable_proceeds() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(make_project("pid", "did"))));
        backend
            .expect_update_project()
            .withf(|_, id: &'_ str, _| id == "pid")
            .returning(|_, _, _| Ok(make_project("pid", "did")));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let result = provider
            .update_project(
                &ExecutionContext::internal(&state),
                "pid",
                ProjectUpdate {
                    name: Some("new_name".into()),
                    ..Default::default()
                },
            )
            .await;
        assert!(result.is_ok());
    }

    // --- Per-request cache (ADR 0030) -------------------------------------

    #[tokio::test]
    async fn test_get_domain_hits_backend_once_across_repeated_calls() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_domain()
            .times(1)
            .withf(|_, id: &'_ str| id == "did")
            .returning(|_, _| Ok(Some(make_domain("did"))));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            let first = provider.get_domain(&ctx, "did").await.unwrap().unwrap();
            let second = provider.get_domain(&ctx, "did").await.unwrap().unwrap();
            assert_eq!(first, second);
        })
        .await;
    }

    #[tokio::test]
    async fn test_get_domain_not_cached_outside_request_scope() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_domain()
            .times(2)
            .withf(|_, id: &'_ str| id == "did")
            .returning(|_, _| Ok(Some(make_domain("did"))));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let ctx = ExecutionContext::internal(&state);
        provider.get_domain(&ctx, "did").await.unwrap();
        // No `RequestCache::scope` established (mirrors CLI/background-job
        // call paths) -- each call must hit the backend.
        provider.get_domain(&ctx, "did").await.unwrap();
    }

    #[tokio::test]
    async fn test_get_project_hits_backend_once_across_repeated_calls() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project()
            .times(1)
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(make_project("pid", "did"))));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            let first = provider.get_project(&ctx, "pid").await.unwrap().unwrap();
            let second = provider.get_project(&ctx, "pid").await.unwrap().unwrap();
            assert_eq!(first, second);
        })
        .await;
    }

    #[tokio::test]
    async fn test_get_project_ref_hits_backend_once_across_repeated_calls() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project_ref()
            .times(1)
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(ProjectRef::from(make_project("pid", "did")))));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            let first = provider
                .get_project_ref(&ctx, "pid")
                .await
                .unwrap()
                .unwrap();
            let second = provider
                .get_project_ref(&ctx, "pid")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first, second);
            // The domain lookup reuses the cached short project.
            assert_eq!(
                Some("did".to_string()),
                provider.get_project_domain_id(&ctx, "pid").await.unwrap()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_get_project_ref_reuses_project_loaded_in_the_request() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project()
            .times(1)
            .returning(|_, _| Ok(Some(make_project("pid", "did"))));
        // No `get_project_ref` expectation: the backend must not be asked.
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.get_project(&ctx, "pid").await.unwrap();
            let short = provider
                .get_project_ref(&ctx, "pid")
                .await
                .unwrap()
                .unwrap();
            assert_eq!("pid", short.id);
            assert_eq!("did", short.domain_id);
        })
        .await;
    }

    #[tokio::test]
    async fn test_update_project_drops_the_cached_short_project() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend.expect_get_project_ref().times(1).returning(|_, _| {
            let mut stale = ProjectRef::from(make_project("pid", "did"));
            stale.name = "stale".into();
            Ok(Some(stale))
        });
        backend
            .expect_get_project()
            .returning(|_, _| Ok(Some(make_project("pid", "did"))));
        backend
            .expect_update_project()
            .returning(|_, _, _| Ok(make_project("pid", "did")));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            let before = provider
                .get_project_ref(&ctx, "pid")
                .await
                .unwrap()
                .unwrap();
            assert_eq!("stale", before.name);
            provider
                .update_project(
                    &ctx,
                    "pid",
                    ProjectUpdate {
                        name: Some("pid-name".into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            let after = provider
                .get_project_ref(&ctx, "pid")
                .await
                .unwrap()
                .unwrap();
            assert_eq!("pid-name", after.name);
        })
        .await;
    }

    #[tokio::test]
    async fn test_get_project_ref_not_cached_outside_request_scope() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project_ref()
            .times(2)
            .returning(|_, _| Ok(Some(ProjectRef::from(make_project("pid", "did")))));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let ctx = ExecutionContext::internal(&state);
        provider.get_project_ref(&ctx, "pid").await.unwrap();
        provider.get_project_ref(&ctx, "pid").await.unwrap();
    }

    #[tokio::test]
    async fn test_get_domain_ref_hits_backend_once_across_repeated_calls() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_domain_ref()
            .times(1)
            .withf(|_, id: &'_ str| id == "did")
            .returning(|_, _| Ok(Some(make_domain("did").into())));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            let first = provider.get_domain_ref(&ctx, "did").await.unwrap().unwrap();
            let second = provider.get_domain_ref(&ctx, "did").await.unwrap().unwrap();
            assert_eq!(first, second);
        })
        .await;
    }

    #[tokio::test]
    async fn test_get_domain_ref_reuses_domain_loaded_in_the_request() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_domain()
            .times(1)
            .returning(|_, _| Ok(Some(make_domain("did"))));
        // The short lookup must not reach the backend at all.
        backend.expect_get_domain_ref().times(0);
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.get_domain(&ctx, "did").await.unwrap();
            let short = provider.get_domain_ref(&ctx, "did").await.unwrap().unwrap();
            assert_eq!("did", short.id);
        })
        .await;
    }

    #[tokio::test]
    async fn test_update_domain_drops_the_cached_short_domain() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_domain()
            .returning(|_, _| Ok(Some(make_domain("did"))));
        backend
            .expect_get_domain_ref()
            .times(1)
            .returning(|_, _| Ok(Some(make_domain("did").into())));
        backend.expect_update_domain().returning(|_, _, update| {
            let mut d = make_domain("did");
            if let Some(name) = update.name {
                d.name = name;
            }
            Ok(d)
        });
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.get_domain_ref(&ctx, "did").await.unwrap();
            provider
                .update_domain(
                    &ctx,
                    "did",
                    DomainUpdate {
                        name: Some("renamed".into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            // Served from the refreshed full domain, not the stale short one.
            let short = provider.get_domain_ref(&ctx, "did").await.unwrap().unwrap();
            assert_eq!("renamed", short.name);
        })
        .await;
    }

    #[tokio::test]
    async fn test_update_domain_refreshes_cache_instead_of_refetching() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        // Only the very first `get_domain` (populating the cache) and the
        // one inside `check_domain_mutable` before it's cached should ever
        // reach the backend -- exactly once total.
        backend
            .expect_get_domain()
            .times(1)
            .withf(|_, id: &'_ str| id == "did")
            .returning(|_, _| Ok(Some(make_domain("did"))));
        backend
            .expect_update_domain()
            .withf(|_, id: &'_ str, _| id == "did")
            .returning(|_, _, update| {
                let mut d = make_domain("did");
                if let Some(name) = update.name {
                    d.name = name;
                }
                Ok(d)
            });
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.get_domain(&ctx, "did").await.unwrap();

            let updated = provider
                .update_domain(
                    &ctx,
                    "did",
                    DomainUpdate {
                        name: Some("renamed".into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(updated.name, "renamed");

            let refetched = provider.get_domain(&ctx, "did").await.unwrap().unwrap();
            assert_eq!(refetched.name, "renamed");
        })
        .await;
    }

    #[tokio::test]
    async fn test_delete_domain_invalidates_cache() {
        let mut idmapping = MockIdMappingProvider::default();
        idmapping
            .expect_delete_mappings_for_domain()
            .withf(|_, id: &'_ str| id == "did")
            .returning(|_, _| Ok(()));
        let state = get_mocked_state(None, Some(empty_domain_builder(idmapping))).await;
        let mut backend = MockResourceBackend::default();
        backend.expect_list_projects().returning(|_, _| Ok(vec![]));
        // Populated once by the initial `get_domain`, hit from cache inside
        // `check_domain_mutable`, then re-fetched from the backend after
        // deletion invalidates the cache entry.
        backend
            .expect_get_domain()
            .times(2)
            .withf(|_, id: &'_ str| id == "did")
            .returning(|_, _| Ok(Some(make_domain("did"))));
        backend
            .expect_delete_domain()
            .withf(|_, id: &'_ str| id == "did")
            .returning(|_, _| Ok(()));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.get_domain(&ctx, "did").await.unwrap();
            provider.delete_domain(&ctx, "did").await.unwrap();
            // Cache entry was removed by the delete -- this call must reach
            // the backend again rather than serve the deleted domain.
            provider.get_domain(&ctx, "did").await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn test_update_project_refreshes_cache_instead_of_refetching() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project()
            .times(1)
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(make_project("pid", "did"))));
        backend
            .expect_update_project()
            .withf(|_, id: &'_ str, _| id == "pid")
            .returning(|_, _, update| {
                let mut p = make_project("pid", "did");
                if let Some(name) = update.name {
                    p.name = name;
                }
                Ok(p)
            });
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.get_project(&ctx, "pid").await.unwrap();

            let updated = provider
                .update_project(
                    &ctx,
                    "pid",
                    ProjectUpdate {
                        name: Some("renamed".into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(updated.name, "renamed");

            let refetched = provider.get_project(&ctx, "pid").await.unwrap().unwrap();
            assert_eq!(refetched.name, "renamed");
        })
        .await;
    }

    #[tokio::test]
    async fn test_delete_project_invalidates_cache() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_delete_credentials_for_project()
            .withf(|_, pid: &'_ str| pid == "pid")
            .returning(|_, _| Ok(()));
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_credential(credential_mock)
                    .mock_application_credential(project_appcred_mock())
                    .mock_assignment(project_assignment_mock()),
            ),
        )
        .await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project()
            .times(2)
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(make_project("pid", "did"))));
        backend
            .expect_delete_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(()));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.get_project(&ctx, "pid").await.unwrap();
            provider.delete_project(&ctx, "pid").await.unwrap();
            provider.get_project(&ctx, "pid").await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn test_delete_project_cascade_failure_still_invalidates_cache() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_delete_credentials_for_project()
            .returning(|_, _| {
                Err(
                    openstack_keystone_core_types::credential::CredentialProviderError::Driver(
                        "boom".into(),
                    ),
                )
            });
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_credential(credential_mock)),
        )
        .await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project()
            .times(2)
            .returning(|_, _| Ok(Some(make_project("pid", "did"))));
        backend.expect_delete_project().returning(|_, _| Ok(()));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.get_project(&ctx, "pid").await.unwrap();
            provider.delete_project(&ctx, "pid").await.unwrap_err();
            // Served by the backend again, not by the stale cache.
            provider.get_project(&ctx, "pid").await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn test_get_project_parents_hits_backend_once_across_repeated_calls() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project_parents()
            .times(1)
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(vec![make_project("parent", "did")])));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            let first = provider
                .get_project_parents(&ctx, "pid")
                .await
                .unwrap()
                .unwrap();
            let second = provider
                .get_project_parents(&ctx, "pid")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first, second);
        })
        .await;
    }

    #[tokio::test]
    async fn test_get_project_parents_not_cached_outside_request_scope() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project_parents()
            .times(2)
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(vec![make_project("parent", "did")])));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let ctx = ExecutionContext::internal(&state);
        provider.get_project_parents(&ctx, "pid").await.unwrap();
        provider.get_project_parents(&ctx, "pid").await.unwrap();
    }

    #[tokio::test]
    async fn test_get_project_parents_none_is_not_cached() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project_parents()
            .times(2)
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(None));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            assert!(
                provider
                    .get_project_parents(&ctx, "pid")
                    .await
                    .unwrap()
                    .is_none()
            );
            // A `None` result (project not found) must not be cached as
            // "no parents" -- it should keep hitting the backend.
            assert!(
                provider
                    .get_project_parents(&ctx, "pid")
                    .await
                    .unwrap()
                    .is_none()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_delete_project_invalidates_parents_cache() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_delete_credentials_for_project()
            .withf(|_, pid: &'_ str| pid == "pid")
            .returning(|_, _| Ok(()));
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_credential(credential_mock)
                    .mock_application_credential(project_appcred_mock())
                    .mock_assignment(project_assignment_mock()),
            ),
        )
        .await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project_parents()
            .times(2)
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(vec![make_project("parent", "did")])));
        backend
            .expect_get_project()
            .returning(|_, _| Ok(Some(make_project("pid", "did"))));
        backend
            .expect_delete_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(()));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.get_project_parents(&ctx, "pid").await.unwrap();
            provider.delete_project(&ctx, "pid").await.unwrap();
            // Cache entry was removed by the delete -- this call must reach
            // the backend again.
            provider.get_project_parents(&ctx, "pid").await.unwrap();
        })
        .await;
    }

    /// A state whose providers accept the cascade of a project delete.
    async fn delete_cascade_state() -> crate::keystone::ServiceState {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_delete_credentials_for_project()
            .returning(|_, _| Ok(()));
        get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_credential(credential_mock)
                    .mock_application_credential(project_appcred_mock())
                    .mock_assignment(project_assignment_mock()),
            ),
        )
        .await
    }

    #[tokio::test]
    async fn test_get_project_domain_id_cached_in_process_when_caching() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project_domain_id()
            .times(1)
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some("did".into())));
        let provider = ResourceService::with_backend(Arc::new(backend), true);

        // Outside any request scope: only the process-lifetime cache can help.
        let ctx = ExecutionContext::internal(&state);
        for _ in 0..3 {
            assert_eq!(
                Some("did".to_string()),
                provider.get_project_domain_id(&ctx, "pid").await.unwrap()
            );
        }
    }

    #[tokio::test]
    async fn test_get_project_domain_id_not_cached_without_caching() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project_domain_id()
            .times(2)
            .returning(|_, _| Ok(Some("did".into())));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let ctx = ExecutionContext::internal(&state);
        provider.get_project_domain_id(&ctx, "pid").await.unwrap();
        provider.get_project_domain_id(&ctx, "pid").await.unwrap();
    }

    #[tokio::test]
    async fn test_get_project_domain_id_missing_project_is_not_cached() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project_domain_id()
            .times(2)
            .returning(|_, _| Ok(None));
        let provider = ResourceService::with_backend(Arc::new(backend), true);

        let ctx = ExecutionContext::internal(&state);
        assert!(
            provider
                .get_project_domain_id(&ctx, "nope")
                .await
                .unwrap()
                .is_none()
        );
        // The project may be created in between: ask again.
        assert!(
            provider
                .get_project_domain_id(&ctx, "nope")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_get_project_domain_id_reuses_project_loaded_in_the_request() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project()
            .times(1)
            .returning(|_, _| Ok(Some(make_project("pid", "did"))));
        // No `get_project_domain_id` expectation: a call would fail the mock.
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.get_project(&ctx, "pid").await.unwrap();
            assert_eq!(
                Some("did".to_string()),
                provider.get_project_domain_id(&ctx, "pid").await.unwrap()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_get_project_parent_ids_cached_in_process_when_caching() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project_parent_ids()
            .times(1)
            .returning(|_, _| Ok(Some(vec!["p1".into(), "did".into()])));
        let provider = ResourceService::with_backend(Arc::new(backend), true);

        let ctx = ExecutionContext::internal(&state);
        for _ in 0..3 {
            assert_eq!(
                Some(vec!["p1".to_string(), "did".to_string()]),
                provider.get_project_parent_ids(&ctx, "pid").await.unwrap()
            );
        }
    }

    #[tokio::test]
    async fn test_get_project_parent_ids_not_cached_without_caching() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project_parent_ids()
            .times(2)
            .returning(|_, _| Ok(Some(Vec::new())));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        let ctx = ExecutionContext::internal(&state);
        provider.get_project_parent_ids(&ctx, "pid").await.unwrap();
        provider.get_project_parent_ids(&ctx, "pid").await.unwrap();
    }

    #[tokio::test]
    async fn test_get_project_parent_ids_reuse_request_scope_without_caching() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project_parent_ids()
            .times(1)
            .returning(|_, _| Ok(Some(vec!["p1".into()])));
        backend
            .expect_get_project_domain_id()
            .times(1)
            .returning(|_, _| Ok(Some("did".into())));
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            for _ in 0..3 {
                assert_eq!(
                    Some(vec!["p1".to_string()]),
                    provider.get_project_parent_ids(&ctx, "pid").await.unwrap()
                );
                assert_eq!(
                    Some("did".to_string()),
                    provider.get_project_domain_id(&ctx, "pid").await.unwrap()
                );
            }
        })
        .await;
    }

    #[tokio::test]
    async fn test_get_project_parent_ids_derived_from_request_cached_parents() {
        let state = get_mocked_state(None, Some(Provider::mocked_builder())).await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project_parents()
            .times(1)
            .returning(|_, _| {
                Ok(Some(vec![Project {
                    id: "p1".into(),
                    ..Default::default()
                }]))
            });
        // No `get_project_parent_ids` expectation: a call would fail the mock.
        let provider = ResourceService::with_backend(Arc::new(backend), false);

        crate::request_cache::RequestCache::scope(async {
            let ctx = ExecutionContext::internal(&state);
            provider.get_project_parents(&ctx, "pid").await.unwrap();
            assert_eq!(
                Some(vec!["p1".to_string()]),
                provider.get_project_parent_ids(&ctx, "pid").await.unwrap()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_delete_project_drops_its_process_cache_entries() {
        let state = delete_cascade_state().await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_get_project_domain_id()
            .times(2)
            .returning(|_, _| Ok(Some("did".into())));
        backend
            .expect_get_project_parent_ids()
            .times(2)
            .returning(|_, _| Ok(Some(vec!["did".into()])));
        backend
            .expect_get_project()
            .returning(|_, _| Ok(Some(make_project("pid", "did"))));
        backend.expect_delete_project().returning(|_, _| Ok(()));
        let provider = ResourceService::with_backend(Arc::new(backend), true);

        let ctx = ExecutionContext::internal(&state);
        provider.get_project_domain_id(&ctx, "pid").await.unwrap();
        provider.get_project_parent_ids(&ctx, "pid").await.unwrap();
        provider.delete_project(&ctx, "pid").await.unwrap();
        // Both entries are gone: the backend is asked again.
        provider.get_project_domain_id(&ctx, "pid").await.unwrap();
        provider.get_project_parent_ids(&ctx, "pid").await.unwrap();
    }

    #[tokio::test]
    async fn test_delete_project_drops_chains_through_it_and_keeps_the_rest() {
        let state = delete_cascade_state().await;
        let mut backend = MockResourceBackend::default();
        // "child" sits below "pid"; "other" is unrelated.
        backend
            .expect_get_project_parent_ids()
            .times(3)
            .returning(|_, id| {
                Ok(Some(match id {
                    "child" => vec!["pid".into(), "did".into()],
                    _ => vec!["did".into()],
                }))
            });
        backend
            .expect_get_project()
            .returning(|_, _| Ok(Some(make_project("pid", "did"))));
        backend.expect_delete_project().returning(|_, _| Ok(()));
        let provider = ResourceService::with_backend(Arc::new(backend), true);

        let ctx = ExecutionContext::internal(&state);
        provider
            .get_project_parent_ids(&ctx, "child")
            .await
            .unwrap();
        provider
            .get_project_parent_ids(&ctx, "other")
            .await
            .unwrap();
        provider.delete_project(&ctx, "pid").await.unwrap();
        // "other" is still cached (no backend call: the 3 calls are the two
        // above plus the refetch of "child").
        provider
            .get_project_parent_ids(&ctx, "other")
            .await
            .unwrap();
        provider
            .get_project_parent_ids(&ctx, "child")
            .await
            .unwrap();
    }
}
