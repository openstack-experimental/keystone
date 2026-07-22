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
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::resource::*;

use crate::auth::{ExecutionContext, scope_domain_id};
use crate::events::AuditDispatchError;
use crate::plugin_manager::PluginManagerApi;
use crate::resource::{ResourceApi, ResourceProviderError, backend::ResourceBackend};

pub struct ResourceService {
    backend_driver: Arc<dyn ResourceBackend>,
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
        Ok(Self { backend_driver })
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
}

#[async_trait]
impl ResourceApi for ResourceService {
    /// Check whether the domain is enabled.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain_id`: The ID of the domain.
    ///
    /// # Returns
    /// - `Result<bool, ResourceProviderError>` - Whether the domain is enabled
    ///   or an error.
    async fn get_domain_enabled<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
    ) -> Result<bool, ResourceProviderError> {
        self.backend_driver
            .get_domain_enabled(ctx.state(), domain_id)
            .await
    }

    /// Create a new domain.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `domain`: The domain details to create.
    ///
    /// # Returns
    /// - `Result<Domain, ResourceProviderError>` - The created `Domain` or an
    ///   error.
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
        let domain = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            let new_domain_clone = new_domain.clone();
            let domain = crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::Domain { id: domain_id.clone() },
                ),
                operation: async {
                    backend_driver.create_domain(state, new_domain_clone).await
                },
                on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
            }?;

            // `audited_op!` only dispatches to `AuditHook` subscribers
            // (ADR 0023's fail-closed audit path) -- it never notifies
            // `ProviderHooks` subscribers (e.g. `Oauth2KeyHook`, which
            // provisions OAuth2 signing keys per ADR 0026 §3). Emit here too
            // so real, authenticated domain creation actually fires them,
            // matching the internal/no-context branch below.
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Domain {
                        id: domain.id.clone(),
                    },
                ))
                .await;

            domain
        } else {
            let domain = self
                .backend_driver
                .create_domain(ctx.state(), new_domain)
                .await?;

            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Domain {
                        id: domain.id.clone(),
                    },
                ))
                .await;

            domain
        };

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
        let project = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            let new_project_clone = new_project.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::Project { id: project_id.clone() },
                ),
                operation: async {
                    backend_driver.create_project(state, new_project_clone).await
                },
                on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let project = self
                .backend_driver
                .create_project(ctx.state(), new_project)
                .await?;

            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Project {
                        id: project.id.clone(),
                    },
                ))
                .await;

            project
        };

        Ok(project)
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
    async fn update_domain<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        domain: DomainUpdate,
    ) -> Result<Domain, ResourceProviderError> {
        domain.validate()?;
        let domain = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            let domain_id_clone = domain_id.to_string();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::Domain { id: domain_id_clone },
                ),
                operation: async {
                    backend_driver.update_domain(state, domain_id, domain).await
                },
                on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let domain = self
                .backend_driver
                .update_domain(ctx.state(), domain_id, domain)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::Domain {
                        id: domain.id.clone(),
                    },
                ))
                .await;
            domain
        };

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
    async fn update_project<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
        project: ProjectUpdate,
    ) -> Result<Project, ResourceProviderError> {
        project.validate()?;
        let project = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            let project_id_clone = project_id.to_string();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::Project { id: project_id_clone },
                ),
                operation: async {
                    backend_driver.update_project(state, project_id, project).await
                },
                on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let project = self
                .backend_driver
                .update_project(ctx.state(), project_id, project)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::Project {
                        id: project.id.clone(),
                    },
                ))
                .await;
            project
        };

        Ok(project)
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
    async fn delete_domain<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), ResourceProviderError> {
        if let Some(vsc) = ctx.ctx() {
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::Domain { id: id.to_string() },
                ),
                operation: async {
                    self.backend_driver.delete_domain(ctx.state(), id).await?;
                    Ok::<(), ResourceProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver.delete_domain(ctx.state(), id).await?;

            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::Domain { id: id.to_string() },
                ))
                .await;
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
    async fn delete_project<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), ResourceProviderError> {
        if let Some(vsc) = ctx.ctx() {
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::Project { id: id.to_string() },
                ),
                operation: async {
                    self.backend_driver.delete_project(ctx.state(), id).await?;
                    ctx.state()
                        .provider
                        .get_credential_provider()
                        .delete_credentials_for_project(ctx, id)
                        .await?;
                    Ok::<(), ResourceProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| ResourceProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver.delete_project(ctx.state(), id).await?;

            ctx.state()
                .provider
                .get_credential_provider()
                .delete_credentials_for_project(ctx, id)
                .await?;

            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::Project { id: id.to_string() },
                ))
                .await;
        }

        Ok(())
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
    async fn get_domain<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        self.backend_driver.get_domain(ctx.state(), domain_id).await
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
    async fn get_project<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        self.backend_driver
            .get_project(ctx.state(), project_id)
            .await
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

    /// Get project parents.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `project_id`: The ID of the project.
    ///
    /// # Returns
    /// - A `Result` containing an `Option` with the `Vec<Project>` if found, or
    ///   an `Error`.
    async fn get_project_parents<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<Option<Vec<Project>>, ResourceProviderError> {
        self.backend_driver
            .get_project_parents(ctx.state(), project_id)
            .await
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
    async fn find_domain_by_name<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_name: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        self.backend_driver
            .get_domain_by_name(ctx.state(), domain_name)
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
    async fn list_domains<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &DomainListParameters,
    ) -> Result<Vec<Domain>, ResourceProviderError> {
        self.backend_driver.list_domains(ctx.state(), params).await
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
    async fn list_projects<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &ProjectListParameters,
    ) -> Result<Vec<Project>, ResourceProviderError> {
        self.backend_driver.list_projects(ctx.state(), params).await
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
    use crate::provider::Provider;
    use crate::resource::backend::MockResourceBackend;
    use crate::tests::get_mocked_state;
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
        let provider = ResourceService {
            backend_driver: Arc::new(backend),
        };

        let created = provider
            .create_domain(
                &ExecutionContext::internal(&state),
                DomainCreate {
                    id: Some("did".to_string()),
                    name: "dname".to_string(),
                    enabled: true,
                    description: None,
                    extra: Default::default(),
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
        let provider = ResourceService {
            backend_driver: Arc::new(backend),
        };

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

    #[tokio::test]
    async fn test_delete_project_cascades_credentials() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_delete_credentials_for_project()
            .withf(|_, pid: &'_ str| pid == "pid")
            .returning(|_, _| Ok(()));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_credential(credential_mock)),
        )
        .await;
        let mut backend = MockResourceBackend::default();
        backend
            .expect_delete_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(()));
        let provider = ResourceService {
            backend_driver: Arc::new(backend),
        };

        assert!(
            provider
                .delete_project(&ExecutionContext::internal(&state), "pid")
                .await
                .is_ok()
        );
    }

    fn base_project_create() -> ProjectCreate {
        ProjectCreate {
            description: None,
            domain_id: None,
            enabled: true,
            extra: Default::default(),
            id: None,
            is_domain: false,
            name: "pname".into(),
            parent_id: None,
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
        let provider = ResourceService {
            backend_driver: Arc::new(MockResourceBackend::default()),
        };
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
        let provider = ResourceService {
            backend_driver: Arc::new(MockResourceBackend::default()),
        };
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
        let provider = ResourceService {
            backend_driver: Arc::new(MockResourceBackend::default()),
        };
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
        let provider = ResourceService {
            backend_driver: Arc::new(backend),
        };
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
        let provider = ResourceService {
            backend_driver: Arc::new(backend),
        };
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
        let provider = ResourceService {
            backend_driver: Arc::new(backend),
        };
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
        let provider = ResourceService {
            backend_driver: Arc::new(MockResourceBackend::default()),
        };
        let vsc = make_vsc_scoped(ScopeInfo::Domain(make_domain("scoped-did")));
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
        let provider = ResourceService {
            backend_driver: Arc::new(MockResourceBackend::default()),
        };
        let vsc = make_vsc_scoped(ScopeInfo::Project {
            project: make_project("scope-pid", "scoped-did"),
            project_domain: make_domain("scoped-did"),
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
        let provider = ResourceService {
            backend_driver: Arc::new(MockResourceBackend::default()),
        };
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
}
