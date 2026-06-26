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

use crate::auth::ExecutionContext;
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

        if new_domain.id.is_none() {
            new_domain.id = Some(Uuid::new_v4().simple().to_string());
        }
        new_domain.validate()?;
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

        if new_project.id.is_none() {
            new_project.id = Some(Uuid::new_v4().simple().to_string());
        }
        new_project.validate()?;
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
        self.backend_driver.delete_domain(ctx.state(), id).await?;

        ctx.state()
            .event_dispatcher
            .emit(Event::new(
                Operation::Delete,
                EventPayload::Domain { id: id.to_string() },
            ))
            .await;

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
        self.backend_driver.delete_project(ctx.state(), id).await?;

        ctx.state()
            .event_dispatcher
            .emit(Event::new(
                Operation::Delete,
                EventPayload::Project { id: id.to_string() },
            ))
            .await;

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
