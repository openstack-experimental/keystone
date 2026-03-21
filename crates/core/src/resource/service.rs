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

use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::resource::{ResourceProviderError, backend::ResourceBackend, types::*};

pub struct ResourceService {
    backend_driver: Arc<dyn ResourceBackend>,
}

impl ResourceService {
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
    async fn get_domain_enabled<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<bool, ResourceProviderError> {
        self.backend_driver
            .get_domain_enabled(state, domain_id)
            .await
    }

    /// Create new domain.
    async fn create_domain(
        &self,
        state: &ServiceState,
        domain: DomainCreate,
    ) -> Result<Domain, ResourceProviderError> {
        let mut new_domain = domain;

        if new_domain.id.is_none() {
            new_domain.id = Some(Uuid::new_v4().simple().to_string());
        }
        new_domain.validate()?;
        self.backend_driver.create_domain(state, new_domain).await
    }

    /// Create new project.
    async fn create_project(
        &self,
        state: &ServiceState,
        project: ProjectCreate,
    ) -> Result<Project, ResourceProviderError> {
        let mut new_project = project;

        if new_project.id.is_none() {
            new_project.id = Some(Uuid::new_v4().simple().to_string());
        }
        new_project.validate()?;
        self.backend_driver.create_project(state, new_project).await
    }

    /// Delete a domain by the ID.
    async fn delete_domain<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), ResourceProviderError> {
        self.backend_driver.delete_domain(state, id).await
    }

    /// Delete a project by the ID.
    async fn delete_project<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), ResourceProviderError> {
        self.backend_driver.delete_project(state, id).await
    }

    /// Get single domain.
    async fn get_domain<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        self.backend_driver.get_domain(state, domain_id).await
    }

    /// Get single project.
    async fn get_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        self.backend_driver.get_project(state, project_id).await
    }

    /// Get single project by Name and Domain ID.
    async fn get_project_by_name<'a>(
        &self,
        state: &ServiceState,
        name: &'a str,
        domain_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        self.backend_driver
            .get_project_by_name(state, name, domain_id)
            .await
    }

    /// Get project parents.
    async fn get_project_parents<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Vec<Project>>, ResourceProviderError> {
        self.backend_driver
            .get_project_parents(state, project_id)
            .await
    }

    /// Get single domain by its name.
    async fn find_domain_by_name<'a>(
        &self,
        state: &ServiceState,
        domain_name: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        self.backend_driver
            .get_domain_by_name(state, domain_name)
            .await
    }

    /// List domains.
    async fn list_domains(
        &self,
        state: &ServiceState,
        params: &DomainListParameters,
    ) -> Result<Vec<Domain>, ResourceProviderError> {
        self.backend_driver.list_domains(state, params).await
    }

    /// List projects.
    async fn list_projects(
        &self,
        state: &ServiceState,
        params: &ProjectListParameters,
    ) -> Result<Vec<Project>, ResourceProviderError> {
        self.backend_driver.list_projects(state, params).await
    }
}
