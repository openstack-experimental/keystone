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
//!
//! Following Keystone concepts are covered by the provider:
//!
//! ## Domain
//!
//! An Identity service API v3 entity. Domains are a collection of projects and
//! users that define administrative boundaries for managing Identity entities.
//! Domains can represent an individual, company, or operator-owned space. They
//! expose administrative activities directly to system users. Users can be
//! granted the administrator role for a domain. A domain administrator can
//! create projects, users, and groups in a domain and assign roles to users and
//! groups in a domain.
//!
//! ## Project
//!
//! A container that groups or isolates resources or identity objects. Depending
//! on the service operator, a project might map to a customer, account,
//! organization, or tenant.
use async_trait::async_trait;
use std::sync::Arc;

pub mod backend;
pub mod error;
#[cfg(test)]
mod mock;
pub mod types;

use crate::config::Config;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;
use crate::resource::backend::{ResourceBackend, sql::SqlBackend};
use crate::resource::error::ResourceProviderError;
use crate::resource::types::{Domain, Project};

#[cfg(test)]
pub use mock::MockResourceProvider;
pub use types::ResourceApi;

#[derive(Clone)]
pub struct ResourceProvider {
    backend_driver: Arc<dyn ResourceBackend>,
}

impl ResourceProvider {
    pub fn new(
        config: &Config,
        plugin_manager: &PluginManager,
    ) -> Result<Self, ResourceProviderError> {
        let backend_driver = if let Some(driver) =
            plugin_manager.get_resource_backend(config.resource.driver.clone())
        {
            driver.clone()
        } else {
            match config.resource.driver.as_str() {
                "sql" => Arc::new(SqlBackend::default()),
                _ => {
                    return Err(ResourceProviderError::UnsupportedDriver(
                        config.resource.driver.clone(),
                    ));
                }
            }
        };
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl ResourceApi for ResourceProvider {
    /// Get single domain
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_domain<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        self.backend_driver.get_domain(state, domain_id).await
    }

    /// Get single domain by its name
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn find_domain_by_name<'a>(
        &self,
        state: &ServiceState,
        domain_name: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        self.backend_driver
            .get_domain_by_name(state, domain_name)
            .await
    }

    /// Get single project
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        self.backend_driver.get_project(state, project_id).await
    }

    /// Get single project by Name and Domain ID
    #[tracing::instrument(level = "info", skip(self, state))]
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

    /// Get project parents
    async fn get_project_parents<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Vec<Project>>, ResourceProviderError> {
        self.backend_driver
            .get_project_parents(state, project_id)
            .await
    }
}
