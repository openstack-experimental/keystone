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

use openstack_keystone_config::Config;
use openstack_keystone_core_types::resource::*;

pub mod backend;
pub mod error;
#[cfg(any(test, feature = "mock"))]
mod mock;
mod provider_api;
pub mod service;

use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::resource::service::ResourceService;

pub use crate::resource::error::ResourceProviderError;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockResourceProvider;
pub use provider_api::ResourceApi;

pub enum ResourceProvider {
    Service(ResourceService),
    #[cfg(any(test, feature = "mock"))]
    Mock(MockResourceProvider),
}

impl ResourceProvider {
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, ResourceProviderError> {
        Ok(Self::Service(ResourceService::new(config, plugin_manager)?))
    }
}

#[async_trait]
impl ResourceApi for ResourceProvider {
    /// Check whether the domain is enabled.
    async fn get_domain_enabled<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<bool, ResourceProviderError> {
        match self {
            Self::Service(provider) => provider.get_domain_enabled(state, domain_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_domain_enabled(state, domain_id).await,
        }
    }

    /// Create new domain.
    async fn create_domain(
        &self,
        state: &ServiceState,
        domain: DomainCreate,
    ) -> Result<Domain, ResourceProviderError> {
        match self {
            Self::Service(provider) => provider.create_domain(state, domain).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_domain(state, domain).await,
        }
    }

    /// Create new project.
    async fn create_project(
        &self,
        state: &ServiceState,
        project: ProjectCreate,
    ) -> Result<Project, ResourceProviderError> {
        match self {
            Self::Service(provider) => provider.create_project(state, project).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_project(state, project).await,
        }
    }

    /// Delete a domain by the ID.
    async fn delete_domain<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), ResourceProviderError> {
        match self {
            Self::Service(provider) => provider.delete_domain(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.delete_domain(state, id).await,
        }
    }

    /// Delete a project by the ID.
    async fn delete_project<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), ResourceProviderError> {
        match self {
            Self::Service(provider) => provider.delete_project(state, id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.delete_project(state, id).await,
        }
    }

    /// Get single domain.
    async fn get_domain<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        match self {
            Self::Service(provider) => provider.get_domain(state, domain_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_domain(state, domain_id).await,
        }
    }

    /// Get single project.
    async fn get_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        match self {
            Self::Service(provider) => provider.get_project(state, project_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_project(state, project_id).await,
        }
    }

    /// Get single project by Name and Domain ID.
    async fn get_project_by_name<'a>(
        &self,
        state: &ServiceState,
        name: &'a str,
        domain_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        match self {
            Self::Service(provider) => provider.get_project_by_name(state, name, domain_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_project_by_name(state, name, domain_id).await,
        }
    }

    /// Get project parents.
    async fn get_project_parents<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Vec<Project>>, ResourceProviderError> {
        match self {
            Self::Service(provider) => provider.get_project_parents(state, project_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_project_parents(state, project_id).await,
        }
    }

    /// Get single domain by its name.
    async fn find_domain_by_name<'a>(
        &self,
        state: &ServiceState,
        domain_name: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        match self {
            Self::Service(provider) => provider.find_domain_by_name(state, domain_name).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.find_domain_by_name(state, domain_name).await,
        }
    }

    /// List domains.
    async fn list_domains(
        &self,
        state: &ServiceState,
        params: &DomainListParameters,
    ) -> Result<Vec<Domain>, ResourceProviderError> {
        match self {
            Self::Service(provider) => provider.list_domains(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_domains(state, params).await,
        }
    }

    /// List projects.
    async fn list_projects(
        &self,
        state: &ServiceState,
        params: &ProjectListParameters,
    ) -> Result<Vec<Project>, ResourceProviderError> {
        match self {
            Self::Service(provider) => provider.list_projects(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_projects(state, params).await,
        }
    }
}
