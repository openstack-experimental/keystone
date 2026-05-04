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

use async_trait::async_trait;

use openstack_keystone_core_types::resource::*;

use crate::keystone::ServiceState;
use crate::resource::ResourceProviderError;

/// Resource API.
#[async_trait]
pub trait ResourceApi: Send + Sync {
    /// Check whether the domain is enabled.
    ///
    /// * `state` - The current service state.
    /// * `domain_id` - The ID of the domain.
    ///
    /// A `Result` containing a `bool` indicating whether the domain is enabled,
    /// or an `Error`.
    async fn get_domain_enabled<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<bool, ResourceProviderError>;

    /// Create a new domain.
    ///
    /// * `state` - The current service state.
    /// * `domain` - The domain details to create.
    ///
    /// A `Result` containing the created `Domain`, or an `Error`.
    async fn create_domain(
        &self,
        state: &ServiceState,
        domain: DomainCreate,
    ) -> Result<Domain, ResourceProviderError>;

    /// Create a new project.
    ///
    /// * `state` - The current service state.
    /// * `project` - The project details to create.
    ///
    /// A `Result` containing the created `Project`, or an `Error`.
    async fn create_project(
        &self,
        state: &ServiceState,
        project: ProjectCreate,
    ) -> Result<Project, ResourceProviderError>;

    /// Delete a domain by the ID.
    ///
    /// * `state` - The current service state.
    /// * `id` - The ID of the domain to delete.
    ///
    /// A `Result` containing `()` if successful, or an `Error`.
    async fn delete_domain<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), ResourceProviderError>;

    /// Delete a project by the ID.
    ///
    /// * `state` - The current service state.
    /// * `id` - The ID of the project to delete.
    ///
    /// A `Result` containing `()` if successful, or an `Error`.
    async fn delete_project<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), ResourceProviderError>;

    /// Get a domain by the `id`.
    ///
    /// * `state` - The current service state.
    /// * `domain_id` - The ID of the domain.
    ///
    /// A `Result` containing an `Option` with the `Domain` if found, or an
    /// `Error`.
    async fn get_domain<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError>;

    /// Get a project by the `id`.
    ///
    /// * `state` - The current service state.
    /// * `project_id` - The ID of the project.
    ///
    /// A `Result` containing an `Option` with the `Project` if found, or an
    /// `Error`.
    async fn get_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError>;

    /// Get a project by the `name` and the `domain_id`.
    ///
    /// * `state` - The current service state.
    /// * `name` - The name of the project.
    /// * `domain_id` - The ID of the domain.
    ///
    /// A `Result` containing an `Option` with the `Project` if found, or an
    /// `Error`.
    async fn get_project_by_name<'a>(
        &self,
        state: &ServiceState,
        name: &'a str,
        domain_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError>;

    /// Get project parents.
    ///
    /// * `state` - The current service state.
    /// * `project_id` - The ID of the project.
    ///
    /// A `Result` containing an `Option` with the `Vec<Project>` if found, or
    /// an `Error`.
    async fn get_project_parents<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Vec<Project>>, ResourceProviderError>;

    /// Find domain by the `name`.
    ///
    /// * `state` - The current service state.
    /// * `domain_name` - The name of the domain.
    ///
    /// A `Result` containing an `Option` with the `Domain` if found, or an
    /// `Error`.
    async fn find_domain_by_name<'a>(
        &self,
        state: &ServiceState,
        domain_name: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError>;

    /// List domains.
    ///
    /// * `state` - The current service state.
    /// * `params` - The list parameters.
    ///
    /// A `Result` containing a `Vec<Domain>`, or an `Error`.
    async fn list_domains(
        &self,
        state: &ServiceState,
        params: &DomainListParameters,
    ) -> Result<Vec<Domain>, ResourceProviderError>;

    /// List projects.
    ///
    /// * `state` - The current service state.
    /// * `params` - The list parameters.
    ///
    /// A `Result` containing a `Vec<Project>`, or an `Error`.
    async fn list_projects(
        &self,
        state: &ServiceState,
        params: &ProjectListParameters,
    ) -> Result<Vec<Project>, ResourceProviderError>;
}
