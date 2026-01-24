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

use crate::keystone::ServiceState;
use crate::resource::ResourceProviderError;
use crate::resource::types::domain::*;
use crate::resource::types::project::*;

/// Resource API.
#[async_trait]
pub trait ResourceApi: Send + Sync {
    /// Check whether the domain is enabled.
    async fn get_domain_enabled<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<bool, ResourceProviderError>;

    /// Create a new project.
    async fn create_project(
        &self,
        state: &ServiceState,
        project: ProjectCreate,
    ) -> Result<Project, ResourceProviderError>;

    /// Get a domain by the `id`.
    async fn get_domain<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError>;

    /// Get a project by the `id`.
    async fn get_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError>;

    /// Get a project by the `name` and the `domain_id`.
    async fn get_project_by_name<'a>(
        &self,
        state: &ServiceState,
        name: &'a str,
        domain_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError>;

    /// Get project parents.
    async fn get_project_parents<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Vec<Project>>, ResourceProviderError>;

    /// Find domain by the `name`.
    async fn find_domain_by_name<'a>(
        &self,
        state: &ServiceState,
        domain_name: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError>;

    /// List domains.
    async fn list_domains(
        &self,
        state: &ServiceState,
        params: &DomainListParameters,
    ) -> Result<Vec<Domain>, ResourceProviderError>;

    /// List projects.
    async fn list_projects(
        &self,
        state: &ServiceState,
        params: &ProjectListParameters,
    ) -> Result<Vec<Project>, ResourceProviderError>;
}
