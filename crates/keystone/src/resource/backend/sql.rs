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

mod domain;
mod project;

use super::super::types::*;
use crate::keystone::ServiceState;
use crate::resource::ResourceProviderError;
use crate::resource::backend::ResourceBackend;

#[derive(Default)]
pub struct SqlBackend {}

#[async_trait]
impl ResourceBackend for SqlBackend {
    /// Get `enabled` property of a domain.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_domain_enabled<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<bool, ResourceProviderError> {
        Ok(domain::get_domain_enabled(&state.db, domain_id).await?)
    }

    /// Create new project.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_project(
        &self,
        state: &ServiceState,
        project: ProjectCreate,
    ) -> Result<Project, ResourceProviderError> {
        Ok(project::create(&state.db, project).await?)
    }

    /// Get single domain by ID
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_domain<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        Ok(domain::get_domain_by_id(&state.db, domain_id).await?)
    }

    /// Get single domain by Name
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_domain_by_name<'a>(
        &self,
        state: &ServiceState,
        domain_name: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        Ok(domain::get_domain_by_name(&state.db, domain_name).await?)
    }

    /// Get single project by ID
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        Ok(project::get_project(&state.db, project_id).await?)
    }

    /// Get single project by Name and Domain ID
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_project_by_name<'a>(
        &self,
        state: &ServiceState,
        name: &'a str,
        domain_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        Ok(project::get_project_by_name(&state.db, name, domain_id).await?)
    }

    /// Get project parents
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_project_parents<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Vec<Project>>, ResourceProviderError> {
        Ok(project::get_project_parents(&state.db, project_id).await?)
    }

    /// List domains.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_domains(
        &self,
        state: &ServiceState,
        params: &DomainListParameters,
    ) -> Result<Vec<Domain>, ResourceProviderError> {
        Ok(domain::list(&state.db, params).await?)
    }

    /// List projects.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_projects(
        &self,
        state: &ServiceState,
        params: &ProjectListParameters,
    ) -> Result<Vec<Project>, ResourceProviderError> {
        Ok(project::list(&state.db, params).await?)
    }
}

impl From<crate::error::DatabaseError> for ResourceProviderError {
    fn from(source: crate::error::DatabaseError) -> Self {
        match source {
            cfl @ crate::error::DatabaseError::Conflict { .. } => Self::Conflict(cfl.to_string()),
            other => Self::Driver(other.to_string()),
        }
    }
}
