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

pub mod domain;
pub mod project;

use async_trait::async_trait;
use dyn_clone::DynClone;

use crate::config::Config;
use crate::keystone::ServiceState;
use crate::resource::ResourceProviderError;

pub use crate::resource::types::domain::{Domain, DomainBuilder, DomainBuilderError};
pub use crate::resource::types::project::{Project, ProjectBuilder, ProjectBuilderError};

#[async_trait]
pub trait ResourceBackend: DynClone + Send + Sync + std::fmt::Debug {
    /// Set config
    fn set_config(&mut self, config: Config);

    /// Get single domain by ID
    async fn get_domain<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError>;

    /// Get single domain by Name
    async fn get_domain_by_name<'a>(
        &self,
        state: &ServiceState,
        domain_name: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError>;

    /// Get single project by ID
    async fn get_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError>;

    /// Get single project by Name and Domain ID
    async fn get_project_by_name<'a>(
        &self,
        state: &ServiceState,
        name: &'a str,
        domain_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError>;

    /// Get project parents
    async fn get_project_parents<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Vec<Project>>, ResourceProviderError>;
}

dyn_clone::clone_trait_object!(ResourceBackend);
