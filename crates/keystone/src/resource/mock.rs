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
#[cfg(test)]
use mockall::mock;

use crate::config::Config;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;
use crate::resource::error::ResourceProviderError;
use crate::resource::types::*;

#[cfg(test)]
mock! {
    pub ResourceProvider {
        pub fn new(cfg: &Config, plugin_manager: &PluginManager) -> Result<Self, ResourceProviderError>;
    }

    #[async_trait]
    impl ResourceApi for ResourceProvider {
        async fn get_domain_enabled<'a>(
            &self,
            state: &ServiceState,
            domain_id: &'a str,
        ) -> Result<bool, ResourceProviderError>;

        async fn create_project(
            &self,
            state: &ServiceState,
            project: ProjectCreate,
        ) -> Result<Project, ResourceProviderError>;

        /// Delete a project by the ID.
        async fn delete_project<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<(), ResourceProviderError>;

        async fn get_domain<'a>(
            &self,
            state: &ServiceState,
            domain_id: &'a str,
        ) -> Result<Option<Domain>, ResourceProviderError>;

        async fn find_domain_by_name<'a>(
            &self,
            state: &ServiceState,
            domain_name: &'a str,
        ) -> Result<Option<Domain>, ResourceProviderError>;

        async fn get_project<'a>(
            &self,
            state: &ServiceState,
            project_id: &'a str,
        ) -> Result<Option<Project>, ResourceProviderError>;

        async fn get_project_by_name<'a>(
            &self,
            state: &ServiceState,
            name: &'a str,
            domain_id: &'a str,
        ) -> Result<Option<Project>, ResourceProviderError>;

        async fn get_project_parents<'a>(
            &self,
            state: &ServiceState,
            project_id: &'a str,
        ) -> Result<Option<Vec<Project>>, ResourceProviderError>;

        async fn list_domains(
            &self,
            state: &ServiceState,
            params: &DomainListParameters,
        ) -> Result<Vec<Domain>, ResourceProviderError>;

        async fn list_projects(
            &self,
            state: &ServiceState,
            params: &ProjectListParameters,
        ) -> Result<Vec<Project>, ResourceProviderError>;
    }
}
