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
//! # K8s auth - internal mocking tools.
use async_trait::async_trait;
#[cfg(test)]
use mockall::mock;

use crate::auth::AuthenticatedInfo;
use crate::config::Config;
use crate::k8s_auth::{K8sAuthApi, K8sAuthProviderError, types::*};
use crate::plugin_manager::PluginManager;

use crate::keystone::ServiceState;

#[cfg(test)]
mock! {
    pub K8sAuthProvider {
        pub fn new(cfg: &Config, plugin_manager: &PluginManager) -> Result<Self, K8sAuthProviderError>;
    }

    #[async_trait]
    impl K8sAuthApi for K8sAuthProvider {

        /// Authenticate (exchange) the K8s Service account token.
        async fn authenticate_by_k8s_sa_token(
            &self,
            state: &ServiceState,
            req: &K8sAuthRequest,
        ) -> Result<AuthenticatedInfo, K8sAuthProviderError>;

        /// Register new K8s auth.
        async fn create_k8s_auth_configuration(
            &self,
            state: &ServiceState,
            config: K8sAuthConfigurationCreate,
        ) -> Result<K8sAuthConfiguration, K8sAuthProviderError>;

        /// Register new K8s auth role.
        async fn create_k8s_auth_role(
            &self,
            state: &ServiceState,
            role: K8sAuthRoleCreate,
        ) -> Result<K8sAuthRole, K8sAuthProviderError>;

        /// Delete K8s auth.
        async fn delete_k8s_auth_configuration<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<(), K8sAuthProviderError>;

        /// Delete K8s auth role.
        async fn delete_k8s_auth_role<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<(), K8sAuthProviderError>;

        /// Register new K8s auth.
        async fn get_k8s_auth_configuration<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<K8sAuthConfiguration>, K8sAuthProviderError>;

        /// Register new K8s auth role.
        async fn get_k8s_auth_role<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
        ) -> Result<Option<K8sAuthRole>, K8sAuthProviderError>;

        /// List K8s auth configurations.
        async fn list_k8s_auth_configurations(
            &self,
            state: &ServiceState,
            params: &K8sAuthConfigurationListParameters,
        ) -> Result<Vec<K8sAuthConfiguration>, K8sAuthProviderError>;

        /// List K8s auth roles.
        async fn list_k8s_auth_roles(
            &self,
            state: &ServiceState,
            params: &K8sAuthRoleListParameters,
        ) -> Result<Vec<K8sAuthRole>, K8sAuthProviderError>;

        /// Update K8s auth.
        async fn update_k8s_auth_configuration<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
            data: K8sAuthConfigurationUpdate,
        ) -> Result<K8sAuthConfiguration, K8sAuthProviderError>;

        /// Update K8s auth role.
        async fn update_k8s_auth_role<'a>(
            &self,
            state: &ServiceState,
            id: &'a str,
            data: K8sAuthRoleUpdate,
        ) -> Result<K8sAuthRole, K8sAuthProviderError>;
    }
}
