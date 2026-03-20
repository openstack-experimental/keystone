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
//! # Kubernetes authentication.

use std::sync::Arc;

use async_trait::async_trait;

use crate::auth::AuthenticatedInfo;
use crate::common::{HttpClientPool, HttpClientProvider};
use crate::config::Config;
use crate::k8s_auth::{K8sAuthProviderError, backend::K8sAuthBackend, types::*};
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::token::types::TokenRestriction;

/// K8s Auth provider.
pub struct K8sAuthService {
    /// Backend driver.
    pub(super) backend_driver: Arc<dyn K8sAuthBackend>,

    /// Reqwest client.
    pub(super) http_client_pool: Box<dyn HttpClientProvider>,
}

impl K8sAuthService {
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, K8sAuthProviderError> {
        let backend_driver = plugin_manager
            .get_k8s_auth_backend(config.k8s_auth.driver.clone())?
            .clone();
        Ok(Self {
            backend_driver,
            http_client_pool: Box::new(HttpClientPool::default()),
        })
    }
}

#[async_trait]
impl K8sAuthApi for K8sAuthService {
    /// Authenticate (exchange) the K8s Service account token.
    async fn authenticate_by_k8s_sa_token(
        &self,
        state: &ServiceState,
        req: &K8sAuthRequest,
    ) -> Result<(AuthenticatedInfo, TokenRestriction), K8sAuthProviderError> {
        self.authenticate(state, req).await
    }

    /// Register new K8s auth instance.
    #[tracing::instrument(skip(self, state))]
    async fn create_auth_instance(
        &self,
        state: &ServiceState,
        instance: K8sAuthInstanceCreate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError> {
        let mut new = instance;
        if new.id.is_none() {
            new.id = Some(uuid::Uuid::new_v4().simple().to_string());
        }
        self.backend_driver.create_auth_instance(state, new).await
    }

    /// Register new K8s auth role.
    #[tracing::instrument(skip(self, state))]
    async fn create_auth_role(
        &self,
        state: &ServiceState,
        role: K8sAuthRoleCreate,
    ) -> Result<K8sAuthRole, K8sAuthProviderError> {
        let mut new = role;
        if new.id.is_none() {
            new.id = Some(uuid::Uuid::new_v4().simple().to_string());
        }
        self.backend_driver.create_auth_role(state, new).await
    }

    /// Delete K8s auth provider.
    #[tracing::instrument(skip(self, state))]
    async fn delete_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), K8sAuthProviderError> {
        self.backend_driver.delete_auth_instance(state, id).await
    }

    /// Delete K8s auth role.
    #[tracing::instrument(skip(self, state))]
    async fn delete_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), K8sAuthProviderError> {
        self.backend_driver.delete_auth_role(state, id).await
    }

    /// Register new K8s auth instance.
    #[tracing::instrument(skip(self, state))]
    async fn get_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<K8sAuthInstance>, K8sAuthProviderError> {
        self.backend_driver.get_auth_instance(state, id).await
    }

    /// Register new K8s auth role.
    #[tracing::instrument(skip(self, state))]
    async fn get_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<K8sAuthRole>, K8sAuthProviderError> {
        self.backend_driver.get_auth_role(state, id).await
    }

    /// List K8s auth instances.
    #[tracing::instrument(skip(self, state))]
    async fn list_auth_instances(
        &self,
        state: &ServiceState,
        params: &K8sAuthInstanceListParameters,
    ) -> Result<Vec<K8sAuthInstance>, K8sAuthProviderError> {
        self.backend_driver.list_auth_instances(state, params).await
    }

    /// List K8s auth roles.
    #[tracing::instrument(skip(self, state))]
    async fn list_auth_roles(
        &self,
        state: &ServiceState,
        params: &K8sAuthRoleListParameters,
    ) -> Result<Vec<K8sAuthRole>, K8sAuthProviderError> {
        self.backend_driver.list_auth_roles(state, params).await
    }

    /// Update K8s auth instance.
    #[tracing::instrument(skip(self, state))]
    async fn update_auth_instance<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: K8sAuthInstanceUpdate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError> {
        self.backend_driver
            .update_auth_instance(state, id, data)
            .await
    }

    /// Update K8s auth role.
    #[tracing::instrument(skip(self, state))]
    async fn update_auth_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        data: K8sAuthRoleUpdate,
    ) -> Result<K8sAuthRole, K8sAuthProviderError> {
        self.backend_driver.update_auth_role(state, id, data).await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::k8s_auth::backend::MockK8sAuthBackend;
    use crate::tests::get_mocked_state;

    #[tokio::test]
    async fn test_create_auth_instance() {
        let state = get_mocked_state(None, None);
        let mut backend = MockK8sAuthBackend::default();
        backend
            .expect_create_auth_instance()
            .returning(|_, _| Ok(K8sAuthInstance::default()));
        let provider = K8sAuthService {
            backend_driver: Arc::new(backend),
            http_client_pool: Box::new(HttpClientPool::default()),
        };

        assert!(
            provider
                .create_auth_instance(
                    &state,
                    K8sAuthInstanceCreate {
                        ca_cert: Some("ca".into()),
                        disable_local_ca_jwt: Some(true),
                        domain_id: "did".into(),
                        enabled: true,
                        host: "host".into(),
                        id: Some("id".into()),
                        name: Some("name".into()),
                    }
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_create_auth_role() {
        let state = get_mocked_state(None, None);
        let mut backend = MockK8sAuthBackend::default();
        backend
            .expect_create_auth_role()
            .returning(|_, _| Ok(K8sAuthRole::default()));
        let provider = K8sAuthService {
            backend_driver: Arc::new(backend),
            http_client_pool: Box::new(HttpClientPool::default()),
        };

        assert!(
            provider
                .create_auth_role(
                    &state,
                    K8sAuthRoleCreate {
                        auth_instance_id: "cid".into(),
                        bound_audience: Some("aud".into()),
                        bound_service_account_names: vec!["a".into(), "b".into()],
                        bound_service_account_namespaces: vec!["na".into(), "nb".into()],
                        domain_id: "did".into(),
                        enabled: true,
                        id: Some("id".into()),
                        name: "name".into(),
                        token_restriction_id: "trid".into(),
                    }
                )
                .await
                .is_ok()
        );
    }
}
