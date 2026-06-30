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

use openstack_keystone_config::Config;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::k8s_auth::*;

use crate::auth::{AuthenticationResult, ExecutionContext};
use crate::events::AuditDispatchError;
use crate::k8s_auth::{K8sAuthApi, K8sAuthProviderError, K8sHttpClient, backend::K8sAuthBackend};
use crate::plugin_manager::PluginManagerApi;

/// K8s Auth provider.
pub struct K8sAuthService {
    /// Backend driver.
    pub(super) backend_driver: Arc<dyn K8sAuthBackend>,

    /// HTTP client for K8s API communication.
    pub(super) http_client: Arc<dyn K8sHttpClient>,
}

impl K8sAuthService {
    /// Create a new `K8sAuthService`.
    ///
    /// # Arguments
    /// * `config` - Reference to the [`Config`].
    /// * `plugin_manager` - Reference to the [`PluginManagerApi`].
    ///
    /// # Returns
    /// * Success with a new `K8sAuthService` instance.
    /// * `K8sAuthProviderError` if the backend driver cannot be loaded.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
        http_client: Arc<dyn K8sHttpClient>,
    ) -> Result<Self, K8sAuthProviderError> {
        let backend_driver = plugin_manager
            .get_k8s_auth_backend(config.k8s_auth.driver.clone())?
            .clone();
        Ok(Self {
            backend_driver,
            http_client,
        })
    }
}

#[async_trait]
impl K8sAuthApi for K8sAuthService {
    /// Authenticate via K8s TokenReview + mapping engine.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `req` - A reference to the [`K8sAuthRequest`] to authenticate.
    ///
    /// # Returns
    /// * Success with [`AuthenticationResult`] via mapping engine.
    /// * Error if authentication fails.
    async fn authenticate_by_k8s_mapping<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        req: &K8sAuthRequest,
    ) -> Result<AuthenticationResult, K8sAuthProviderError> {
        self.authenticate_by_mapping(ctx, req).await
    }

    /// Register new K8s auth instance.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `instance` - [`K8sAuthInstanceCreate`] data for the new instance.
    ///
    /// # Returns
    /// * Success with the created [`K8sAuthInstance`].
    /// * Error if the instance could not be created.
    async fn create_auth_instance<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        instance: K8sAuthInstanceCreate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError> {
        let mut new = instance;
        if new.id.is_none() {
            new.id = Some(uuid::Uuid::new_v4().simple().to_string());
        }
        let instance_id = new.id.clone().unwrap_or_default();
        let result = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let new_clone = new.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::K8sAuthInstance { id: instance_id },
                ),
                operation: async {
                    backend_driver.create_auth_instance(ctx.state(), new_clone).await
                },
                on_audit_error: |_: AuditDispatchError| K8sAuthProviderError::Driver { source: "audit dispatch failed".into() },
            }?
        } else {
            let result = self
                .backend_driver
                .create_auth_instance(ctx.state(), new)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::K8sAuthInstance { id: instance_id },
                ))
                .await;
            result
        };
        Ok(result)
    }

    /// Delete K8s auth provider.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The identifier of the instance to delete.
    ///
    /// # Returns
    /// * Success if the instance was deleted.
    /// * Error if the deletion failed.
    async fn delete_auth_instance<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), K8sAuthProviderError> {
        if let Some(vsc) = ctx.ctx() {
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::K8sAuthInstance { id: id.to_string() },
                ),
                operation: async {
                    self.backend_driver.delete_auth_instance(ctx.state(), id).await?;
                    Ok::<(), K8sAuthProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| K8sAuthProviderError::Driver { source: "audit dispatch failed".into() },
            }?;
        } else {
            self.backend_driver
                .delete_auth_instance(ctx.state(), id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::K8sAuthInstance { id: id.to_string() },
                ))
                .await;
        }
        Ok(())
    }

    /// Fetch auth instance.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The identifier of the instance to fetch.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the [`K8sAuthInstance`] if found,
    /// or an `Error`.
    async fn get_auth_instance<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<K8sAuthInstance>, K8sAuthProviderError> {
        self.backend_driver.get_auth_instance(ctx.state(), id).await
    }

    /// List K8s auth instances.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `params` - [`K8sAuthInstanceListParameters`] for filtering the list.
    ///
    /// # Returns
    /// * Success with a list of [`K8sAuthInstance`].
    /// * Error if the listing failed.
    async fn list_auth_instances<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &K8sAuthInstanceListParameters,
    ) -> Result<Vec<K8sAuthInstance>, K8sAuthProviderError> {
        self.backend_driver
            .list_auth_instances(ctx.state(), params)
            .await
    }

    /// Update K8s auth instance.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `id` - The identifier of the instance to update.
    /// * `data` - [`K8sAuthInstanceUpdate`] data to apply.
    ///
    /// # Returns
    /// * Success with the updated [`K8sAuthInstance`].
    /// * Error if the update failed.
    async fn update_auth_instance<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
        data: K8sAuthInstanceUpdate,
    ) -> Result<K8sAuthInstance, K8sAuthProviderError> {
        let result = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let data_clone = data.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::K8sAuthInstance { id: id.to_string() },
                ),
                operation: async {
                    backend_driver.update_auth_instance(ctx.state(), id, data_clone).await
                },
                on_audit_error: |_: AuditDispatchError| K8sAuthProviderError::Driver { source: "audit dispatch failed".into() },
            }?
        } else {
            let result = self
                .backend_driver
                .update_auth_instance(ctx.state(), id, data)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::K8sAuthInstance { id: id.to_string() },
                ))
                .await;
            result
        };
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::k8s_auth::K8sHttpClient;
    use crate::k8s_auth::backend::MockK8sAuthBackend;
    use crate::tests::get_mocked_state;
    use openstack_keystone_core_types::k8s_auth::{K8sClaims, QueryTokenReviewResult};

    struct TestK8sHttpClient;

    #[async_trait]
    impl K8sHttpClient for TestK8sHttpClient {
        async fn query_token_review(
            &self,
            _instance: &K8sAuthInstance,
            _jwt: &str,
        ) -> Result<QueryTokenReviewResult, K8sAuthProviderError> {
            Ok(QueryTokenReviewResult {
                claims: K8sClaims {
                    aud: vec![],
                    exp: 0,
                    sub: String::new(),
                },
                token_review: json!({}),
            })
        }
    }

    fn create_k8s_auth_service(backend: MockK8sAuthBackend) -> K8sAuthService {
        K8sAuthService {
            backend_driver: Arc::new(backend),
            http_client: Arc::new(TestK8sHttpClient),
        }
    }

    #[tokio::test]
    async fn test_create_auth_instance() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockK8sAuthBackend::default();
        backend
            .expect_create_auth_instance()
            .returning(|_, _| Ok(K8sAuthInstance::default()));
        let provider = create_k8s_auth_service(backend);

        assert!(
            provider
                .create_auth_instance(
                    &ExecutionContext::internal(&state),
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
}
