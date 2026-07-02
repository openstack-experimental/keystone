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
//! # API Key provider

use std::sync::Arc;

use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::api_key::*;

use crate::api_key::{ApiKeyApi, ApiKeyProviderError, backend::ApiKeyBackend};
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;

/// API Key Provider.
pub struct ApiKeyService {
    /// Backend driver.
    pub(super) backend_driver: Arc<dyn ApiKeyBackend>,
}

impl ApiKeyService {
    /// Create a new `ApiKeyService`.
    ///
    /// # Arguments
    /// * `config` - Reference to the [`Config`].
    /// * `plugin_manager` - Reference to the [`PluginManagerApi`].
    ///
    /// # Returns
    /// * Success with a new `ApiKeyService` instance.
    /// * `ApiKeyProviderError` if the backend driver cannot be loaded.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, ApiKeyProviderError> {
        let backend_driver = plugin_manager
            .get_api_key_backend(config.api_key.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl ApiKeyApi for ApiKeyService {
    async fn create(
        &self,
        state: &ServiceState,
        data: ApiClientResourceCreate,
    ) -> Result<ApiClientResource, ApiKeyProviderError> {
        self.backend_driver.create(state, data).await
    }

    async fn get_by_client_id<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
    ) -> Result<Option<ApiClientResource>, ApiKeyProviderError> {
        self.backend_driver
            .get_by_client_id(state, domain_id, client_id)
            .await
    }

    async fn get_by_lookup_hash<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        lookup_hash: &'a str,
    ) -> Result<Option<ApiClientResource>, ApiKeyProviderError> {
        self.backend_driver
            .get_by_lookup_hash(state, domain_id, lookup_hash)
            .await
    }

    async fn list(
        &self,
        state: &ServiceState,
        params: &ApiClientResourceListParameters,
    ) -> Result<Vec<ApiClientResource>, ApiKeyProviderError> {
        self.backend_driver.list(state, params).await
    }

    async fn update<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
        data: ApiClientResourceUpdate,
    ) -> Result<ApiClientResource, ApiKeyProviderError> {
        // ADR 0021 §5.C: revocation is the emergency-response path and MUST
        // NOT be reversible through the ordinary update surface. Enforced
        // here (not just at the HTTP layer) so it holds for every caller,
        // including direct provider use. Only checked when the caller is
        // actually trying to re-enable, so the common update (allowed_ips /
        // description, or disabling) doesn't pay for an extra read.
        if data.enabled == Some(true) {
            let current = self
                .backend_driver
                .get_by_client_id(state, domain_id, client_id)
                .await?
                .ok_or_else(|| ApiKeyProviderError::NotFound(client_id.to_string()))?;
            if current.revoked_at.is_some() {
                return Err(ApiKeyProviderError::Conflict(
                    "cannot re-enable a revoked API key".to_string(),
                ));
            }
        }
        self.backend_driver
            .update(state, domain_id, client_id, data)
            .await
    }

    async fn revoke<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
        revoked_by: &'a str,
    ) -> Result<ApiClientResource, ApiKeyProviderError> {
        self.backend_driver
            .revoke(state, domain_id, client_id, revoked_by)
            .await
    }

    async fn update_last_used<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        lookup_hash: &'a str,
        last_used_at: i64,
    ) -> Result<(), ApiKeyProviderError> {
        self.backend_driver
            .update_last_used(state, domain_id, lookup_hash, last_used_at)
            .await
    }

    async fn update_secret_hash<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        lookup_hash: &'a str,
        secret_hash: String,
    ) -> Result<(), ApiKeyProviderError> {
        self.backend_driver
            .update_secret_hash(state, domain_id, lookup_hash, secret_hash)
            .await
    }

    async fn list_all(
        &self,
        state: &ServiceState,
    ) -> Result<Vec<ApiClientResource>, ApiKeyProviderError> {
        self.backend_driver.list_all(state).await
    }

    async fn purge<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        client_id: &'a str,
    ) -> Result<(), ApiKeyProviderError> {
        self.backend_driver.purge(state, domain_id, client_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_key::backend::MockApiKeyBackend;
    use crate::tests::get_mocked_state;

    fn sample_resource(revoked_at: Option<i64>) -> ApiClientResource {
        ApiClientResource {
            domain_id: "domain_id".into(),
            provider_id: "provider-1".into(),
            client_id: "client-1".into(),
            lookup_hash: "hash-1".into(),
            secret_hash: "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA".into(),
            allowed_ips: None,
            description: None,
            enabled: revoked_at.is_none(),
            created_at: 0,
            expires_at: i64::MAX / 2,
            last_used_at: None,
            revoked_at,
            revoked_by: revoked_at.map(|_| "operator-1".to_string()),
        }
    }

    fn enable_patch() -> ApiClientResourceUpdate {
        ApiClientResourceUpdate {
            allowed_ips: None,
            description: None,
            enabled: Some(true),
        }
    }

    #[tokio::test]
    async fn test_update_rejects_reactivating_revoked_key() {
        let mut mock = MockApiKeyBackend::new();
        mock.expect_get_by_client_id()
            .returning(|_, _, _| Ok(Some(sample_resource(Some(1_000)))));
        // `expect_update` deliberately not configured: mockall panics if it's
        // called, proving the guard short-circuits before reaching the backend.
        let service = ApiKeyService {
            backend_driver: Arc::new(mock),
        };
        let state = get_mocked_state(None, None).await;

        let result = service
            .update(&state, "domain_id", "client-1", enable_patch())
            .await;

        assert!(matches!(result, Err(ApiKeyProviderError::Conflict(_))));
    }

    #[tokio::test]
    async fn test_update_allows_reactivating_non_revoked_key() {
        let mut mock = MockApiKeyBackend::new();
        mock.expect_get_by_client_id()
            .returning(|_, _, _| Ok(Some(sample_resource(None))));
        mock.expect_update()
            .returning(|_, _, _, _| Ok(sample_resource(None)));
        let service = ApiKeyService {
            backend_driver: Arc::new(mock),
        };
        let state = get_mocked_state(None, None).await;

        let result = service
            .update(&state, "domain_id", "client-1", enable_patch())
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_update_skips_guard_when_not_reactivating() {
        let mut mock = MockApiKeyBackend::new();
        // `expect_get_by_client_id` deliberately not configured: the guard
        // must not fire (and must not read) when `enabled` isn't `Some(true)`.
        mock.expect_update()
            .returning(|_, _, _, _| Ok(sample_resource(None)));
        let service = ApiKeyService {
            backend_driver: Arc::new(mock),
        };
        let state = get_mocked_state(None, None).await;

        let result = service
            .update(
                &state,
                "domain_id",
                "client-1",
                ApiClientResourceUpdate {
                    allowed_ips: Some(Some(vec!["10.0.0.0/8".to_string()])),
                    description: None,
                    enabled: None,
                },
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_update_reactivate_missing_key_is_not_found() {
        let mut mock = MockApiKeyBackend::new();
        mock.expect_get_by_client_id().returning(|_, _, _| Ok(None));
        let service = ApiKeyService {
            backend_driver: Arc::new(mock),
        };
        let state = get_mocked_state(None, None).await;

        let result = service
            .update(&state, "domain_id", "nonexistent", enable_patch())
            .await;

        assert!(matches!(result, Err(ApiKeyProviderError::NotFound(_))));
    }
}
