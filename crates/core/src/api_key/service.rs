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
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};

use crate::api_key::{ApiKeyApi, ApiKeyProviderError, backend::ApiKeyBackend};
use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
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

/// Build the audit event for an API key change. The payload carries the public
/// `client_id` only, never the key, its lookup hash or its secret hash.
fn api_key_event(operation: Operation, domain_id: &str, client_id: &str) -> Event {
    Event::new(
        operation,
        EventPayload::ApiKey {
            domain_id: domain_id.to_string(),
            client_id: client_id.to_string(),
        },
    )
}

#[async_trait]
impl ApiKeyApi for ApiKeyService {
    async fn create<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        data: ApiClientResourceCreate,
    ) -> Result<ApiClientResource, ApiKeyProviderError> {
        let event = api_key_event(Operation::Create, &data.domain_id, &data.client_id);
        let op = async { self.backend_driver.create(ctx.state(), data).await };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: event,
            operation: op,
            on_audit_error: |_: AuditDispatchError| ApiKeyProviderError::AuditUnavailable,
        }
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
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        client_id: &'a str,
        data: ApiClientResourceUpdate,
    ) -> Result<ApiClientResource, ApiKeyProviderError> {
        let state = ctx.state();
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
        let op = async {
            self.backend_driver
                .update(state, domain_id, client_id, data)
                .await
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: api_key_event(Operation::Update, domain_id, client_id),
            operation: op,
            on_audit_error: |_: AuditDispatchError| ApiKeyProviderError::AuditUnavailable,
        }
    }

    async fn revoke<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        client_id: &'a str,
        revoked_by: &'a str,
    ) -> Result<ApiClientResource, ApiKeyProviderError> {
        let op = async {
            self.backend_driver
                .revoke(ctx.state(), domain_id, client_id, revoked_by)
                .await
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: api_key_event(Operation::Revoke, domain_id, client_id),
            operation: op,
            on_audit_error: |_: AuditDispatchError| ApiKeyProviderError::AuditUnavailable,
        }
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
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        client_id: &'a str,
    ) -> Result<(), ApiKeyProviderError> {
        let op = async {
            self.backend_driver
                .purge(ctx.state(), domain_id, client_id)
                .await
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: api_key_event(Operation::Delete, domain_id, client_id),
            operation: op,
            on_audit_error: |_: AuditDispatchError| ApiKeyProviderError::AuditUnavailable,
        }
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
            .update(
                &ExecutionContext::internal(&state),
                "domain_id",
                "client-1",
                enable_patch(),
            )
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
            .update(
                &ExecutionContext::internal(&state),
                "domain_id",
                "client-1",
                enable_patch(),
            )
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
                &ExecutionContext::internal(&state),
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
            .update(
                &ExecutionContext::internal(&state),
                "domain_id",
                "nonexistent",
                enable_patch(),
            )
            .await;

        assert!(matches!(result, Err(ApiKeyProviderError::NotFound(_))));
    }

    // ---- audit (ADR 0023): fail-closed around the provider operation ----

    #[tokio::test]
    async fn test_revoke_with_security_context_records_attempt_and_success() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockApiKeyBackend::default();
        backend
            .expect_revoke()
            .returning(|_, _, _, _| Ok(sample_resource(Some(1))));
        let service = ApiKeyService {
            backend_driver: std::sync::Arc::new(backend),
        };
        let hook = crate::tests::RecordingAuditHook::new();
        state.event_dispatcher.subscribe_audit(hook.clone()).await;
        let vsc = crate::tests::test_vsc();

        service
            .revoke(
                &ExecutionContext::from_auth(&state, &vsc),
                "domain_id",
                "client-1",
                "operator-1",
            )
            .await
            .unwrap();

        assert_eq!(hook.outcomes(), ["Attempt", "Success"]);
        let (operation, payload, _) = &hook.seen()[0];
        assert_eq!(operation, "Revoke");
        assert!(payload.contains("ApiKey"), "{payload}");
        assert!(payload.contains("client-1"), "{payload}");
        assert!(!payload.contains("hash-1"), "lookup hash leaked: {payload}");
        assert!(!payload.contains("argon2"), "secret hash leaked: {payload}");
    }

    #[tokio::test]
    async fn test_purge_fails_closed_when_the_pre_audit_is_refused() {
        let state = get_mocked_state(None, None).await;
        // No `expect_purge`: the backend must not be reached.
        let service = ApiKeyService {
            backend_driver: std::sync::Arc::new(MockApiKeyBackend::default()),
        };
        state
            .event_dispatcher
            .subscribe_audit(crate::tests::RecordingAuditHook::refusing())
            .await;
        let vsc = crate::tests::test_vsc();

        let err = service
            .purge(
                &ExecutionContext::from_auth(&state, &vsc),
                "domain_id",
                "client-1",
            )
            .await
            .unwrap_err();

        assert!(matches!(err, ApiKeyProviderError::AuditUnavailable));
    }

    #[tokio::test]
    async fn test_internal_purge_is_not_blocked_by_a_refusing_hook() {
        // The janitor has no principal: it runs the operation and the event
        // is best-effort (the `emit` path), so a refusing audit hook cannot
        // wedge housekeeping.
        let state = get_mocked_state(None, None).await;
        let mut backend = MockApiKeyBackend::default();
        backend.expect_purge().times(1).returning(|_, _, _| Ok(()));
        let service = ApiKeyService {
            backend_driver: std::sync::Arc::new(backend),
        };
        state
            .event_dispatcher
            .subscribe_audit(crate::tests::RecordingAuditHook::refusing())
            .await;

        service
            .purge(&ExecutionContext::internal(&state), "domain_id", "client-1")
            .await
            .unwrap();
    }
}
