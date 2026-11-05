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
//! # Token revocation provider.

use async_trait::async_trait;
use chrono::{TimeDelta, Utc};
use std::sync::Arc;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::revoke::*;
use openstack_keystone_core_types::token::FernetToken;

use crate::auth::ExecutionContext;
use crate::auth::ValidatedSecurityContext;
use crate::events::AuditDispatchError;
use crate::plugin_manager::PluginManagerApi;
use crate::revoke::{RevokeApi, RevokeProviderError, backend::RevokeBackend};

/// Revoke provider.
pub struct RevokeService {
    /// Backend driver.
    backend_driver: Arc<dyn RevokeBackend>,
}

impl RevokeService {
    /// Create a new RevokeService.
    ///
    /// # Arguments
    /// * `config` - The configuration for the service.
    /// * `plugin_manager` - The plugin manager used to load the backend driver.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, RevokeProviderError> {
        let backend_driver = plugin_manager
            .get_revoke_backend(config.revoke.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl RevokeApi for RevokeService {
    /// Delete the revocation events that can no longer affect any token.
    ///
    /// A token issued at `t` expires no later than `t + token.expiration`, so
    /// an event revoked longer ago than that plus `expiration_buffer` cannot
    /// match a token that is still usable.
    ///
    /// # Arguments
    /// * `ctx` - The execution context.
    #[tracing::instrument(name = "provider.revoke.cleanup", level = "debug", skip_all)]
    async fn cleanup<'a>(&self, ctx: &ExecutionContext<'a>) -> Result<u64, RevokeProviderError> {
        // Read the lifetimes on every run: a reloaded `token.expiration` must
        // not leave events that still cover live tokens exposed to cleanup.
        let retention = {
            let config = ctx.state().config_manager.config.read().await;
            TimeDelta::seconds(
                i64::try_from(config.token.expiration)
                    .unwrap_or(i64::MAX)
                    .saturating_add(
                        i64::try_from(config.revoke.expiration_buffer).unwrap_or(i64::MAX),
                    ),
            )
        };
        let revoked_before = Utc::now()
            .checked_sub_signed(retention)
            .unwrap_or(chrono::DateTime::UNIX_EPOCH);
        self.backend_driver
            .delete_expired_revocation_events(ctx.state(), revoked_before)
            .await
    }

    /// Create revocation event.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `event` - The revocation event to create.
    #[tracing::instrument(
        name = "provider.revoke.create_revocation_event",
        level = "debug",
        skip_all
    )]
    async fn create_revocation_event<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        event: RevocationEventCreate,
    ) -> Result<RevocationEvent, RevokeProviderError> {
        let payload = EventPayload::RevocationEvent {
            audit_id: event.audit_id.clone(),
            user_id: event.user_id.clone(),
        };
        let op = async {
            self.backend_driver
                .create_revocation_event(ctx.state(), event)
                .await
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: Event::new(Operation::Revoke, payload),
            operation: op,
            on_audit_error: |_: AuditDispatchError| RevokeProviderError::AuditUnavailable,
        }
    }

    /// Check whether the token has been revoked or not.
    ///
    /// Checks revocation events matching the token parameters and return
    /// `false` if their count is more than `0`.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `token_security_context` - A `ValidatedSecurityContext` of the Token.
    /// * `token` - The token to check.
    #[tracing::instrument(name = "provider.revoke.is_token_revoked", level = "debug", skip_all)]
    async fn is_token_revoked<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        token_security_context: &ValidatedSecurityContext,
    ) -> Result<bool, RevokeProviderError> {
        tracing::debug!("Checking for the revocation events");
        self.backend_driver
            .is_token_revoked(ctx.state(), token_security_context)
            .await
    }

    /// Revoke the token.
    ///
    /// Mark the token as revoked to prohibit from being used even while not
    /// expired.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `token` - The token to revoke.
    #[tracing::instrument(name = "provider.revoke.revoke_token", level = "debug", skip_all)]
    async fn revoke_token<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        token: &FernetToken,
    ) -> Result<(), RevokeProviderError> {
        let payload = EventPayload::RevocationEvent {
            audit_id: token.audit_ids().first().cloned(),
            user_id: Some(token.user_id().clone()),
        };
        let op = async { self.backend_driver.revoke_token(ctx.state(), token).await };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: Event::new(Operation::Revoke, payload),
            operation: op,
            on_audit_error: |_: AuditDispatchError| RevokeProviderError::AuditUnavailable,
        }?;
        // ADR 0031 "Tokens": `keystone_token_revoked_total{reason}`. This
        // `RevokeApi::revoke_token` method (as opposed to the more general
        // `create_revocation_event`) has exactly one caller across the
        // workspace - `DELETE /v3/auth/tokens`
        // (`crates/keystone/src/api/v3/auth/token/delete.rs`), the token
        // owner (or an admin) explicitly revoking one specific token -
        // hence the fixed `"user_request"` reason here.
        crate::token::TOKEN_METRICS.record_revoked("user_request");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::revoke::backend::MockRevokeBackend;
    use crate::tests::get_mocked_state;

    fn create_revoke_provider(backend: MockRevokeBackend) -> RevokeService {
        RevokeService {
            backend_driver: Arc::new(backend),
        }
    }

    #[tokio::test]
    async fn test_create_revocation_event() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockRevokeBackend::default();
        backend
            .expect_create_revocation_event()
            .returning(|_, _| Ok(RevocationEvent::default()));
        let provider = create_revoke_provider(backend);

        assert!(
            provider
                .create_revocation_event(
                    &ExecutionContext::internal(&state),
                    RevocationEventCreate::default()
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_cleanup_uses_retention_cutoff() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockRevokeBackend::default();
        backend
            .expect_delete_expired_revocation_events()
            .withf(|_, before| {
                let expected = Utc::now() - TimeDelta::seconds(5400);
                (expected - *before).num_seconds().abs() <= 5
            })
            .returning(|_, _| Ok(7));
        let provider = create_revoke_provider(backend);

        assert_eq!(
            provider
                .cleanup(&ExecutionContext::internal(&state))
                .await
                .unwrap(),
            7
        );
    }

    #[tokio::test]
    async fn test_cleanup_propagates_backend_error() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockRevokeBackend::default();
        backend
            .expect_delete_expired_revocation_events()
            .returning(|_, _| Err(RevokeProviderError::TokenHasNoAuditId));
        let provider = create_revoke_provider(backend);

        assert!(
            provider
                .cleanup(&ExecutionContext::internal(&state))
                .await
                .is_err()
        );
    }
}
