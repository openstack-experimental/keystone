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
use std::sync::Arc;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::revoke::*;
use openstack_keystone_core_types::token::Token;

use crate::keystone::ServiceState;
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
    /// Create revocation event.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `event` - The revocation event to create.
    async fn create_revocation_event(
        &self,
        state: &ServiceState,
        event: RevocationEventCreate,
    ) -> Result<RevocationEvent, RevokeProviderError> {
        self.backend_driver
            .create_revocation_event(state, event)
            .await
    }

    /// Check whether the token has been revoked or not.
    ///
    /// Checks revocation events matching the token parameters and return
    /// `false` if their count is more than `0`.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `token` - The token to check.
    async fn is_token_revoked(
        &self,
        state: &ServiceState,
        token: &Token,
    ) -> Result<bool, RevokeProviderError> {
        tracing::info!("Checking for the revocation events");
        self.backend_driver.is_token_revoked(state, token).await
    }

    /// Revoke the token.
    ///
    /// Mark the token as revoked to prohibit from being used even while not
    /// expired.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `token` - The token to revoke.
    async fn revoke_token(
        &self,
        state: &ServiceState,
        token: &Token,
    ) -> Result<(), RevokeProviderError> {
        self.backend_driver.revoke_token(state, token).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::revoke::backend::MockRevokeBackend;
    use crate::tests::get_mocked_state;

    #[tokio::test]
    async fn test_create_revocation_event() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockRevokeBackend::default();
        backend
            .expect_create_revocation_event()
            .returning(|_, _| Ok(RevocationEvent::default()));
        let provider = RevokeService {
            backend_driver: Arc::new(backend),
        };

        assert!(
            provider
                .create_revocation_event(&state, RevocationEventCreate::default())
                .await
                .is_ok()
        );
    }
}
