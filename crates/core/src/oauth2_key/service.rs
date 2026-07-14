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
//! # OAuth2 signing key provider
use std::sync::Arc;

use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_key_repository::asymmetric::{
    KeyMaterial, SigningAlgorithm as KeySigningAlgorithm,
};

use crate::keystone::ServiceState;
use crate::oauth2_key::jwks::active_keys_to_jwk_set;
use crate::oauth2_key::{Oauth2KeyApi, Oauth2KeyProviderError, backend::Oauth2KeyBackend};
use crate::plugin_manager::PluginManagerApi;

/// The only backend name registered for the OAuth2 signing key provider:
/// ADR 0026 §3 mandates Raft + FjallDB, there is no alternative driver to
/// select between (unlike e.g. `[api_key] driver`).
const BACKEND_NAME: &str = "raft";

/// OAuth2 signing key Provider.
pub struct Oauth2KeyService {
    /// Backend driver.
    backend_driver: Arc<dyn Oauth2KeyBackend>,
    /// Signing algorithm from `[oauth2] signing_algorithm`.
    signing_algorithm: KeySigningAlgorithm,
}

impl Oauth2KeyService {
    /// Create a new `Oauth2KeyService`.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, Oauth2KeyProviderError> {
        let backend_driver = plugin_manager.get_oauth2_key_backend(BACKEND_NAME)?.clone();
        let signing_algorithm = match config.oauth2.signing_algorithm {
            openstack_keystone_config::SigningAlgorithm::Es256 => KeySigningAlgorithm::Es256,
            openstack_keystone_config::SigningAlgorithm::Rs256 => KeySigningAlgorithm::Rs256,
        };
        Ok(Self {
            backend_driver,
            signing_algorithm,
        })
    }
}

#[async_trait]
impl Oauth2KeyApi for Oauth2KeyService {
    async fn ensure_domain_keys(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<KeyMaterial, Oauth2KeyProviderError> {
        self.backend_driver
            .ensure_domain_keys(state, domain_id, self.signing_algorithm)
            .await
    }

    async fn jwks(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<jsonwebtoken::jwk::JwkSet, Oauth2KeyProviderError> {
        let active = self.backend_driver.active_keys(state, domain_id).await?;
        active_keys_to_jwk_set(&active)
    }

    async fn active_signing_key(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<KeyMaterial, Oauth2KeyProviderError> {
        let active = self.backend_driver.active_keys(state, domain_id).await?;
        Ok(active.primary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2_key::backend::MockOauth2KeyBackend;
    use crate::tests::get_mocked_state;
    use openstack_keystone_key_repository::asymmetric::generate_keypair;

    #[tokio::test]
    async fn test_ensure_domain_keys_delegates_configured_algorithm() {
        let mut backend = MockOauth2KeyBackend::default();
        backend
            .expect_ensure_domain_keys()
            .withf(|_, domain_id: &str, algorithm: &KeySigningAlgorithm| {
                domain_id == "domain-1" && *algorithm == KeySigningAlgorithm::Es256
            })
            .returning(|_, _, algorithm| Ok(generate_keypair(algorithm).unwrap()));
        let service = Oauth2KeyService {
            backend_driver: Arc::new(backend),
            signing_algorithm: KeySigningAlgorithm::Es256,
        };
        let state = get_mocked_state(None, None).await;

        assert!(service.ensure_domain_keys(&state, "domain-1").await.is_ok());
    }

    #[tokio::test]
    async fn test_jwks_converts_active_keys() {
        let mut backend = MockOauth2KeyBackend::default();
        backend.expect_active_keys().returning(|_, _| {
            Ok(openstack_keystone_key_repository::asymmetric::ActiveKeys {
                primary: generate_keypair(KeySigningAlgorithm::Es256).unwrap(),
                previous: None,
            })
        });
        let service = Oauth2KeyService {
            backend_driver: Arc::new(backend),
            signing_algorithm: KeySigningAlgorithm::Es256,
        };
        let state = get_mocked_state(None, None).await;

        let jwks = service.jwks(&state, "domain-1").await.unwrap();
        assert_eq!(jwks.keys.len(), 1);
    }

    #[tokio::test]
    async fn test_active_signing_key_returns_primary() {
        let mut backend = MockOauth2KeyBackend::default();
        backend.expect_active_keys().returning(|_, _| {
            Ok(openstack_keystone_key_repository::asymmetric::ActiveKeys {
                primary: generate_keypair(KeySigningAlgorithm::Es256).unwrap(),
                previous: None,
            })
        });
        let service = Oauth2KeyService {
            backend_driver: Arc::new(backend),
            signing_algorithm: KeySigningAlgorithm::Es256,
        };
        let state = get_mocked_state(None, None).await;

        let key = service
            .active_signing_key(&state, "domain-1")
            .await
            .unwrap();
        assert_eq!(key.algorithm, KeySigningAlgorithm::Es256);
    }
}
