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
//! # SPIFFE attestation signing key provider
//!
//! Filesystem-backed, one subdirectory per domain under
//! `[vendordata] key_repository` -- deliberately not Raft-backed like
//! `[oauth2]`'s signing key (ADR 0026 §3): this is a Phase 2 scope
//! reduction, tracked as a known gap in
//! `doc/src/adr/0032-vendor-data-jwt.md`. A single-node keystone-rs
//! deployment (matching the JWS token provider's own Phase 0 posture)
//! works unchanged; multi-node HA would need the same Raft-backed
//! generalization `[oauth2]` already has.
use std::path::{Path, PathBuf};

use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::spiffe_key::SpiffeKeyProviderError;
use openstack_keystone_key_repository::asymmetric::{
    ActiveKeys, AsymmetricKeyRepository, FilesystemAsymmetricKeySource, KeyMaterial,
    SigningAlgorithm as KeySigningAlgorithm,
};
use openstack_keystone_key_repository::error::KeyRepositoryError;

use crate::keystone::ServiceState;
use crate::oauth2_key::jwks::active_keys_to_jwk_set;
use crate::spiffe_key::SpiffeKeyApi;

fn map_err(domain_id: &str, error: KeyRepositoryError) -> SpiffeKeyProviderError {
    match error {
        KeyRepositoryError::RoleMissing(_) | KeyRepositoryError::KeysMissing => {
            SpiffeKeyProviderError::NotFound(domain_id.to_string())
        }
        KeyRepositoryError::Crypto(e) => SpiffeKeyProviderError::Crypto(e),
        other => SpiffeKeyProviderError::Io(other.to_string()),
    }
}

/// SPIFFE attestation signing key Provider.
pub struct SpiffeKeyService {
    key_repository_base: PathBuf,
    signing_algorithm: KeySigningAlgorithm,
}

impl SpiffeKeyService {
    /// Create a new `SpiffeKeyService` from `[vendordata]` configuration.
    pub fn new(config: &Config) -> Result<Self, SpiffeKeyProviderError> {
        let signing_algorithm = match config.vendordata.signing_algorithm {
            openstack_keystone_config::SigningAlgorithm::Es256 => KeySigningAlgorithm::Es256,
            openstack_keystone_config::SigningAlgorithm::Rs256 => KeySigningAlgorithm::Rs256,
        };
        Ok(Self {
            key_repository_base: config.vendordata.key_repository.clone(),
            signing_algorithm,
        })
    }

    fn domain_repository(
        &self,
        domain_id: &str,
    ) -> AsymmetricKeyRepository<FilesystemAsymmetricKeySource> {
        let dir: &Path = &self.key_repository_base;
        AsymmetricKeyRepository::new(FilesystemAsymmetricKeySource::new(dir.join(domain_id)))
    }
}

#[async_trait]
impl SpiffeKeyApi for SpiffeKeyService {
    async fn ensure_domain_keys(
        &self,
        _state: &ServiceState,
        domain_id: &str,
    ) -> Result<KeyMaterial, SpiffeKeyProviderError> {
        self.domain_repository(domain_id)
            .setup(self.signing_algorithm)
            .await
            .map_err(|e| map_err(domain_id, e))
    }

    async fn jwks(
        &self,
        _state: &ServiceState,
        domain_id: &str,
    ) -> Result<jsonwebtoken::jwk::JwkSet, SpiffeKeyProviderError> {
        let active: ActiveKeys = self
            .domain_repository(domain_id)
            .load_active()
            .await
            .map_err(|e| map_err(domain_id, e))?;
        active_keys_to_jwk_set(&active).map_err(|e| SpiffeKeyProviderError::Crypto(e.to_string()))
    }

    async fn active_signing_key(
        &self,
        _state: &ServiceState,
        domain_id: &str,
    ) -> Result<KeyMaterial, SpiffeKeyProviderError> {
        let active: ActiveKeys = self
            .domain_repository(domain_id)
            .load_active()
            .await
            .map_err(|e| map_err(domain_id, e))?;
        Ok(active.primary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_config::VendordataProvider;
    use openstack_keystone_key_repository::asymmetric::SigningAlgorithm;

    fn service_with_tempdir(dir: &Path) -> SpiffeKeyService {
        let config = Config {
            vendordata: VendordataProvider {
                key_repository: dir.to_path_buf(),
                ..Default::default()
            },
            ..Default::default()
        };
        SpiffeKeyService::new(&config).unwrap()
    }

    #[tokio::test]
    async fn test_ensure_domain_keys_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_with_tempdir(dir.path());
        let state = crate::tests::get_mocked_state(None, None).await;

        let first = service
            .ensure_domain_keys(&state, "domain-1")
            .await
            .unwrap();
        let second = service
            .ensure_domain_keys(&state, "domain-1")
            .await
            .unwrap();
        assert_eq!(first.kid, second.kid);
    }

    #[tokio::test]
    async fn test_active_signing_key_not_found_for_unprovisioned_domain() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_with_tempdir(dir.path());
        let state = crate::tests::get_mocked_state(None, None).await;

        let result = service.active_signing_key(&state, "domain-1").await;
        assert!(matches!(result, Err(SpiffeKeyProviderError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_jwks_after_ensure_domain_keys() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_with_tempdir(dir.path());
        let state = crate::tests::get_mocked_state(None, None).await;

        service
            .ensure_domain_keys(&state, "domain-1")
            .await
            .unwrap();
        let jwks = service.jwks(&state, "domain-1").await.unwrap();
        assert_eq!(jwks.keys.len(), 1);
    }

    #[test]
    fn test_new_maps_algorithm_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            vendordata: VendordataProvider {
                key_repository: dir.path().to_path_buf(),
                signing_algorithm: openstack_keystone_config::SigningAlgorithm::Rs256,
                ..Default::default()
            },
            ..Default::default()
        };
        let service = SpiffeKeyService::new(&config).unwrap();
        assert_eq!(service.signing_algorithm, SigningAlgorithm::Rs256);
    }
}
