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
//! # OAuth2 signing key provider API.
use async_trait::async_trait;

use openstack_keystone_key_repository::asymmetric::KeyMaterial;

use crate::keystone::ServiceState;
use crate::oauth2_key::Oauth2KeyProviderError;

/// The trait for managing per-domain OAuth2 signing keys (ADR 0026 §3).
#[async_trait]
pub trait Oauth2KeyApi: Send + Sync {
    /// Idempotently ensure a `Primary` signing keypair exists for
    /// `domain_id`, using the configured `[oauth2] signing_algorithm`. Safe
    /// to call on a retried domain-creation request.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `domain_id` - The domain to provision keys for.
    ///
    /// # Returns
    /// * Success with the domain's `Primary` [`KeyMaterial`].
    /// * Error if the keypair could not be generated or persisted.
    async fn ensure_domain_keys(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<KeyMaterial, Oauth2KeyProviderError>;

    /// Fetch the domain's active signing keys as a JSON Web Key Set,
    /// carrying `Primary` (and `Previous`, if present) for
    /// `GET /v4/oauth2/{domain_id}/jwks` (ADR 0026 §3).
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `domain_id` - The domain to fetch the JWKS for.
    ///
    /// # Returns
    /// * Success with the domain's [`jsonwebtoken::jwk::JwkSet`].
    /// * [`Oauth2KeyProviderError::NotFound`] if no keys are provisioned for
    ///   this domain.
    async fn jwks(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<jsonwebtoken::jwk::JwkSet, Oauth2KeyProviderError>;

    /// Fetch the domain's current `Primary` signing key, including private
    /// key material, for signing a newly minted `/token` JWT (ADR 0026 §7,
    /// Phase 3). Unlike [`Self::jwks`] this is never exposed over HTTP.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `domain_id` - The domain to fetch the signing key for.
    ///
    /// # Returns
    /// * Success with the domain's `Primary` [`KeyMaterial`].
    /// * [`Oauth2KeyProviderError::NotFound`] if no keys are provisioned for
    ///   this domain.
    async fn active_signing_key(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<KeyMaterial, Oauth2KeyProviderError>;
}
