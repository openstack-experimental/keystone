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
//! # SPIFFE attestation signing key provider API.

use async_trait::async_trait;

use openstack_keystone_core_types::spiffe_key::SpiffeKeyProviderError;
use openstack_keystone_key_repository::asymmetric::KeyMaterial;

use crate::keystone::ServiceState;

/// The trait for managing per-domain SPIFFE attestation signing keys
/// (SPIRE integration plan, Phase 2, "Attestation key isolation"). A
/// second, independent key from `[oauth2]`'s -- see
/// `doc/src/adr/0032-vendor-data-jwt.md`. Mocked centrally in
/// [`crate::mocks`] as `MockSpiffeKeyProvider`, matching every other
/// top-level provider trait in this crate.
#[async_trait]
pub trait SpiffeKeyApi: Send + Sync {
    /// Idempotently ensure a `Primary` attestation signing keypair exists
    /// for `domain_id`, using the configured
    /// `[vendordata] signing_algorithm`.
    async fn ensure_domain_keys(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<KeyMaterial, SpiffeKeyProviderError>;

    /// Fetch the domain's active attestation signing keys as a JSON Web Key
    /// Set, for `GET /v4/spiffe/{domain_id}/jwks`.
    async fn jwks(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<jsonwebtoken::jwk::JwkSet, SpiffeKeyProviderError>;

    /// Fetch the domain's current `Primary` attestation signing key,
    /// including private key material, for signing a new attestation JWT
    /// at `POST /v4/vendordata`.
    async fn active_signing_key(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<KeyMaterial, SpiffeKeyProviderError>;
}
