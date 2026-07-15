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
//! # OAuth2 signing key provider: Backends.
use std::collections::HashSet;

use async_trait::async_trait;

use openstack_keystone_key_repository::asymmetric::{ActiveKeys, KeyMaterial, SigningAlgorithm};

use crate::keystone::ServiceState;
use crate::oauth2_key::Oauth2KeyProviderError;
use openstack_keystone_core_types::oauth2_key::PendingRotationInfo;

/// OAuth2 signing key Backend trait.
///
/// Backend driver interface expected by the OAuth2 signing key provider
/// (ADR 0026 §3). Every method is scoped to a single `domain_id` — each
/// domain owns an independent keypair, there is no cluster-wide key.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait Oauth2KeyBackend: Send + Sync {
    /// Idempotently ensure a `Primary` signing keypair exists for
    /// `domain_id`, generating one via `algorithm` if absent. Safe to call
    /// on a retried domain-creation request.
    ///
    /// # Returns
    /// * Success with the domain's `Primary` [`KeyMaterial`] (freshly generated
    ///   or pre-existing).
    /// * Error if the keypair could not be generated or persisted.
    async fn ensure_domain_keys(
        &self,
        state: &ServiceState,
        domain_id: &str,
        algorithm: SigningAlgorithm,
    ) -> Result<KeyMaterial, Oauth2KeyProviderError>;

    /// Fetch the currently active signing keys for `domain_id`: always a
    /// `Primary`, and a `Previous` if a rotation happened recently.
    ///
    /// # Returns
    /// * Success with the domain's [`ActiveKeys`].
    /// * [`Oauth2KeyProviderError::NotFound`] if no keys are provisioned for
    ///   this domain.
    async fn active_keys(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<ActiveKeys, Oauth2KeyProviderError>;

    /// Normal rotation: generate, stage as `Pending`, promote to `Primary`.
    /// See [`crate::oauth2_key::Oauth2KeyApi::rotate_signing_key`].
    async fn rotate_signing_key(
        &self,
        state: &ServiceState,
        domain_id: &str,
        algorithm: SigningAlgorithm,
    ) -> Result<KeyMaterial, Oauth2KeyProviderError>;

    /// Stage stage 1 of an emergency rotation.
    /// See [`crate::oauth2_key::Oauth2KeyApi::stage_emergency_rotation`].
    async fn stage_emergency_rotation(
        &self,
        state: &ServiceState,
        domain_id: &str,
        algorithm: SigningAlgorithm,
        initiator: &str,
    ) -> Result<PendingRotationInfo, Oauth2KeyProviderError>;

    /// Confirm stage 2 of an emergency rotation.
    /// See [`crate::oauth2_key::Oauth2KeyApi::confirm_emergency_rotation`].
    async fn confirm_emergency_rotation(
        &self,
        state: &ServiceState,
        domain_id: &str,
        rotation_id: &str,
        confirmer: &str,
        revoke_jtis: Vec<String>,
    ) -> Result<KeyMaterial, Oauth2KeyProviderError>;

    /// Fetch the domain's current (non-expired) JTI revocation list.
    /// See [`crate::oauth2_key::Oauth2KeyApi::revoked_jtis`].
    async fn revoked_jtis(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<HashSet<String>, Oauth2KeyProviderError>;

    /// Cross-domain scan of every domain currently holding a `Primary`
    /// signing key, for the previous-key/JTI janitor.
    /// See [`crate::oauth2_key::Oauth2KeyApi::list_all_active_keys`].
    async fn list_all_active_keys(
        &self,
        state: &ServiceState,
    ) -> Result<Vec<(String, ActiveKeys)>, Oauth2KeyProviderError>;

    /// Remove `domain_id`'s `Previous` signing key, if present.
    /// See [`crate::oauth2_key::Oauth2KeyApi::retire_previous_key`].
    async fn retire_previous_key(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<bool, Oauth2KeyProviderError>;

    /// Proactively sweep `domain_id`'s JTI revocation list for expired
    /// entries. See [`crate::oauth2_key::Oauth2KeyApi::prune_expired_jtis`].
    async fn prune_expired_jtis(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<(), Oauth2KeyProviderError>;
}
