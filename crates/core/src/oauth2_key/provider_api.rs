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
use std::collections::HashSet;

use async_trait::async_trait;

use openstack_keystone_key_repository::asymmetric::KeyMaterial;

use crate::keystone::ServiceState;
use crate::oauth2_key::Oauth2KeyProviderError;
use openstack_keystone_core_types::oauth2_key::PendingRotationInfo;

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

    /// Normal (non-emergency) signing key rotation (ADR 0026 §3, "Normal
    /// Rotation Flow"): generate a fresh keypair, stage it as `Pending`,
    /// then atomically promote it to `Primary` (demoting the prior
    /// `Primary` to `Previous`).
    ///
    /// # Returns
    /// * Success with the newly active `Primary` [`KeyMaterial`].
    /// * [`Oauth2KeyProviderError::NotFound`] if no keys are provisioned yet
    ///   for this domain (rotation requires an existing `Primary`).
    async fn rotate_signing_key(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<KeyMaterial, Oauth2KeyProviderError>;

    /// Stage stage 1 of an emergency rotation (ADR 0026 §3, "Emergency
    /// Rotation and Signing Key Compromise"): generate a fresh keypair and
    /// persist it as a pending emergency rotation record, awaiting a second
    /// operator's confirmation within the 15-minute dual-control window.
    /// Does not touch the currently active keys.
    ///
    /// # Arguments
    /// * `initiator` - Identity of the operator staging the rotation (recorded
    ///   for the dual-control check and the audit trail).
    async fn stage_emergency_rotation(
        &self,
        state: &ServiceState,
        domain_id: &str,
        initiator: &str,
    ) -> Result<PendingRotationInfo, Oauth2KeyProviderError>;

    /// Confirm a pending emergency rotation (stage 2): validates
    /// `rotation_id` exists, has not expired, and that `confirmer` differs
    /// from the staging `initiator` (dual-control), then atomically
    /// promotes the staged key to `Primary` (demoting the prior `Primary`
    /// to `Previous`, same as normal rotation) and adds `revoke_jtis` to
    /// the domain's JTI revocation list (ADR 0026 §3, §11).
    ///
    /// # Errors
    /// * [`Oauth2KeyProviderError::NoPendingRotation`] if `rotation_id` is
    ///   unknown.
    /// * [`Oauth2KeyProviderError::RotationExpired`] if the 15-minute window
    ///   elapsed.
    /// * [`Oauth2KeyProviderError::DualControlViolation`] if `confirmer ==
    ///   initiator`.
    async fn confirm_emergency_rotation(
        &self,
        state: &ServiceState,
        domain_id: &str,
        rotation_id: &str,
        confirmer: &str,
        revoke_jtis: Vec<String>,
    ) -> Result<KeyMaterial, Oauth2KeyProviderError>;

    /// Fetch the domain's current JTI revocation list for
    /// `GET /v4/oauth2/{domain_id}/jwks/revocation` (ADR 0026 §3, §11).
    /// Entries past their TTL are lazily excluded, mirroring ADR 0020
    /// §4.A's lazy-sweep posture -- there is no separate background
    /// janitor for this list.
    async fn revoked_jtis(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<HashSet<String>, Oauth2KeyProviderError>;
}
