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

use openstack_keystone_key_repository::asymmetric::{ActiveKeys, KeyMaterial};

use crate::keystone::ServiceState;
use crate::oauth2_key::Oauth2KeyProviderError;
use openstack_keystone_core_types::oauth2_key::{
    LocalEmergencyCandidateSummary, LocalEmergencyRotationInfo, PendingRotationInfo,
};

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

    /// Stage a `--local-quorum-bypass` emergency rotation (ADR 0028 §2):
    /// generate a fresh keypair and persist it as a node-local candidate,
    /// bypassing Raft/`StorageApi` entirely. Unlike
    /// [`Self::stage_emergency_rotation`], this never touches distributed
    /// storage — the whole point is that it works even when the node
    /// cannot reach Raft quorum.
    ///
    /// # Errors
    /// * [`Oauth2KeyProviderError::LocalEmergencyBypassNotAllowed`] if the
    ///   node's quorum-bypass guardrail refuses the request (bypass
    ///   disabled, quorum currently reachable, or grace period not yet
    ///   elapsed).
    /// * [`Oauth2KeyProviderError::LocalEmergencyAlreadyStaged`] if a
    ///   non-revoked local candidate already exists for this domain on this
    ///   node.
    async fn stage_local_emergency_rotation(
        &self,
        state: &ServiceState,
        domain_id: &str,
        initiator: &str,
        justification: &str,
    ) -> Result<LocalEmergencyRotationInfo, Oauth2KeyProviderError>;

    /// List every node-local emergency rotation candidate staged or adopted
    /// (via gossip) on this node for `domain_id` (ADR 0028 §6), so an
    /// operator can see any `LOCAL_EMERGENCY_CONFLICT` before choosing which
    /// `rotation_id` to reconcile.
    async fn list_local_emergency_candidates(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<Vec<LocalEmergencyCandidateSummary>, Oauth2KeyProviderError>;

    /// Reconcile a node-local emergency candidate into the Raft-replicated
    /// state once quorum has returned (ADR 0028 §6): promotes the chosen
    /// candidate's key to `Primary` (demoting the current `Primary` to
    /// `Previous`) via the normal Raft transaction path, then clears it from
    /// this node's local store and revokes any other active candidate for
    /// the same domain on this node (they lost).
    ///
    /// Must be called against the specific node holding `rotation_id` --
    /// reconciliation does not fan out across the cluster.
    ///
    /// # Errors
    /// * [`Oauth2KeyProviderError::LocalEmergencyCandidateNotFound`] if no
    ///   candidate with `rotation_id` exists on this node.
    /// * [`Oauth2KeyProviderError::LocalEmergencyCandidateRevoked`] if the
    ///   candidate already lost a prior reconciliation.
    /// * [`Oauth2KeyProviderError::DualControlViolation`] if `confirmer ==
    ///   initiator` (the operator who staged the candidate).
    async fn reconcile_local_emergency_rotation(
        &self,
        state: &ServiceState,
        domain_id: &str,
        rotation_id: &str,
        confirmer: &str,
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

    /// Cross-domain scan of every domain currently holding a `Primary`
    /// signing key with its `Previous` (if any), for the previous-key/JTI
    /// janitor (`crate::oauth2_key::janitor`). There is no cluster-wide
    /// domain listing elsewhere in this provider (every other method is
    /// scoped to a single `domain_id`), so this is the janitor's only entry
    /// point for discovering which domains to sweep.
    async fn list_all_active_keys(
        &self,
        state: &ServiceState,
    ) -> Result<Vec<(String, ActiveKeys)>, Oauth2KeyProviderError>;

    /// Remove `domain_id`'s `Previous` signing key, if present (ADR 0026
    /// §3: one full access-token lifetime after demotion). Idempotent:
    /// returns `Ok(false)`, not an error, if there was nothing to remove.
    async fn retire_previous_key(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<bool, Oauth2KeyProviderError>;

    /// Proactively sweep `domain_id`'s JTI revocation list for entries past
    /// their TTL, for domains with no emergency rotation to otherwise
    /// trigger the lazy sweep in [`Self::confirm_emergency_rotation`].
    async fn prune_expired_jtis(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<(), Oauth2KeyProviderError>;
}
