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
//! # OAuth2 session provider: Backends.
use async_trait::async_trait;

use openstack_keystone_core_types::oauth2_session::*;

use crate::keystone::ServiceState;
use crate::oauth2_session::Oauth2SessionProviderError;

/// OAuth2 browser session Backend trait (ADR 0026 §10 Phase 4).
///
/// Pure CRUD over the three record types -- TTL enforcement, refresh-token
/// rotation state-machine logic (reuse detection, grace period), and
/// authorization-code single-use semantics are the service layer's
/// responsibility, not the backend's.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait Oauth2SessionBackend: Send + Sync {
    /// Persist a new pre-auth browser session.
    async fn create_pre_auth_session(
        &self,
        state: &ServiceState,
        data: PreAuthSessionCreate,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError>;

    /// Fetch a pre-auth session by its `session_id`.
    async fn get_pre_auth_session(
        &self,
        state: &ServiceState,
        session_id: &str,
    ) -> Result<Option<PreAuthSession>, Oauth2SessionProviderError>;

    /// Stamp `user_id`/`auth_time` on a pre-auth session once login
    /// succeeds.
    async fn mark_pre_auth_session_authenticated(
        &self,
        state: &ServiceState,
        session_id: &str,
        user_id: &str,
        auth_time: i64,
        amr: Vec<String>,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError>;

    /// Record that `user_id` passed the password step and `factors` are
    /// still outstanding. `user_id` on the session stays unset.
    async fn begin_pre_auth_session_mfa(
        &self,
        state: &ServiceState,
        session_id: &str,
        user_id: &str,
        factors: Vec<String>,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError>;

    /// Count a second-factor attempt (before the code is verified) and
    /// return the updated session.
    async fn record_pre_auth_session_mfa_attempt(
        &self,
        state: &ServiceState,
        session_id: &str,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError>;

    /// Stamp `consent_granted` on a pre-auth session once the consent step
    /// completes.
    async fn mark_pre_auth_session_consent(
        &self,
        state: &ServiceState,
        session_id: &str,
        granted: bool,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError>;

    /// Delete a pre-auth session (completion or expiry).
    async fn delete_pre_auth_session(
        &self,
        state: &ServiceState,
        session_id: &str,
    ) -> Result<(), Oauth2SessionProviderError>;

    /// Persist a new single-use authorization code.
    async fn create_authorization_code(
        &self,
        state: &ServiceState,
        data: AuthorizationCodeCreate,
    ) -> Result<AuthorizationCode, Oauth2SessionProviderError>;

    /// Atomically fetch and delete an authorization code -- a second call
    /// for the same `code` returns `Ok(None)`, never the same record twice.
    async fn take_authorization_code(
        &self,
        state: &ServiceState,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, Oauth2SessionProviderError>;

    /// Persist a new refresh token record (family root or rotated child).
    async fn create_refresh_token(
        &self,
        state: &ServiceState,
        data: RefreshTokenCreate,
    ) -> Result<RefreshToken, Oauth2SessionProviderError>;

    /// Fetch a refresh token by its `token_id` (hash of the bearer value).
    async fn get_refresh_token(
        &self,
        state: &ServiceState,
        token_id: &str,
    ) -> Result<Option<RefreshToken>, Oauth2SessionProviderError>;

    /// Stamp `spent_at` on a refresh token (rotation).
    async fn mark_refresh_token_spent(
        &self,
        state: &ServiceState,
        token_id: &str,
        spent_at: i64,
    ) -> Result<(), Oauth2SessionProviderError>;

    /// List every token in a rotation family, oldest first.
    async fn list_refresh_token_family(
        &self,
        state: &ServiceState,
        family_id: &str,
    ) -> Result<Vec<RefreshToken>, Oauth2SessionProviderError>;

    /// Revoke a rotation family (breach containment, ADR 0026 §9) by
    /// stamping every member with `revoked_at` (UTC epoch seconds) and
    /// `reason`. Members are
    /// kept as tombstones; already-revoked members keep their original
    /// stamp.
    async fn revoke_refresh_token_family(
        &self,
        state: &ServiceState,
        family_id: &str,
        reason: RefreshTokenRevocationReason,
        revoked_at: i64,
    ) -> Result<(), Oauth2SessionProviderError>;

    /// Persist a new RFC 8628 Device Authorization Grant (ADR 0026 §7.C).
    async fn create_device_code_grant(
        &self,
        state: &ServiceState,
        data: DeviceCodeGrantCreate,
    ) -> Result<DeviceCodeGrant, Oauth2SessionProviderError>;

    /// Fetch a device code grant by the `device_code` the polling device
    /// holds.
    async fn get_device_code_grant(
        &self,
        state: &ServiceState,
        device_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Oauth2SessionProviderError>;

    /// Fetch a device code grant by the short `user_code` entered at the
    /// verification page.
    async fn get_device_code_grant_by_user_code(
        &self,
        state: &ServiceState,
        user_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Oauth2SessionProviderError>;

    /// Stamp `user_id`/`auth_time`/`amr` once the verification page's login
    /// step succeeds.
    async fn mark_device_code_grant_authenticated(
        &self,
        state: &ServiceState,
        device_code: &str,
        user_id: &str,
        auth_time: i64,
        amr: Vec<String>,
    ) -> Result<DeviceCodeGrant, Oauth2SessionProviderError>;

    /// Record that `user_id` passed the password step and `factors` are
    /// still outstanding. `user_id` on the grant stays unset.
    async fn begin_device_code_grant_mfa(
        &self,
        state: &ServiceState,
        device_code: &str,
        user_id: &str,
        factors: Vec<String>,
    ) -> Result<DeviceCodeGrant, Oauth2SessionProviderError>;

    /// Count a second-factor attempt (before the code is verified) and
    /// return the updated grant.
    async fn record_device_code_grant_mfa_attempt(
        &self,
        state: &ServiceState,
        device_code: &str,
    ) -> Result<DeviceCodeGrant, Oauth2SessionProviderError>;

    /// Stamp the terminal `status` once the verification page's consent
    /// step completes.
    async fn mark_device_code_grant_decision(
        &self,
        state: &ServiceState,
        device_code: &str,
        status: DeviceGrantStatus,
    ) -> Result<DeviceCodeGrant, Oauth2SessionProviderError>;

    /// Stamp `last_polled_at`, for RFC 8628 §3.5 poll-interval enforcement.
    async fn mark_device_code_grant_polled(
        &self,
        state: &ServiceState,
        device_code: &str,
        polled_at: i64,
    ) -> Result<(), Oauth2SessionProviderError>;

    /// Atomically fetch and delete a device code grant -- a second call for
    /// the same `device_code` returns `Ok(None)`, never the same record
    /// twice (single-use redemption at `/token`).
    async fn take_device_code_grant(
        &self,
        state: &ServiceState,
        device_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Oauth2SessionProviderError>;

    /// List the refresh token family ids for `user_id` within `domain_id`
    /// -- backs "revoke all my sessions" without a full table scan.
    async fn list_refresh_families_by_user(
        &self,
        state: &ServiceState,
        domain_id: &str,
        user_id: &str,
    ) -> Result<Vec<String>, Oauth2SessionProviderError>;

    /// List the refresh token family ids for `user_id` across every domain
    /// -- backs revocation after the user was deleted, when its domain can
    /// no longer be looked up.
    async fn list_refresh_families_by_user_any_domain(
        &self,
        state: &ServiceState,
        user_id: &str,
    ) -> Result<Vec<String>, Oauth2SessionProviderError>;

    /// List the refresh token family ids issued to `client_id` -- backs
    /// per-client revocation (e.g. a compromised or deregistered client).
    async fn list_refresh_families_by_client(
        &self,
        state: &ServiceState,
        client_id: &str,
    ) -> Result<Vec<String>, Oauth2SessionProviderError>;

    /// List the refresh token family ids within `domain_id` -- backs
    /// domain-wide revocation.
    async fn list_refresh_families_by_domain(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<Vec<String>, Oauth2SessionProviderError>;

    /// Delete a refresh token together with its family and expiry index
    /// entries. Deleting a missing token is a no-op. Used by the session
    /// janitor only.
    async fn delete_refresh_token(
        &self,
        state: &ServiceState,
        token_id: &str,
    ) -> Result<(), Oauth2SessionProviderError>;

    /// List up to `limit` expired records with `expires_at < before`,
    /// ordered oldest first, as `(kind, primary_key)` pairs. When `kind` is
    /// set only records of that kind are returned (filtered before `limit`
    /// is applied). `kind` is one of `"session"`, `"code"`, `"device"`,
    /// `"refresh"`, `"refresh_tombstone"`. Backs a sweeper that reclaims
    /// expired pre-auth sessions, authorization codes, refresh tokens and
    /// device grants without a full table scan.
    async fn list_expired<'k>(
        &self,
        state: &ServiceState,
        kind: Option<&'k str>,
        before: i64,
        limit: usize,
    ) -> Result<Vec<(String, String)>, Oauth2SessionProviderError>;
}
