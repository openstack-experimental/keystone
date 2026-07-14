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

    /// Delete every token in a rotation family (breach containment, ADR
    /// 0026 §9).
    async fn revoke_refresh_token_family(
        &self,
        state: &ServiceState,
        family_id: &str,
    ) -> Result<(), Oauth2SessionProviderError>;
}
