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
//! # OAuth2 browser session provider (ADR 0026 §10 Phase 4, §9)

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use rand::distr::{Alphanumeric, SampleString};
use sha2::{Digest, Sha256};

use openstack_keystone_config::Config;
use openstack_keystone_core_types::oauth2_session::*;

use crate::keystone::ServiceState;
use crate::oauth2_session::Oauth2SessionProviderError;
use crate::oauth2_session::backend::Oauth2SessionBackend;
use crate::oauth2_session::provider_api::{
    DeviceAuthorizationStart, DevicePollOutcome, IssueAuthorizationCodeRequest,
    IssueRefreshTokenRequest, Oauth2SessionApi, RefreshTokenRedemption,
    StartDeviceAuthorizationRequest, StartPreAuthSessionRequest,
};
use crate::plugin_manager::PluginManagerApi;

/// The only backend name registered for the OAuth2 session provider (like
/// `[oauth2]`'s signing key and client providers, ADR 0026 §2 mandates
/// Raft + FjallDB, there is no alternative driver to select between).
const BACKEND_NAME: &str = "raft";

/// ~256 bits of entropy over the 62-character alphanumeric alphabet, for
/// session IDs, authorization codes, refresh token bearer values, and the
/// CSRF-derivation secret. Matches the entropy bar `[oauth2] client_secret`
/// generation already uses (`crate::oauth2_client::crypto`), and the RFC
/// 8628 §3.5 `device_code` entropy requirement this ADR cites for the same
/// reasoning (brute-force resistance at a network-facing redemption
/// endpoint).
const ENTROPY_LEN: usize = 43;

fn generate_entropy() -> String {
    Alphanumeric.sample_string(&mut rand::rng(), ENTROPY_LEN)
}

/// Unambiguous charset for RFC 8628 `user_code` generation (ADR 0026 §7.C):
/// excludes vowels (avoids accidentally spelling words) and visually
/// confusable characters (`0`/`O`, `1`/`I`). 8 symbols formatted as
/// `XXXX-XXXX`, matching the ADR's stated shape.
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ23456789";
const USER_CODE_LEN: usize = 8;

fn generate_user_code() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    let code: String = (0..USER_CODE_LEN)
        .map(|_| USER_CODE_ALPHABET[rng.random_range(0..USER_CODE_ALPHABET.len())] as char)
        .collect();
    format!("{}-{}", &code[0..4], &code[4..8])
}

fn hash_bearer(bearer: &str) -> String {
    let digest = Sha256::digest(bearer.as_bytes());
    data_encoding::HEXLOWER.encode(&digest)
}

fn now() -> i64 {
    Utc::now().timestamp()
}

/// OAuth2 browser session Provider.
pub struct Oauth2SessionService {
    /// Backend driver.
    backend_driver: Arc<dyn Oauth2SessionBackend>,
    /// `[oauth2]` config, for session/code/token lifetimes and the refresh
    /// reuse grace period.
    oauth2_config: openstack_keystone_config::Oauth2Provider,
}

impl Oauth2SessionService {
    /// Create a new `Oauth2SessionService`.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, Oauth2SessionProviderError> {
        let backend_driver = plugin_manager
            .get_oauth2_session_backend(BACKEND_NAME)?
            .clone();
        Ok(Self {
            backend_driver,
            oauth2_config: config.oauth2.clone(),
        })
    }

    /// Tombstone each of `family_ids` with `reason` and return them.
    async fn revoke_families(
        &self,
        state: &ServiceState,
        family_ids: Vec<String>,
        reason: RefreshTokenRevocationReason,
    ) -> Result<Vec<String>, Oauth2SessionProviderError> {
        let revoked_at = now();
        for family_id in &family_ids {
            self.backend_driver
                .revoke_refresh_token_family(state, family_id, reason, revoked_at)
                .await?;
        }
        Ok(family_ids)
    }

    /// Delete every live pre-auth session and device code grant matching
    /// the predicates and return how many were deleted. Neither record kind
    /// has an owner index, so the candidates come from the expiry index:
    /// both are short-lived, which keeps the scan bounded.
    async fn purge_pending_grants(
        &self,
        state: &ServiceState,
        session_matches: impl Fn(&PreAuthSession) -> bool + Send + Sync,
        grant_matches: impl Fn(&DeviceCodeGrant) -> bool + Send + Sync,
    ) -> Result<usize, Oauth2SessionProviderError> {
        let mut purged = 0;
        for (_, session_id) in self
            .backend_driver
            .list_expired(state, Some("session"), i64::MAX, usize::MAX)
            .await?
        {
            if let Some(session) = self
                .backend_driver
                .get_pre_auth_session(state, &session_id)
                .await?
                && session_matches(&session)
            {
                self.backend_driver
                    .delete_pre_auth_session(state, &session_id)
                    .await?;
                purged += 1;
            }
        }
        for (_, device_code) in self
            .backend_driver
            .list_expired(state, Some("device"), i64::MAX, usize::MAX)
            .await?
        {
            if let Some(grant) = self
                .backend_driver
                .get_device_code_grant(state, &device_code)
                .await?
                && grant_matches(&grant)
            {
                self.backend_driver
                    .take_device_code_grant(state, &device_code)
                    .await?;
                purged += 1;
            }
        }
        Ok(purged)
    }
}

#[async_trait]
impl Oauth2SessionApi for Oauth2SessionService {
    #[tracing::instrument(
        name = "provider.oauth2_session.start_pre_auth_session",
        level = "debug",
        skip_all
    )]
    async fn start_pre_auth_session(
        &self,
        state: &ServiceState,
        req: StartPreAuthSessionRequest,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError> {
        let created_at = now();
        let expires_at =
            created_at + i64::from(self.oauth2_config.pre_auth_session_lifetime_minutes) * 60;
        self.backend_driver
            .create_pre_auth_session(
                state,
                PreAuthSessionCreate {
                    session_id: generate_entropy(),
                    domain_id: req.domain_id,
                    client_id: req.client_id,
                    redirect_uri: req.redirect_uri,
                    scope: req.scope,
                    state: req.state,
                    code_challenge: req.code_challenge,
                    code_challenge_method: req.code_challenge_method,
                    nonce: req.nonce,
                    server_side_session_secret: generate_entropy(),
                    created_at,
                    expires_at,
                },
            )
            .await
    }

    #[tracing::instrument(name = "provider.oauth2_session.get_pre_auth_session", level = "debug", skip_all, fields(session_id = %session_id))]
    async fn get_pre_auth_session(
        &self,
        state: &ServiceState,
        session_id: &str,
    ) -> Result<Option<PreAuthSession>, Oauth2SessionProviderError> {
        let Some(session) = self
            .backend_driver
            .get_pre_auth_session(state, session_id)
            .await?
        else {
            return Ok(None);
        };
        if session.expires_at < now() {
            // Best-effort opportunistic cleanup on expired read (mirrors
            // ADR 0020 §4.A's lazy-sweep posture); failure to delete does
            // not affect the caller-visible result.
            let _ = self
                .backend_driver
                .delete_pre_auth_session(state, session_id)
                .await;
            return Ok(None);
        }
        Ok(Some(session))
    }

    #[tracing::instrument(name = "provider.oauth2_session.mark_authenticated", level = "debug", skip_all, fields(session_id = %session_id, user_id = %user_id))]
    async fn mark_authenticated(
        &self,
        state: &ServiceState,
        session_id: &str,
        user_id: &str,
        auth_time: i64,
        amr: Vec<String>,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError> {
        self.backend_driver
            .mark_pre_auth_session_authenticated(state, session_id, user_id, auth_time, amr)
            .await
    }

    #[tracing::instrument(name = "provider.oauth2_session.begin_mfa", level = "debug", skip_all, fields(session_id = %session_id))]
    async fn begin_mfa(
        &self,
        state: &ServiceState,
        session_id: &str,
        user_id: &str,
        factors: Vec<String>,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError> {
        self.backend_driver
            .begin_pre_auth_session_mfa(state, session_id, user_id, factors)
            .await
    }

    #[tracing::instrument(name = "provider.oauth2_session.record_mfa_failure", level = "debug", skip_all, fields(session_id = %session_id))]
    async fn record_mfa_failure(
        &self,
        state: &ServiceState,
        session_id: &str,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError> {
        self.backend_driver
            .record_pre_auth_session_mfa_failure(state, session_id)
            .await
    }

    #[tracing::instrument(name = "provider.oauth2_session.mark_consent", level = "debug", skip_all, fields(session_id = %session_id))]
    async fn mark_consent(
        &self,
        state: &ServiceState,
        session_id: &str,
        granted: bool,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError> {
        self.backend_driver
            .mark_pre_auth_session_consent(state, session_id, granted)
            .await
    }

    #[tracing::instrument(name = "provider.oauth2_session.complete_pre_auth_session", level = "debug", skip_all, fields(session_id = %session_id))]
    async fn complete_pre_auth_session(
        &self,
        state: &ServiceState,
        session_id: &str,
    ) -> Result<(), Oauth2SessionProviderError> {
        self.backend_driver
            .delete_pre_auth_session(state, session_id)
            .await
    }

    #[tracing::instrument(
        name = "provider.oauth2_session.issue_authorization_code",
        level = "debug",
        skip_all
    )]
    async fn issue_authorization_code(
        &self,
        state: &ServiceState,
        req: IssueAuthorizationCodeRequest,
    ) -> Result<String, Oauth2SessionProviderError> {
        let created_at = now();
        let expires_at =
            created_at + i64::from(self.oauth2_config.authorization_code_lifetime_seconds);
        let code = generate_entropy();
        self.backend_driver
            .create_authorization_code(
                state,
                AuthorizationCodeCreate {
                    code: code.clone(),
                    domain_id: req.domain_id,
                    client_id: req.client_id,
                    user_id: req.user_id,
                    redirect_uri: req.redirect_uri,
                    code_challenge: req.code_challenge,
                    code_challenge_method: req.code_challenge_method,
                    scope: req.scope,
                    nonce: req.nonce,
                    auth_time: req.auth_time,
                    amr: req.amr,
                    created_at,
                    expires_at,
                },
            )
            .await?;
        Ok(code)
    }

    #[tracing::instrument(
        name = "provider.oauth2_session.redeem_authorization_code",
        level = "debug",
        skip_all
    )]
    async fn redeem_authorization_code(
        &self,
        state: &ServiceState,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, Oauth2SessionProviderError> {
        // `take_authorization_code` is atomically fetch-and-delete, so a
        // concurrent or repeated redemption of the same code can never
        // observe `Some` twice, regardless of the expiry check below.
        let Some(record) = self
            .backend_driver
            .take_authorization_code(state, code)
            .await?
        else {
            return Ok(None);
        };
        if record.expires_at < now() {
            return Ok(None);
        }
        Ok(Some(record))
    }

    #[tracing::instrument(
        name = "provider.oauth2_session.issue_refresh_token",
        level = "debug",
        skip_all
    )]
    async fn issue_refresh_token(
        &self,
        state: &ServiceState,
        req: IssueRefreshTokenRequest,
    ) -> Result<(RefreshToken, String), Oauth2SessionProviderError> {
        let bearer = generate_entropy();
        let issued_at = now();
        let expires_at =
            issued_at + i64::from(self.oauth2_config.refresh_token_lifetime_days) * 86400;
        // Absolute family cap: fixed here at root issuance and copied
        // unchanged to every rotated child.
        let family_expires_at =
            issued_at + i64::from(self.oauth2_config.refresh_token_absolute_lifetime_days) * 86400;
        let record = self
            .backend_driver
            .create_refresh_token(
                state,
                RefreshTokenCreate {
                    token_id: hash_bearer(&bearer),
                    family_id: uuid::Uuid::new_v4().to_string(),
                    parent_token_id: None,
                    domain_id: req.domain_id,
                    client_id: req.client_id,
                    user_id: req.user_id,
                    scope: req.scope,
                    amr: req.amr,
                    issued_at,
                    expires_at: expires_at.min(family_expires_at),
                    family_expires_at,
                },
            )
            .await?;
        Ok((record, bearer))
    }

    #[tracing::instrument(name = "provider.oauth2_session.redeem_refresh_token", level = "debug", skip_all, fields(client_id = %client_id, domain_id = %domain_id))]
    async fn redeem_refresh_token(
        &self,
        state: &ServiceState,
        presented_bearer: &str,
        client_id: &str,
        domain_id: &str,
    ) -> Result<RefreshTokenRedemption, Oauth2SessionProviderError> {
        let token_id = hash_bearer(presented_bearer);
        let Some(record) = self
            .backend_driver
            .get_refresh_token(state, &token_id)
            .await?
        else {
            return Ok(RefreshTokenRedemption::Invalid);
        };
        // Ownership first, before any write or reuse accounting: a foreign
        // presenter must not spend the owner's token or trip the breach
        // cascade.
        if record.client_id != client_id || record.domain_id != domain_id {
            return Ok(RefreshTokenRedemption::Invalid);
        }
        let now = now();
        if record.expires_at < now {
            return Ok(RefreshTokenRedemption::Invalid);
        }
        // Absolute family lifetime: checked before any write so an
        // over-age family can never mint a child. `0` is a legacy record
        // from before the cap existed ("no cap").
        if record.family_expires_at != 0 && now >= record.family_expires_at {
            return Ok(RefreshTokenRedemption::Invalid);
        }
        // Tombstoned (revoked) family: checked before the `spent_at`
        // branch so presenting a token from an already-revoked family does
        // not re-trigger the breach cascade or a second critical audit
        // event.
        if record.revoked_at.is_some() {
            return Ok(RefreshTokenRedemption::Invalid);
        }

        match record.spent_at {
            None => {
                // `NotFound` here means the family was revoked between the
                // read above and this write (the backend refuses to
                // overwrite a tombstone).
                match self
                    .backend_driver
                    .mark_refresh_token_spent(state, &token_id, now)
                    .await
                {
                    Ok(()) => {}
                    Err(Oauth2SessionProviderError::NotFound(_)) => {
                        return Ok(RefreshTokenRedemption::Invalid);
                    }
                    Err(e) => return Err(e),
                }
                let bearer = generate_entropy();
                // Legacy record (written before the absolute cap existed,
                // `family_expires_at == 0`): backfill the cap on its first
                // post-upgrade rotation, measured from now, so such a
                // family cannot stay uncapped forever.
                let family_expires_at = if record.family_expires_at == 0 {
                    now + i64::from(self.oauth2_config.refresh_token_absolute_lifetime_days) * 86400
                } else {
                    record.family_expires_at
                };
                // Rotation resets the idle window but never extends the
                // family beyond its absolute cap.
                let expires_at = (now
                    + i64::from(self.oauth2_config.refresh_token_lifetime_days) * 86400)
                    .min(family_expires_at);
                let child = self
                    .backend_driver
                    .create_refresh_token(
                        state,
                        RefreshTokenCreate {
                            token_id: hash_bearer(&bearer),
                            family_id: record.family_id.clone(),
                            parent_token_id: Some(token_id),
                            domain_id: record.domain_id.clone(),
                            client_id: record.client_id.clone(),
                            user_id: record.user_id.clone(),
                            scope: record.scope.clone(),
                            amr: record.amr.clone(),
                            issued_at: now,
                            expires_at,
                            family_expires_at,
                        },
                    )
                    .await?;
                // Close the race with a concurrent family revocation: if
                // the parent got tombstoned while the child was being
                // minted, the child is not stamped. Never hand out its
                // bearer, so the stray record is unusable.
                let parent_revoked = self
                    .backend_driver
                    .get_refresh_token(state, &record.token_id)
                    .await?
                    .is_none_or(|p| p.revoked_at.is_some());
                if parent_revoked {
                    return Ok(RefreshTokenRedemption::Invalid);
                }
                Ok(RefreshTokenRedemption::Rotated {
                    record: Box::new(child),
                    bearer,
                })
            }
            Some(spent_at) => {
                let grace = i64::from(self.oauth2_config.refresh_token_reuse_grace_minutes) * 60;
                // Strict `<`, not `<=`: timestamps are second-granularity,
                // so `grace = 0` ("disable the grace period entirely", per
                // ADR 0026 §9) must mean same-second reuse still breaches --
                // `now - spent_at <= 0` would tolerate it whenever both
                // calls land in the same wall-clock second.
                if now - spent_at < grace {
                    // Tolerated benign reuse (multi-device race, ADR 0026
                    // §9): no family-wide cascade, but this specific
                    // redemption still does not succeed a second time --
                    // the caller must use the token it already received
                    // from the original rotation.
                    Ok(RefreshTokenRedemption::Invalid)
                } else {
                    self.backend_driver
                        .revoke_refresh_token_family(
                            state,
                            &record.family_id,
                            RefreshTokenRevocationReason::ReuseDetected,
                            now,
                        )
                        .await?;
                    Ok(RefreshTokenRedemption::ReuseDetected {
                        family_id: record.family_id,
                        reason: RefreshTokenRevocationReason::ReuseDetected,
                    })
                }
            }
        }
    }

    #[tracing::instrument(
        name = "provider.oauth2_session.peek_refresh_token",
        level = "debug",
        skip_all
    )]
    async fn peek_refresh_token(
        &self,
        state: &ServiceState,
        presented_bearer: &str,
    ) -> Result<Option<RefreshToken>, Oauth2SessionProviderError> {
        self.backend_driver
            .get_refresh_token(state, &hash_bearer(presented_bearer))
            .await
    }

    #[tracing::instrument(name = "provider.oauth2_session.revoke_refresh_token_family", level = "debug", skip_all, fields(family_id = %family_id))]
    async fn revoke_refresh_token_family(
        &self,
        state: &ServiceState,
        family_id: &str,
        reason: RefreshTokenRevocationReason,
    ) -> Result<(), Oauth2SessionProviderError> {
        self.backend_driver
            .revoke_refresh_token_family(state, family_id, reason, now())
            .await
    }

    #[tracing::instrument(name = "provider.oauth2_session.revoke_refresh_token_families_by_client", level = "debug", skip_all, fields(client_id = %client_id))]
    async fn revoke_refresh_token_families_by_client(
        &self,
        state: &ServiceState,
        client_id: &str,
        reason: RefreshTokenRevocationReason,
    ) -> Result<usize, Oauth2SessionProviderError> {
        let family_ids = self
            .backend_driver
            .list_refresh_families_by_client(state, client_id)
            .await?;
        let revoked_at = now();
        for family_id in &family_ids {
            self.backend_driver
                .revoke_refresh_token_family(state, family_id, reason, revoked_at)
                .await?;
        }
        Ok(family_ids.len())
    }

    #[tracing::instrument(name = "provider.oauth2_session.revoke_refresh_token_families_by_user", level = "debug", skip_all, fields(user_id = %user_id))]
    async fn revoke_refresh_token_families_by_user<'a>(
        &self,
        state: &ServiceState,
        domain_id: Option<&'a str>,
        user_id: &str,
        reason: RefreshTokenRevocationReason,
    ) -> Result<Vec<String>, Oauth2SessionProviderError> {
        let family_ids = match domain_id {
            Some(domain_id) => {
                self.backend_driver
                    .list_refresh_families_by_user(state, domain_id, user_id)
                    .await?
            }
            None => {
                self.backend_driver
                    .list_refresh_families_by_user_any_domain(state, user_id)
                    .await?
            }
        };
        self.revoke_families(state, family_ids, reason).await
    }

    #[tracing::instrument(name = "provider.oauth2_session.revoke_refresh_token_families_by_domain", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn revoke_refresh_token_families_by_domain(
        &self,
        state: &ServiceState,
        domain_id: &str,
        reason: RefreshTokenRevocationReason,
    ) -> Result<Vec<String>, Oauth2SessionProviderError> {
        let family_ids = self
            .backend_driver
            .list_refresh_families_by_domain(state, domain_id)
            .await?;
        self.revoke_families(state, family_ids, reason).await
    }

    #[tracing::instrument(name = "provider.oauth2_session.purge_pending_grants_by_domain", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn purge_pending_grants_by_domain(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<usize, Oauth2SessionProviderError> {
        self.purge_pending_grants(
            state,
            |s| s.domain_id == domain_id,
            |g| g.domain_id == domain_id,
        )
        .await
    }

    #[tracing::instrument(name = "provider.oauth2_session.purge_pending_grants_by_user", level = "debug", skip_all, fields(user_id = %user_id))]
    async fn purge_pending_grants_by_user(
        &self,
        state: &ServiceState,
        user_id: &str,
    ) -> Result<usize, Oauth2SessionProviderError> {
        self.purge_pending_grants(
            state,
            |s| s.user_id.as_deref() == Some(user_id),
            |g| g.user_id.as_deref() == Some(user_id),
        )
        .await
    }

    #[tracing::instrument(
        name = "provider.oauth2_session.start_device_authorization",
        level = "debug",
        skip_all
    )]
    async fn start_device_authorization(
        &self,
        state: &ServiceState,
        req: StartDeviceAuthorizationRequest,
    ) -> Result<DeviceAuthorizationStart, Oauth2SessionProviderError> {
        let created_at = now();
        let expires_at =
            created_at + i64::from(self.oauth2_config.device_code_lifetime_minutes) * 60;
        let record = self
            .backend_driver
            .create_device_code_grant(
                state,
                DeviceCodeGrantCreate {
                    device_code: generate_entropy(),
                    user_code: generate_user_code(),
                    domain_id: req.domain_id,
                    client_id: req.client_id,
                    scope: req.scope,
                    server_side_session_secret: generate_entropy(),
                    created_at,
                    expires_at,
                },
            )
            .await?;
        Ok(DeviceAuthorizationStart {
            device_code: record.device_code,
            user_code: record.user_code,
            expires_at: record.expires_at,
            interval: self.oauth2_config.device_code_poll_interval_seconds,
        })
    }

    #[tracing::instrument(
        name = "provider.oauth2_session.get_device_code_grant_by_user_code",
        level = "debug",
        skip_all
    )]
    async fn get_device_code_grant_by_user_code(
        &self,
        state: &ServiceState,
        user_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Oauth2SessionProviderError> {
        let Some(grant) = self
            .backend_driver
            .get_device_code_grant_by_user_code(state, user_code)
            .await?
        else {
            return Ok(None);
        };
        if grant.expires_at < now() {
            return Ok(None);
        }
        Ok(Some(grant))
    }

    #[tracing::instrument(
        name = "provider.oauth2_session.get_device_code_grant",
        level = "debug",
        skip_all
    )]
    async fn get_device_code_grant(
        &self,
        state: &ServiceState,
        device_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Oauth2SessionProviderError> {
        let Some(grant) = self
            .backend_driver
            .get_device_code_grant(state, device_code)
            .await?
        else {
            return Ok(None);
        };
        if grant.expires_at < now() {
            return Ok(None);
        }
        Ok(Some(grant))
    }

    #[tracing::instrument(name = "provider.oauth2_session.mark_device_authenticated", level = "debug", skip_all, fields(user_id = %user_id))]
    async fn mark_device_authenticated(
        &self,
        state: &ServiceState,
        device_code: &str,
        user_id: &str,
        auth_time: i64,
        amr: Vec<String>,
    ) -> Result<DeviceCodeGrant, Oauth2SessionProviderError> {
        self.backend_driver
            .mark_device_code_grant_authenticated(state, device_code, user_id, auth_time, amr)
            .await
    }

    #[tracing::instrument(
        name = "provider.oauth2_session.begin_device_mfa",
        level = "debug",
        skip_all
    )]
    async fn begin_device_mfa(
        &self,
        state: &ServiceState,
        device_code: &str,
        user_id: &str,
        factors: Vec<String>,
    ) -> Result<DeviceCodeGrant, Oauth2SessionProviderError> {
        self.backend_driver
            .begin_device_code_grant_mfa(state, device_code, user_id, factors)
            .await
    }

    #[tracing::instrument(
        name = "provider.oauth2_session.record_device_mfa_failure",
        level = "debug",
        skip_all
    )]
    async fn record_device_mfa_failure(
        &self,
        state: &ServiceState,
        device_code: &str,
    ) -> Result<DeviceCodeGrant, Oauth2SessionProviderError> {
        self.backend_driver
            .record_device_code_grant_mfa_failure(state, device_code)
            .await
    }

    #[tracing::instrument(
        name = "provider.oauth2_session.mark_device_decision",
        level = "debug",
        skip_all
    )]
    async fn mark_device_decision(
        &self,
        state: &ServiceState,
        device_code: &str,
        granted: bool,
    ) -> Result<DeviceCodeGrant, Oauth2SessionProviderError> {
        let status = if granted {
            DeviceGrantStatus::Authorized
        } else {
            DeviceGrantStatus::Denied
        };
        self.backend_driver
            .mark_device_code_grant_decision(state, device_code, status)
            .await
    }

    #[tracing::instrument(name = "provider.oauth2_session.poll_device_code_grant", level = "debug", skip_all, fields(domain_id = %domain_id, client_id = %client_id))]
    async fn poll_device_code_grant(
        &self,
        state: &ServiceState,
        device_code: &str,
        domain_id: &str,
        client_id: &str,
    ) -> Result<DevicePollOutcome, Oauth2SessionProviderError> {
        let Some(record) = self
            .backend_driver
            .get_device_code_grant(state, device_code)
            .await?
        else {
            return Ok(DevicePollOutcome::InvalidGrant);
        };
        // Checked before anything is stamped or consumed, so a poll through
        // the wrong domain's endpoint cannot burn the grant.
        if record.client_id != client_id || record.domain_id != domain_id {
            return Ok(DevicePollOutcome::InvalidGrant);
        }

        let now = now();
        if record.expires_at < now {
            return Ok(DevicePollOutcome::Expired);
        }

        let interval_secs = i64::from(self.oauth2_config.device_code_poll_interval_seconds);
        if let Some(last_polled_at) = record.last_polled_at
            && now - last_polled_at < interval_secs
        {
            return Ok(DevicePollOutcome::SlowDown);
        }

        match record.status {
            DeviceGrantStatus::Pending => {
                self.backend_driver
                    .mark_device_code_grant_polled(state, device_code, now)
                    .await?;
                Ok(DevicePollOutcome::Pending)
            }
            DeviceGrantStatus::Denied => Ok(DevicePollOutcome::Denied),
            DeviceGrantStatus::Authorized => {
                match self
                    .backend_driver
                    .take_device_code_grant(state, device_code)
                    .await?
                {
                    // Concurrent poll already redeemed it between the read
                    // above and this call; treat the same as unknown.
                    None => Ok(DevicePollOutcome::InvalidGrant),
                    Some(taken) => Ok(DevicePollOutcome::Authorized(Box::new(taken))),
                }
            }
        }
    }

    #[tracing::instrument(name = "provider.oauth2_session.list_expired", level = "debug", skip_all, fields(kind = %kind))]
    async fn list_expired(
        &self,
        state: &ServiceState,
        kind: &str,
        before: i64,
        limit: usize,
    ) -> Result<Vec<(String, String)>, Oauth2SessionProviderError> {
        self.backend_driver
            .list_expired(state, Some(kind), before, limit)
            .await
    }

    #[tracing::instrument(name = "provider.oauth2_session.purge_expired", level = "debug", skip_all, fields(kind = %kind))]
    async fn purge_expired(
        &self,
        state: &ServiceState,
        kind: &str,
        primary_key: &str,
    ) -> Result<(), Oauth2SessionProviderError> {
        match kind {
            "session" => {
                self.backend_driver
                    .delete_pre_auth_session(state, primary_key)
                    .await
            }
            // `take_*` fetch-and-delete, which also drops the expiry index
            // entry; the returned record is discarded.
            "code" => self
                .backend_driver
                .take_authorization_code(state, primary_key)
                .await
                .map(|_| ()),
            "device" => self
                .backend_driver
                .take_device_code_grant(state, primary_key)
                .await
                .map(|_| ()),
            "refresh" | "refresh_tombstone" => {
                self.backend_driver
                    .delete_refresh_token(state, primary_key)
                    .await
            }
            other => Err(Oauth2SessionProviderError::InvalidRecordKind(
                other.to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2_session::backend::MockOauth2SessionBackend;
    use crate::tests::get_mocked_state;

    fn service_with(mock: MockOauth2SessionBackend) -> Oauth2SessionService {
        Oauth2SessionService {
            backend_driver: Arc::new(mock),
            oauth2_config: openstack_keystone_config::Oauth2Provider {
                pre_auth_session_lifetime_minutes: 10,
                authorization_code_lifetime_seconds: 60,
                refresh_token_lifetime_days: 30,
                refresh_token_reuse_grace_minutes: 10,
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn test_revoke_families_by_client_revokes_each_family() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_list_refresh_families_by_client()
            .withf(|_, client_id| client_id == "client-1")
            .returning(|_, _| Ok(vec!["f1".to_string(), "f2".to_string()]));
        mock.expect_revoke_refresh_token_family()
            .withf(|_, _, reason, _| *reason == RefreshTokenRevocationReason::ClientRevoked)
            .times(2)
            .returning(|_, _, _, _| Ok(()));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let revoked = service
            .revoke_refresh_token_families_by_client(
                &state,
                "client-1",
                RefreshTokenRevocationReason::ClientRevoked,
            )
            .await
            .unwrap();
        assert_eq!(revoked, 2);
    }

    #[tokio::test]
    async fn test_revoke_families_by_user_in_domain_revokes_each_family() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_list_refresh_families_by_user()
            .withf(|_, domain_id, user_id| domain_id == "domain-1" && user_id == "user-1")
            .returning(|_, _, _| Ok(vec!["f1".to_string(), "f2".to_string()]));
        mock.expect_list_refresh_families_by_user_any_domain()
            .never();
        mock.expect_revoke_refresh_token_family()
            .withf(|_, _, reason, _| *reason == RefreshTokenRevocationReason::UserDisabled)
            .times(2)
            .returning(|_, _, _, _| Ok(()));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let revoked = service
            .revoke_refresh_token_families_by_user(
                &state,
                Some("domain-1"),
                "user-1",
                RefreshTokenRevocationReason::UserDisabled,
            )
            .await
            .unwrap();
        assert_eq!(revoked, vec!["f1".to_string(), "f2".to_string()]);
    }

    #[tokio::test]
    async fn test_revoke_families_by_user_without_domain_searches_every_domain() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_list_refresh_families_by_user().never();
        mock.expect_list_refresh_families_by_user_any_domain()
            .withf(|_, user_id| user_id == "user-1")
            .returning(|_, _| Ok(vec!["f1".to_string()]));
        mock.expect_revoke_refresh_token_family()
            .withf(|_, family_id, reason, _| {
                family_id == "f1" && *reason == RefreshTokenRevocationReason::UserDeleted
            })
            .times(1)
            .returning(|_, _, _, _| Ok(()));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let revoked = service
            .revoke_refresh_token_families_by_user(
                &state,
                None,
                "user-1",
                RefreshTokenRevocationReason::UserDeleted,
            )
            .await
            .unwrap();
        assert_eq!(revoked, vec!["f1".to_string()]);
    }

    #[tokio::test]
    async fn test_revoke_families_by_domain_revokes_each_family() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_list_refresh_families_by_domain()
            .withf(|_, domain_id| domain_id == "domain-1")
            .returning(|_, _| Ok(vec!["f1".to_string(), "f2".to_string()]));
        mock.expect_revoke_refresh_token_family()
            .withf(|_, _, reason, _| *reason == RefreshTokenRevocationReason::DomainDeleted)
            .times(2)
            .returning(|_, _, _, _| Ok(()));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let revoked = service
            .revoke_refresh_token_families_by_domain(
                &state,
                "domain-1",
                RefreshTokenRevocationReason::DomainDeleted,
            )
            .await
            .unwrap();
        assert_eq!(revoked.len(), 2);
    }

    fn sample_pre_auth_session(
        session_id: &str,
        domain_id: &str,
        user_id: Option<&str>,
    ) -> PreAuthSession {
        PreAuthSession {
            session_id: session_id.to_string(),
            domain_id: domain_id.to_string(),
            client_id: "client-1".to_string(),
            redirect_uri: "https://rp.example/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: "state".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: "S256".to_string(),
            nonce: None,
            server_side_session_secret: "secret".to_string(),
            user_id: user_id.map(str::to_string),
            auth_time: None,
            consent_granted: None,
            created_at: now(),
            expires_at: now() + 600,
            amr: vec![],
            pending_user_id: None,
            pending_factors: vec![],
            mfa_attempts: 0,
        }
    }

    /// Backend with sessions `s1` (domain-1, user-1) and `s2` (domain-2,
    /// unauthenticated) and device grants `d1` (domain-1, unauthenticated)
    /// and `d2` (domain-2, user-1).
    fn backend_with_pending_grants() -> MockOauth2SessionBackend {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_list_expired()
            .withf(|_, kind, before, _| *kind == Some("session") && *before == i64::MAX)
            .returning(|_, _, _, _| {
                Ok(vec![
                    ("session".to_string(), "s1".to_string()),
                    ("session".to_string(), "s2".to_string()),
                ])
            });
        mock.expect_list_expired()
            .withf(|_, kind, before, _| *kind == Some("device") && *before == i64::MAX)
            .returning(|_, _, _, _| {
                Ok(vec![
                    ("device".to_string(), "d1".to_string()),
                    ("device".to_string(), "d2".to_string()),
                ])
            });
        mock.expect_get_pre_auth_session()
            .returning(|_, session_id| {
                Ok(Some(match session_id {
                    "s1" => sample_pre_auth_session("s1", "domain-1", Some("user-1")),
                    _ => sample_pre_auth_session(session_id, "domain-2", None),
                }))
            });
        mock.expect_get_device_code_grant()
            .returning(|_, device_code| {
                let mut grant = sample_device_grant(DeviceGrantStatus::Pending, None);
                grant.device_code = device_code.to_string();
                if device_code == "d2" {
                    grant.domain_id = "domain-2".to_string();
                    grant.user_id = Some("user-1".to_string());
                }
                Ok(Some(grant))
            });
        mock
    }

    #[tokio::test]
    async fn test_purge_pending_grants_by_domain_deletes_only_that_domain() {
        let mut mock = backend_with_pending_grants();
        mock.expect_delete_pre_auth_session()
            .withf(|_, session_id| session_id == "s1")
            .times(1)
            .returning(|_, _| Ok(()));
        mock.expect_take_device_code_grant()
            .withf(|_, device_code| device_code == "d1")
            .times(1)
            .returning(|_, _| Ok(None));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let purged = service
            .purge_pending_grants_by_domain(&state, "domain-1")
            .await
            .unwrap();
        assert_eq!(purged, 2);
    }

    #[tokio::test]
    async fn test_purge_pending_grants_by_user_deletes_only_that_user() {
        let mut mock = backend_with_pending_grants();
        mock.expect_delete_pre_auth_session()
            .withf(|_, session_id| session_id == "s1")
            .times(1)
            .returning(|_, _| Ok(()));
        mock.expect_take_device_code_grant()
            .withf(|_, device_code| device_code == "d2")
            .times(1)
            .returning(|_, _| Ok(None));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let purged = service
            .purge_pending_grants_by_user(&state, "user-1")
            .await
            .unwrap();
        assert_eq!(purged, 2);
    }

    fn sample_refresh_token(spent_at: Option<i64>) -> RefreshToken {
        RefreshToken {
            token_id: "irrelevant".to_string(),
            family_id: "family-1".to_string(),
            parent_token_id: None,
            domain_id: "domain-1".to_string(),
            client_id: "client-1".to_string(),
            user_id: "user-1".to_string(),
            scope: vec!["openid".to_string()],
            issued_at: now() - 100,
            spent_at,
            revoked_at: None,
            revocation_reason: None,
            expires_at: now() + 1_000_000,
            family_expires_at: now() + 10_000_000,
            amr: vec![],
        }
    }

    #[tokio::test]
    async fn test_get_pre_auth_session_returns_none_when_expired() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_pre_auth_session().returning(|_, _| {
            Ok(Some(PreAuthSession {
                session_id: "s1".to_string(),
                domain_id: "d1".to_string(),
                client_id: "c1".to_string(),
                redirect_uri: "https://rp.example/cb".to_string(),
                scope: vec![],
                state: "st".to_string(),
                code_challenge: "cc".to_string(),
                code_challenge_method: "S256".to_string(),
                nonce: None,
                server_side_session_secret: "secret".to_string(),
                user_id: None,
                auth_time: None,
                consent_granted: None,
                created_at: now() - 1000,
                expires_at: now() - 1,
                amr: vec![],
                pending_user_id: None,
                pending_factors: vec![],
                mfa_attempts: 0,
            }))
        });
        mock.expect_delete_pre_auth_session()
            .returning(|_, _| Ok(()));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service.get_pre_auth_session(&state, "s1").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_redeem_authorization_code_expired_returns_none() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_take_authorization_code().returning(|_, _| {
            Ok(Some(AuthorizationCode {
                code: "code-1".to_string(),
                domain_id: "d1".to_string(),
                client_id: "c1".to_string(),
                user_id: "u1".to_string(),
                redirect_uri: "https://rp.example/cb".to_string(),
                code_challenge: "cc".to_string(),
                code_challenge_method: "S256".to_string(),
                scope: vec![],
                nonce: None,
                auth_time: now(),
                amr: vec!["pwd".to_string()],
                created_at: now() - 1000,
                expires_at: now() - 1,
            }))
        });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_authorization_code(&state, "code-1")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_redeem_refresh_token_normal_rotation() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_refresh_token()
            .returning(|_, _| Ok(Some(sample_refresh_token(None))));
        mock.expect_mark_refresh_token_spent()
            .returning(|_, _, _| Ok(()));
        mock.expect_create_refresh_token().returning(|_, data| {
            Ok(RefreshToken {
                token_id: data.token_id,
                family_id: data.family_id,
                parent_token_id: data.parent_token_id,
                domain_id: data.domain_id,
                client_id: data.client_id,
                user_id: data.user_id,
                scope: data.scope,
                issued_at: data.issued_at,
                spent_at: None,
                expires_at: data.expires_at,
                family_expires_at: data.family_expires_at,
                revoked_at: None,
                revocation_reason: None,
                amr: vec![],
            })
        });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "presented-bearer", "client-1", "domain-1")
            .await
            .unwrap();
        assert!(matches!(result, RefreshTokenRedemption::Rotated { .. }));
    }

    #[tokio::test]
    async fn test_redeem_refresh_token_family_lifetime_reached_is_invalid_no_writes() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_refresh_token().returning(|_, _| {
            let mut record = sample_refresh_token(None);
            record.family_expires_at = now() - 1;
            Ok(Some(record))
        });
        // `mark_refresh_token_spent` / `create_refresh_token` deliberately
        // not configured: mockall panics if a write is attempted.
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "presented-bearer", "client-1", "domain-1")
            .await
            .unwrap();
        assert!(matches!(result, RefreshTokenRedemption::Invalid));
    }

    #[tokio::test]
    async fn test_redeem_refresh_token_child_inherits_and_is_capped_by_family_expiry() {
        let family_expires_at = now() + 3600; // far sooner than the 30d idle window
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_refresh_token().returning(move |_, _| {
            let mut record = sample_refresh_token(None);
            record.family_expires_at = family_expires_at;
            Ok(Some(record))
        });
        mock.expect_mark_refresh_token_spent()
            .returning(|_, _, _| Ok(()));
        mock.expect_create_refresh_token()
            .withf(move |_, data| {
                data.family_expires_at == family_expires_at && data.expires_at == family_expires_at
            })
            .returning(|_, data| {
                Ok(RefreshToken {
                    token_id: data.token_id,
                    family_id: data.family_id,
                    parent_token_id: data.parent_token_id,
                    domain_id: data.domain_id,
                    client_id: data.client_id,
                    user_id: data.user_id,
                    scope: data.scope,
                    issued_at: data.issued_at,
                    spent_at: None,
                    expires_at: data.expires_at,
                    family_expires_at: data.family_expires_at,
                    revoked_at: None,
                    revocation_reason: None,
                    amr: vec![],
                })
            });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "presented-bearer", "client-1", "domain-1")
            .await
            .unwrap();
        assert!(matches!(result, RefreshTokenRedemption::Rotated { .. }));
    }

    #[tokio::test]
    async fn test_redeem_refresh_token_legacy_record_backfills_family_cap() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_refresh_token().returning(|_, _| {
            let mut record = sample_refresh_token(None);
            record.family_expires_at = 0;
            Ok(Some(record))
        });
        mock.expect_mark_refresh_token_spent()
            .returning(|_, _, _| Ok(()));
        mock.expect_create_refresh_token()
            .withf(|_, data| {
                // Backfilled: now + 90d (config default), idle 30d inside it.
                data.family_expires_at > now() + 89 * 86400
                    && data.family_expires_at <= now() + 90 * 86400
                    && data.expires_at > now() + 29 * 86400
                    && data.expires_at <= data.family_expires_at
            })
            .returning(|_, data| {
                Ok(RefreshToken {
                    token_id: data.token_id,
                    family_id: data.family_id,
                    parent_token_id: data.parent_token_id,
                    domain_id: data.domain_id,
                    client_id: data.client_id,
                    user_id: data.user_id,
                    scope: data.scope,
                    issued_at: data.issued_at,
                    spent_at: None,
                    expires_at: data.expires_at,
                    family_expires_at: data.family_expires_at,
                    revoked_at: None,
                    revocation_reason: None,
                    amr: vec![],
                })
            });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "presented-bearer", "client-1", "domain-1")
            .await
            .unwrap();
        assert!(matches!(result, RefreshTokenRedemption::Rotated { .. }));
    }

    #[tokio::test]
    async fn test_issue_refresh_token_sets_family_expiry() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_create_refresh_token()
            .withf(|_, data| {
                let abs = 90 * 86400;
                data.family_expires_at - data.issued_at == abs
                    && data.expires_at - data.issued_at == 30 * 86400
            })
            .returning(|_, data| {
                Ok(RefreshToken {
                    token_id: data.token_id,
                    family_id: data.family_id,
                    parent_token_id: data.parent_token_id,
                    domain_id: data.domain_id,
                    client_id: data.client_id,
                    user_id: data.user_id,
                    scope: data.scope,
                    issued_at: data.issued_at,
                    spent_at: None,
                    expires_at: data.expires_at,
                    family_expires_at: data.family_expires_at,
                    revoked_at: None,
                    revocation_reason: None,
                    amr: vec![],
                })
            });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        service
            .issue_refresh_token(
                &state,
                IssueRefreshTokenRequest {
                    domain_id: "d".to_string(),
                    client_id: "c".to_string(),
                    user_id: "u".to_string(),
                    scope: vec![],
                    amr: vec![],
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_redeem_refresh_token_reuse_outside_grace_revokes_family() {
        let mut mock = MockOauth2SessionBackend::new();
        let spent_at = now() - 3600; // 1h ago, grace is 10 min
        mock.expect_get_refresh_token()
            .returning(move |_, _| Ok(Some(sample_refresh_token(Some(spent_at)))));
        mock.expect_revoke_refresh_token_family()
            .withf(|_, family_id, reason, revoked_at| {
                family_id == "family-1"
                    && *reason == RefreshTokenRevocationReason::ReuseDetected
                    && *revoked_at > 0
            })
            .returning(|_, _, _, _| Ok(()));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "presented-bearer", "client-1", "domain-1")
            .await
            .unwrap();
        assert!(matches!(
            result,
            RefreshTokenRedemption::ReuseDetected { family_id, reason }
                if family_id == "family-1"
                    && reason == RefreshTokenRevocationReason::ReuseDetected
        ));
    }

    #[tokio::test]
    async fn test_redeem_refresh_token_revoked_during_rotation_is_invalid() {
        // Backend refuses to spend a tombstoned token.
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_refresh_token()
            .returning(|_, _| Ok(Some(sample_refresh_token(None))));
        mock.expect_mark_refresh_token_spent()
            .returning(|_, id, _| Err(Oauth2SessionProviderError::NotFound(id.to_string())));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "presented-bearer", "client-1", "domain-1")
            .await
            .unwrap();
        assert!(matches!(result, RefreshTokenRedemption::Invalid));
    }

    #[tokio::test]
    async fn test_redeem_refresh_token_parent_revoked_after_child_minted_withholds_bearer() {
        let mut mock = MockOauth2SessionBackend::new();
        let mut reads = 0;
        mock.expect_get_refresh_token().returning(move |_, _| {
            reads += 1;
            let mut record = sample_refresh_token(None);
            // Second read (post-rotation re-check) sees the tombstone.
            if reads > 1 {
                record.revoked_at = Some(now());
                record.revocation_reason = Some("client_revoked".to_string());
            }
            Ok(Some(record))
        });
        mock.expect_mark_refresh_token_spent()
            .returning(|_, _, _| Ok(()));
        mock.expect_create_refresh_token().returning(|_, data| {
            Ok(RefreshToken {
                token_id: data.token_id,
                family_id: data.family_id,
                parent_token_id: data.parent_token_id,
                domain_id: data.domain_id,
                client_id: data.client_id,
                user_id: data.user_id,
                scope: data.scope,
                issued_at: data.issued_at,
                spent_at: None,
                expires_at: data.expires_at,
                family_expires_at: data.family_expires_at,
                revoked_at: None,
                revocation_reason: None,
                amr: vec![],
            })
        });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "presented-bearer", "client-1", "domain-1")
            .await
            .unwrap();
        assert!(matches!(result, RefreshTokenRedemption::Invalid));
    }

    #[tokio::test]
    async fn test_redeem_refresh_token_revoked_family_is_invalid_not_recascaded() {
        let mut mock = MockOauth2SessionBackend::new();
        // Spent long ago (outside grace) AND tombstoned: the revoked check
        // must win over the `spent_at` branch.
        let spent_at = now() - 3600;
        mock.expect_get_refresh_token().returning(move |_, _| {
            let mut record = sample_refresh_token(Some(spent_at));
            record.revoked_at = Some(now() - 10);
            record.revocation_reason = Some("reuse_detected".to_string());
            Ok(Some(record))
        });
        // `revoke_refresh_token_family` deliberately not configured:
        // mockall panics if it's called again.
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "presented-bearer", "client-1", "domain-1")
            .await
            .unwrap();
        assert!(matches!(result, RefreshTokenRedemption::Invalid));
    }

    #[tokio::test]
    async fn test_redeem_refresh_token_reuse_inside_grace_is_invalid_not_cascaded() {
        let mut mock = MockOauth2SessionBackend::new();
        let spent_at = now() - 60; // 1 min ago, well inside 10 min grace
        mock.expect_get_refresh_token()
            .returning(move |_, _| Ok(Some(sample_refresh_token(Some(spent_at)))));
        // `revoke_refresh_token_family` deliberately not configured: mockall
        // panics if it's called, proving the grace window short-circuits
        // before cascading.
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "presented-bearer", "client-1", "domain-1")
            .await
            .unwrap();
        assert!(matches!(result, RefreshTokenRedemption::Invalid));
    }

    #[tokio::test]
    async fn test_peek_refresh_token_is_read_only() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_refresh_token()
            .returning(|_, _| Ok(Some(sample_refresh_token(None))));
        // `mark_refresh_token_spent` / `create_refresh_token` deliberately
        // not configured: peeking must never mutate.
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let record = service
            .peek_refresh_token(&state, "presented-bearer")
            .await
            .unwrap();
        assert_eq!(record.unwrap().family_id, "family-1");
    }

    #[tokio::test]
    async fn test_redeem_refresh_token_unknown_is_invalid() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_refresh_token().returning(|_, _| Ok(None));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "unknown-bearer", "client-1", "domain-1")
            .await
            .unwrap();
        assert!(matches!(result, RefreshTokenRedemption::Invalid));
    }

    #[tokio::test]
    async fn test_redeem_refresh_token_foreign_client_is_invalid_no_writes() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_refresh_token()
            .returning(|_, _| Ok(Some(sample_refresh_token(None))));
        // `mark_refresh_token_spent` / `create_refresh_token` /
        // `revoke_refresh_token_family` deliberately not configured:
        // mockall panics if a foreign presenter reaches any write.
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "presented-bearer", "other-client", "domain-1")
            .await
            .unwrap();
        assert!(matches!(result, RefreshTokenRedemption::Invalid));
    }

    #[tokio::test]
    async fn test_redeem_refresh_token_foreign_domain_is_invalid_no_writes() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_refresh_token()
            .returning(|_, _| Ok(Some(sample_refresh_token(None))));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "presented-bearer", "client-1", "other-domain")
            .await
            .unwrap();
        assert!(matches!(result, RefreshTokenRedemption::Invalid));
    }

    #[tokio::test]
    async fn test_redeem_refresh_token_foreign_client_spent_token_does_not_revoke() {
        let mut mock = MockOauth2SessionBackend::new();
        // Spent long ago: a legitimate presenter would trigger the breach
        // cascade, a foreign one must not.
        mock.expect_get_refresh_token()
            .returning(|_, _| Ok(Some(sample_refresh_token(Some(1)))));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "presented-bearer", "other-client", "domain-1")
            .await
            .unwrap();
        assert!(matches!(result, RefreshTokenRedemption::Invalid));
    }

    fn sample_device_grant(
        status: DeviceGrantStatus,
        last_polled_at: Option<i64>,
    ) -> DeviceCodeGrant {
        DeviceCodeGrant {
            device_code: "device-code-1".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            domain_id: "domain-1".to_string(),
            client_id: "client-1".to_string(),
            scope: vec!["openid".to_string()],
            status,
            user_id: None,
            auth_time: None,
            amr: vec![],
            nonce: None,
            server_side_session_secret: "secret".to_string(),
            last_polled_at,
            created_at: now() - 100,
            expires_at: now() + 1_000_000,
            pending_user_id: None,
            pending_factors: vec![],
            mfa_attempts: 0,
        }
    }

    #[tokio::test]
    async fn test_start_device_authorization_generates_codes() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_create_device_code_grant().returning(|_, data| {
            Ok(DeviceCodeGrant {
                device_code: data.device_code,
                user_code: data.user_code,
                domain_id: data.domain_id,
                client_id: data.client_id,
                scope: data.scope,
                status: DeviceGrantStatus::Pending,
                user_id: None,
                auth_time: None,
                amr: vec![],
                nonce: None,
                server_side_session_secret: data.server_side_session_secret,
                last_polled_at: None,
                created_at: data.created_at,
                expires_at: data.expires_at,
                pending_user_id: None,
                pending_factors: vec![],
                mfa_attempts: 0,
            })
        });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let start = service
            .start_device_authorization(
                &state,
                StartDeviceAuthorizationRequest {
                    domain_id: "domain-1".to_string(),
                    client_id: "client-1".to_string(),
                    scope: vec!["openid".to_string()],
                },
            )
            .await
            .unwrap();
        assert!(!start.device_code.is_empty());
        // "XXXX-XXXX" shape (ADR 0026 §7.C).
        assert_eq!(start.user_code.len(), 9);
        assert_eq!(start.user_code.chars().nth(4), Some('-'));
    }

    #[tokio::test]
    async fn test_get_device_code_grant_by_user_code_expired_returns_none() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_device_code_grant_by_user_code()
            .returning(|_, _| {
                Ok(Some(DeviceCodeGrant {
                    expires_at: now() - 1,
                    ..sample_device_grant(DeviceGrantStatus::Pending, None)
                }))
            });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .get_device_code_grant_by_user_code(&state, "ABCD-EFGH")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_poll_device_code_grant_unknown_client_id_is_invalid_grant() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_device_code_grant()
            .returning(|_, _| Ok(Some(sample_device_grant(DeviceGrantStatus::Pending, None))));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .poll_device_code_grant(&state, "device-code-1", "domain-1", "wrong-client")
            .await
            .unwrap();
        assert!(matches!(result, DevicePollOutcome::InvalidGrant));
    }

    #[tokio::test]
    async fn test_poll_device_code_grant_foreign_domain_is_invalid_grant() {
        // No `take_*`/`mark_*` expectation: a wrong-domain poll must not
        // consume or stamp the grant.
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_device_code_grant().returning(|_, _| {
            Ok(Some(sample_device_grant(
                DeviceGrantStatus::Authorized,
                None,
            )))
        });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .poll_device_code_grant(&state, "device-code-1", "other-domain", "client-1")
            .await
            .unwrap();
        assert!(matches!(result, DevicePollOutcome::InvalidGrant));
    }

    #[tokio::test]
    async fn test_poll_device_code_grant_pending_stamps_last_polled_at() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_device_code_grant()
            .returning(|_, _| Ok(Some(sample_device_grant(DeviceGrantStatus::Pending, None))));
        mock.expect_mark_device_code_grant_polled()
            .returning(|_, _, _| Ok(()));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .poll_device_code_grant(&state, "device-code-1", "domain-1", "client-1")
            .await
            .unwrap();
        assert!(matches!(result, DevicePollOutcome::Pending));
    }

    #[tokio::test]
    async fn test_poll_device_code_grant_too_soon_is_slow_down() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_device_code_grant().returning(|_, _| {
            Ok(Some(sample_device_grant(
                DeviceGrantStatus::Pending,
                Some(now()),
            )))
        });
        // No `expect_mark_device_code_grant_polled`: calling it would panic
        // the mock -- a throttled poll must not reset the interval clock.
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .poll_device_code_grant(&state, "device-code-1", "domain-1", "client-1")
            .await
            .unwrap();
        assert!(matches!(result, DevicePollOutcome::SlowDown));
    }

    #[tokio::test]
    async fn test_poll_device_code_grant_denied() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_device_code_grant()
            .returning(|_, _| Ok(Some(sample_device_grant(DeviceGrantStatus::Denied, None))));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .poll_device_code_grant(&state, "device-code-1", "domain-1", "client-1")
            .await
            .unwrap();
        assert!(matches!(result, DevicePollOutcome::Denied));
    }

    #[tokio::test]
    async fn test_poll_device_code_grant_authorized_takes_and_returns_record() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_device_code_grant().returning(|_, _| {
            Ok(Some(sample_device_grant(
                DeviceGrantStatus::Authorized,
                None,
            )))
        });
        mock.expect_take_device_code_grant().returning(|_, _| {
            Ok(Some(sample_device_grant(
                DeviceGrantStatus::Authorized,
                None,
            )))
        });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .poll_device_code_grant(&state, "device-code-1", "domain-1", "client-1")
            .await
            .unwrap();
        assert!(matches!(result, DevicePollOutcome::Authorized(_)));
    }

    #[tokio::test]
    async fn test_poll_device_code_grant_expired() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_device_code_grant().returning(|_, _| {
            Ok(Some(DeviceCodeGrant {
                expires_at: now() - 1,
                ..sample_device_grant(DeviceGrantStatus::Pending, None)
            }))
        });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .poll_device_code_grant(&state, "device-code-1", "domain-1", "client-1")
            .await
            .unwrap();
        assert!(matches!(result, DevicePollOutcome::Expired));
    }
    #[tokio::test]
    async fn test_purge_expired_dispatches_by_kind() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_delete_pre_auth_session()
            .withf(|_, id| id == "s1")
            .times(1)
            .returning(|_, _| Ok(()));
        mock.expect_take_authorization_code()
            .withf(|_, c| c == "c1")
            .times(1)
            .returning(|_, _| Ok(None));
        mock.expect_take_device_code_grant()
            .withf(|_, d| d == "d1")
            .times(1)
            .returning(|_, _| Ok(None));
        mock.expect_delete_refresh_token()
            .withf(|_, t| t == "t1")
            .times(2)
            .returning(|_, _| Ok(()));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        for (kind, pk) in [
            ("session", "s1"),
            ("code", "c1"),
            ("device", "d1"),
            ("refresh", "t1"),
            ("refresh_tombstone", "t1"),
        ] {
            service.purge_expired(&state, kind, pk).await.unwrap();
        }
        assert!(matches!(
            service.purge_expired(&state, "bogus", "x").await,
            Err(Oauth2SessionProviderError::InvalidRecordKind(_))
        ));
    }

    #[tokio::test]
    async fn test_list_expired_filters_by_kind() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_list_expired()
            .withf(|_, kind, before, limit| {
                *kind == Some("session") && *before == 10 && *limit == 5
            })
            .returning(|_, _, _, _| Ok(vec![("session".to_string(), "s1".to_string())]));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let out = service
            .list_expired(&state, "session", 10, 5)
            .await
            .unwrap();
        assert_eq!(out, vec![("session".to_string(), "s1".to_string())]);
    }
}
