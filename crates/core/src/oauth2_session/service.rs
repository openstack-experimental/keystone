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
    IssueAuthorizationCodeRequest, IssueRefreshTokenRequest, Oauth2SessionApi,
    RefreshTokenRedemption, StartPreAuthSessionRequest,
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
}

#[async_trait]
impl Oauth2SessionApi for Oauth2SessionService {
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

    async fn mark_authenticated(
        &self,
        state: &ServiceState,
        session_id: &str,
        user_id: &str,
        auth_time: i64,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError> {
        self.backend_driver
            .mark_pre_auth_session_authenticated(state, session_id, user_id, auth_time)
            .await
    }

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

    async fn complete_pre_auth_session(
        &self,
        state: &ServiceState,
        session_id: &str,
    ) -> Result<(), Oauth2SessionProviderError> {
        self.backend_driver
            .delete_pre_auth_session(state, session_id)
            .await
    }

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

    async fn issue_refresh_token(
        &self,
        state: &ServiceState,
        req: IssueRefreshTokenRequest,
    ) -> Result<(RefreshToken, String), Oauth2SessionProviderError> {
        let bearer = generate_entropy();
        let issued_at = now();
        let expires_at =
            issued_at + i64::from(self.oauth2_config.refresh_token_lifetime_days) * 86400;
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
                    issued_at,
                    expires_at,
                },
            )
            .await?;
        Ok((record, bearer))
    }

    async fn redeem_refresh_token(
        &self,
        state: &ServiceState,
        presented_bearer: &str,
    ) -> Result<RefreshTokenRedemption, Oauth2SessionProviderError> {
        let token_id = hash_bearer(presented_bearer);
        let Some(record) = self
            .backend_driver
            .get_refresh_token(state, &token_id)
            .await?
        else {
            return Ok(RefreshTokenRedemption::Invalid);
        };
        let now = now();
        if record.expires_at < now {
            return Ok(RefreshTokenRedemption::Invalid);
        }

        match record.spent_at {
            None => {
                self.backend_driver
                    .mark_refresh_token_spent(state, &token_id, now)
                    .await?;
                let bearer = generate_entropy();
                let expires_at =
                    now + i64::from(self.oauth2_config.refresh_token_lifetime_days) * 86400;
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
                            issued_at: now,
                            expires_at,
                        },
                    )
                    .await?;
                Ok(RefreshTokenRedemption::Rotated {
                    record: child,
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
                        .revoke_refresh_token_family(state, &record.family_id)
                        .await?;
                    Ok(RefreshTokenRedemption::ReuseDetected {
                        family_id: record.family_id,
                    })
                }
            }
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
            expires_at: now() + 1_000_000,
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
            })
        });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "presented-bearer")
            .await
            .unwrap();
        assert!(matches!(result, RefreshTokenRedemption::Rotated { .. }));
    }

    #[tokio::test]
    async fn test_redeem_refresh_token_reuse_outside_grace_revokes_family() {
        let mut mock = MockOauth2SessionBackend::new();
        let spent_at = now() - 3600; // 1h ago, grace is 10 min
        mock.expect_get_refresh_token()
            .returning(move |_, _| Ok(Some(sample_refresh_token(Some(spent_at)))));
        mock.expect_revoke_refresh_token_family()
            .withf(|_, family_id| family_id == "family-1")
            .returning(|_, _| Ok(()));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "presented-bearer")
            .await
            .unwrap();
        assert!(matches!(
            result,
            RefreshTokenRedemption::ReuseDetected { family_id } if family_id == "family-1"
        ));
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
            .redeem_refresh_token(&state, "presented-bearer")
            .await
            .unwrap();
        assert!(matches!(result, RefreshTokenRedemption::Invalid));
    }

    #[tokio::test]
    async fn test_redeem_refresh_token_unknown_is_invalid() {
        let mut mock = MockOauth2SessionBackend::new();
        mock.expect_get_refresh_token().returning(|_, _| Ok(None));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;

        let result = service
            .redeem_refresh_token(&state, "unknown-bearer")
            .await
            .unwrap();
        assert!(matches!(result, RefreshTokenRedemption::Invalid));
    }
}
