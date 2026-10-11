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
//! Second-factor step of the browser (`authorize`) and device login pages.
//!
//! After the password step, a user holding a second factor must pass it
//! before the flow reaches consent; a session in that state carries
//! `pending_user_id`/`pending_factors` but no `user_id`, so the consent and
//! code-issuing steps (which require `user_id`) cannot be reached early.
//! TOTP and, when the WebAuthn extension is enabled, passkeys are offered.

use std::sync::Arc;

use secrecy::SecretString;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::auth::IdentityInfo;
use openstack_keystone_core_types::identity::{IdentityProviderError, UserTotpAuthRequestBuilder};

use super::passkey::{PasskeyFactor, PasskeyOutcome};
use crate::keystone::ServiceState;

/// Pending-factor name of a TOTP passcode.
pub(super) const FACTOR_TOTP: &str = "totp";

/// Pending-factor name of a WebAuthn passkey assertion.
pub(super) const FACTOR_WEBAUTHN: &str = "webauthn";

/// Decide which second factors `user_id` has to pass after the password
/// step: a TOTP passcode when the user has a `totp` credential, unless the
/// user switched MFA off (`multi_factor_auth_enabled = false`). This uses
/// the same credentials `POST /v3/auth/tokens` accepts for the `totp`
/// method, so a user cannot sign in through the OP with less than a
/// multi-method v3 login would take. A user with a registered passkey also
/// gets the `webauthn` factor when the extension is enabled (`passkeys`).
/// Passing either of the offered factors completes the login. Any lookup
/// failure is an error:
/// failing open would let the second factor be skipped.
pub(super) async fn required_factors(
    state: &ServiceState,
    passkeys: Option<&Arc<dyn PasskeyFactor>>,
    user_id: &str,
) -> Result<Vec<String>, String> {
    let exec = ExecutionContext::internal(state);
    let user = state
        .provider
        .get_identity_provider()
        .get_user(&exec, user_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("user {user_id} not found"))?;
    if user.options.multi_factor_auth_enabled == Some(false) {
        return Ok(Vec::new());
    }
    let totp = state
        .provider
        .get_credential_provider()
        .list_credentials_for_user(&exec, user_id, Some("totp"))
        .await
        .map_err(|e| e.to_string())?;
    let mut factors = Vec::new();
    if !totp.is_empty() {
        factors.push(FACTOR_TOTP.to_string());
    }
    if let Some(passkeys) = passkeys
        && passkeys.has_passkey(user_id).await?
    {
        factors.push(FACTOR_WEBAUTHN.to_string());
    }
    Ok(factors)
}

/// What the MFA page offers: the TOTP form and/or a passkey challenge.
pub(super) struct MfaOffer {
    pub totp: bool,
    /// JSON request options of the freshly issued passkey challenge.
    pub passkey: Option<String>,
}

/// Build the offer for `factors`, issuing a new passkey challenge when
/// needed. Call again for every re-render: a challenge is single use.
pub(super) async fn mfa_offer(
    passkeys: Option<&Arc<dyn PasskeyFactor>>,
    factors: &[String],
    user_id: &str,
    ceremony: &str,
) -> Result<MfaOffer, String> {
    Ok(MfaOffer {
        totp: factors.iter().any(|f| f == FACTOR_TOTP),
        passkey: passkey_challenge(passkeys, factors, user_id, ceremony).await?,
    })
}

/// Check the submitted second factor `factor` (`totp` or `webauthn`).
pub(super) async fn verify_factor(
    state: &ServiceState,
    passkeys: Option<&Arc<dyn PasskeyFactor>>,
    factor: &str,
    user_id: &str,
    ceremony: &str,
    passcode: &str,
    assertion: &str,
) -> FactorOutcome {
    if factor == FACTOR_WEBAUTHN {
        return match verify_passkey(state, passkeys, user_id, ceremony, assertion).await {
            PasskeyOutcome::Verified => FactorOutcome::Verified,
            PasskeyOutcome::Invalid => FactorOutcome::Invalid,
            PasskeyOutcome::RateLimited(s) => FactorOutcome::RateLimited(s),
            PasskeyOutcome::Failed => FactorOutcome::Failed,
        };
    }
    verify_totp(state, user_id, passcode.trim()).await
}

/// Challenge for the passkey page when `webauthn` is among `factors`.
/// `Ok(None)` when no passkey is pending; a failure to issue the challenge
/// is an error rather than silently dropping the factor.
pub(super) async fn passkey_challenge(
    passkeys: Option<&Arc<dyn PasskeyFactor>>,
    factors: &[String],
    user_id: &str,
    ceremony: &str,
) -> Result<Option<String>, String> {
    match passkeys {
        Some(passkeys) if factors.iter().any(|f| f == FACTOR_WEBAUTHN) => {
            passkeys.start(user_id, ceremony).await.map(Some)
        }
        _ => Ok(None),
    }
}

/// Verify a passkey assertion for `user_id`, applying the same per-user
/// rate limit as password and TOTP authentication.
pub(super) async fn verify_passkey(
    state: &ServiceState,
    passkeys: Option<&Arc<dyn PasskeyFactor>>,
    user_id: &str,
    ceremony: &str,
    assertion: &str,
) -> PasskeyOutcome {
    let Some(passkeys) = passkeys else {
        return PasskeyOutcome::Invalid;
    };
    if let Err(retry_after) = state.rate_limiters.check_user(user_id) {
        return PasskeyOutcome::RateLimited(retry_after.as_secs());
    }
    passkeys.verify(user_id, ceremony, assertion).await
}

/// RFC 8176 `amr` values for a login that passed the password step and the
/// given second factor: `["pwd"]`, `["pwd", "otp", "mfa"]` with TOTP or
/// `["pwd", "hwk", "mfa"]` with a passkey. `passed` is the factor that was
/// actually verified, not the whole pending list.
pub(super) fn amr_for(passed: &[String]) -> Vec<String> {
    let second_factors = passed;
    let mut amr = vec!["pwd".to_string()];
    if second_factors.iter().any(|f| f == FACTOR_TOTP) {
        amr.push("otp".to_string());
    }
    if second_factors.iter().any(|f| f == FACTOR_WEBAUTHN) {
        amr.push("hwk".to_string());
    }
    if !second_factors.is_empty() {
        amr.push("mfa".to_string());
    }
    amr
}

/// Result of checking a second factor.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum FactorOutcome {
    /// The passcode or assertion matched one of the user's credentials.
    Verified,
    /// Wrong passcode (or the user has no usable credential).
    Invalid,
    /// The per-user rate limit (`[rate_limit_user_auth]`) refused the attempt.
    RateLimited(u64),
    /// Anything else; the caller answers `500`.
    Failed,
}

/// Verify `passcode` for `user_id` through `authenticate_by_totp`, which also
/// applies the per-user rate limit shared with password authentication.
pub(super) async fn verify_totp(
    state: &ServiceState,
    user_id: &str,
    passcode: &str,
) -> FactorOutcome {
    let Ok(request) = UserTotpAuthRequestBuilder::default()
        .id(user_id)
        .passcode(SecretString::from(passcode.to_string()))
        .build()
    else {
        return FactorOutcome::Invalid;
    };
    let exec = ExecutionContext::internal(state);
    match state
        .provider
        .get_identity_provider()
        .authenticate_by_totp(&exec, &request)
        .await
    {
        Ok(result) => match &result.principal.identity {
            IdentityInfo::User(info) if info.user_id == user_id => FactorOutcome::Verified,
            _ => FactorOutcome::Failed,
        },
        Err(IdentityProviderError::TooManyRequests { retry_after_secs }) => {
            FactorOutcome::RateLimited(retry_after_secs)
        }
        Err(IdentityProviderError::Authentication { source }) => {
            tracing::debug!(error = %source, "oauth2 totp verification failed");
            FactorOutcome::Invalid
        }
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 totp verification error");
            FactorOutcome::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::tests::get_mocked_state;
    use crate::credential::MockCredentialProvider;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use openstack_keystone_core_types::credential::CredentialBuilder;
    use openstack_keystone_core_types::identity::{UserOptions, UserResponseBuilder};

    async fn factors(
        mfa_enabled: Option<bool>,
        totp_credentials: usize,
        user_exists: bool,
    ) -> Result<Vec<String>, String> {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(move |_, _| {
            if !user_exists {
                return Ok(None);
            }
            let mut user = UserResponseBuilder::default()
                .id("user-1")
                .name("alice")
                .domain_id("domain-1")
                .enabled(true)
                .build()
                .unwrap();
            user.options = UserOptions {
                multi_factor_auth_enabled: mfa_enabled,
                ..Default::default()
            };
            Ok(Some(user))
        });
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_list_credentials_for_user()
            .returning(move |_, _, _| {
                Ok((0..totp_credentials)
                    .map(|i| {
                        CredentialBuilder::default()
                            .id(format!("cred-{i}"))
                            .blob(r#"{"seed": "x"}"#)
                            .r#type("totp")
                            .user_id("user-1")
                            .build()
                            .unwrap()
                    })
                    .collect())
            });
        let provider = Provider::mocked_builder()
            .mock_identity(identity_mock)
            .mock_credential(credential_mock);
        let state = get_mocked_state(provider, true, None).await;
        required_factors(&state, None, "user-1").await
    }

    #[tokio::test]
    async fn test_required_factors_totp_when_credential_enrolled() {
        assert_eq!(factors(None, 1, true).await.unwrap(), vec![FACTOR_TOTP]);
        assert_eq!(
            factors(Some(true), 1, true).await.unwrap(),
            vec![FACTOR_TOTP]
        );
    }

    #[tokio::test]
    async fn test_required_factors_none_without_credential() {
        assert!(factors(None, 0, true).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_required_factors_skipped_when_mfa_disabled_for_user() {
        assert!(factors(Some(false), 1, true).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_required_factors_fails_closed_for_missing_user() {
        assert!(factors(None, 1, false).await.is_err());
    }

    #[derive(Debug)]
    struct FakePasskeys {
        registered: bool,
        accept: bool,
    }

    #[async_trait::async_trait]
    impl PasskeyFactor for FakePasskeys {
        async fn has_passkey(&self, _user_id: &str) -> Result<bool, String> {
            Ok(self.registered)
        }
        async fn start(&self, _user_id: &str, _ceremony: &str) -> Result<String, String> {
            Ok(r#"{"public_key":{"challenge":"abc"}}"#.to_string())
        }
        async fn verify(&self, _user_id: &str, _ceremony: &str, assertion: &str) -> PasskeyOutcome {
            if self.accept && assertion == "good" {
                PasskeyOutcome::Verified
            } else {
                PasskeyOutcome::Invalid
            }
        }
    }

    #[tokio::test]
    async fn test_required_factors_includes_registered_passkey() {
        let passkeys: Arc<dyn PasskeyFactor> = Arc::new(FakePasskeys {
            registered: true,
            accept: true,
        });
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| {
            Ok(Some(
                openstack_keystone_core_types::identity::UserResponseBuilder::default()
                    .id("user-1")
                    .name("alice")
                    .domain_id("d")
                    .enabled(true)
                    .build()
                    .unwrap(),
            ))
        });
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_list_credentials_for_user()
            .returning(|_, _, _| Ok(Vec::new()));
        let provider = Provider::mocked_builder()
            .mock_identity(identity_mock)
            .mock_credential(credential_mock);
        let state = get_mocked_state(provider, true, None).await;
        assert_eq!(
            required_factors(&state, Some(&passkeys), "user-1")
                .await
                .unwrap(),
            vec![FACTOR_WEBAUTHN]
        );
        let offer = mfa_offer(
            Some(&passkeys),
            &[FACTOR_WEBAUTHN.to_string()],
            "user-1",
            "c-1",
        )
        .await
        .unwrap();
        assert!(!offer.totp);
        assert!(offer.passkey.is_some());
        // Without the extension no challenge is issued.
        let offer = mfa_offer(None, &[FACTOR_WEBAUTHN.to_string()], "user-1", "c-1")
            .await
            .unwrap();
        assert!(offer.passkey.is_none());
    }

    #[test]
    fn test_amr_for_passkey() {
        assert_eq!(
            amr_for(&[FACTOR_WEBAUTHN.to_string()]),
            vec!["pwd", "hwk", "mfa"]
        );
    }

    #[test]
    fn test_amr_for() {
        assert_eq!(amr_for(&[]), vec!["pwd"]);
        assert_eq!(
            amr_for(&[FACTOR_TOTP.to_string()]),
            vec!["pwd", "otp", "mfa"]
        );
    }
}
