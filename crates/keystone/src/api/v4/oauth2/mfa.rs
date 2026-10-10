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
//! Only TOTP is offered; WebAuthn/passkeys need the extension state and a
//! script nonce on the page and are not wired into the OP yet.

use secrecy::SecretString;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::auth::IdentityInfo;
use openstack_keystone_core_types::identity::{IdentityProviderError, UserTotpAuthRequestBuilder};

use crate::keystone::ServiceState;

/// Pending-factor name of a TOTP passcode.
pub(super) const FACTOR_TOTP: &str = "totp";

/// Decide which second factors `user_id` has to pass after the password
/// step: a TOTP passcode when the user has a `totp` credential, unless the
/// user switched MFA off (`multi_factor_auth_enabled = false`). This uses
/// the same credentials `POST /v3/auth/tokens` accepts for the `totp`
/// method, so a user cannot sign in through the OP with less than a
/// multi-method v3 login would take. Any lookup failure is an error:
/// failing open would let the second factor be skipped.
pub(super) async fn required_factors(
    state: &ServiceState,
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
    Ok(if totp.is_empty() {
        Vec::new()
    } else {
        vec![FACTOR_TOTP.to_string()]
    })
}

/// RFC 8176 `amr` values for a login that passed the password step and the
/// given second factors: `["pwd"]`, or `["pwd", "otp", "mfa"]` with TOTP.
pub(super) fn amr_for(second_factors: &[String]) -> Vec<String> {
    let mut amr = vec!["pwd".to_string()];
    if second_factors.iter().any(|f| f == FACTOR_TOTP) {
        amr.push("otp".to_string());
    }
    if !second_factors.is_empty() {
        amr.push("mfa".to_string());
    }
    amr
}

/// Result of checking a TOTP passcode.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum TotpOutcome {
    /// The passcode matched one of the user's TOTP credentials.
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
) -> TotpOutcome {
    let Ok(request) = UserTotpAuthRequestBuilder::default()
        .id(user_id)
        .passcode(SecretString::from(passcode.to_string()))
        .build()
    else {
        return TotpOutcome::Invalid;
    };
    let exec = ExecutionContext::internal(state);
    match state
        .provider
        .get_identity_provider()
        .authenticate_by_totp(&exec, &request)
        .await
    {
        Ok(result) => match &result.principal.identity {
            IdentityInfo::User(info) if info.user_id == user_id => TotpOutcome::Verified,
            _ => TotpOutcome::Failed,
        },
        Err(IdentityProviderError::TooManyRequests { retry_after_secs }) => {
            TotpOutcome::RateLimited(retry_after_secs)
        }
        Err(IdentityProviderError::Authentication { source }) => {
            tracing::debug!(error = %source, "oauth2 totp verification failed");
            TotpOutcome::Invalid
        }
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 totp verification error");
            TotpOutcome::Failed
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
        required_factors(&state, "user-1").await
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

    #[test]
    fn test_amr_for() {
        assert_eq!(amr_for(&[]), vec!["pwd"]);
        assert_eq!(
            amr_for(&[FACTOR_TOTP.to_string()]),
            vec!["pwd", "otp", "mfa"]
        );
    }
}
