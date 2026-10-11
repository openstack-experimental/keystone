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
//! Passkey (WebAuthn) second factor of the OAuth2 provider.
//!
//! The WebAuthn extension keeps its own state, which core `ServiceState`
//! cannot reach. When the extension is enabled the router injects an
//! [`Arc<dyn PasskeyFactor>`] request extension; the MFA handlers take it as
//! an optional extractor, so a deployment without the extension simply never
//! offers (or requires) a passkey.

use std::sync::Arc;

use async_trait::async_trait;
use axum::Extension;
use validator::Validate;

use openstack_keystone_api_types::error::KeystoneApiError;
use openstack_keystone_api_types::webauthn::auth::PasskeyAuthenticationFinishRequest;
use openstack_keystone_webauthn::api::types::CombinedExtensionState;
use openstack_keystone_webauthn::api::{start_challenge, user_has_passkeys, verify_assertion};

/// Result of checking a signed passkey assertion.
#[derive(Debug, PartialEq, Eq)]
pub enum PasskeyOutcome {
    /// The assertion matched one of the user's passkeys.
    Verified,
    /// Malformed, unsigned for this challenge, replayed or otherwise refused.
    Invalid,
    /// The per-user rate limit refused the attempt.
    RateLimited(u64),
    /// Anything else; the caller answers `500`.
    Failed,
}

/// What the OP needs from the WebAuthn extension.
#[async_trait]
pub trait PasskeyFactor: Send + Sync + std::fmt::Debug {
    /// Whether the user has at least one registered passkey.
    async fn has_passkey(&self, user_id: &str) -> Result<bool, String>;

    /// Issue a challenge for the user; returns the JSON request options for
    /// `navigator.credentials.get`.
    ///
    /// `ceremony` is a secret of the login in progress (its pre-auth session
    /// or device code). The challenge lives in a slot of its own, so neither
    /// the public passkey endpoints nor another login of the same user can
    /// replace or consume it.
    async fn start(&self, user_id: &str, ceremony: &str) -> Result<String, String>;

    /// Verify the JSON `PublicKeyCredential` the browser produced against
    /// the challenge `start` issued for the same `ceremony`.
    async fn verify(&self, user_id: &str, ceremony: &str, assertion: &str) -> PasskeyOutcome;
}

/// Optional handle injected by the router when the extension is enabled.
pub(super) type Passkeys = Option<Extension<Arc<dyn PasskeyFactor>>>;

/// [`PasskeyFactor`] backed by the real WebAuthn extension.
pub struct WebauthnPasskeys(pub CombinedExtensionState);

impl std::fmt::Debug for WebauthnPasskeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WebauthnPasskeys")
    }
}

#[async_trait]
impl PasskeyFactor for WebauthnPasskeys {
    async fn has_passkey(&self, user_id: &str) -> Result<bool, String> {
        user_has_passkeys(&self.0, user_id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn start(&self, user_id: &str, ceremony: &str) -> Result<String, String> {
        let options = start_challenge(&self.0, user_id, Some(ceremony))
            .await
            .map_err(|e| e.to_string())?;
        serde_json::to_string(&options).map_err(|e| e.to_string())
    }

    async fn verify(&self, user_id: &str, ceremony: &str, assertion: &str) -> PasskeyOutcome {
        let Ok(mut request) = serde_json::from_str::<PasskeyAuthenticationFinishRequest>(assertion)
        else {
            return PasskeyOutcome::Invalid;
        };
        // The user is the one that passed the first factor, never whatever
        // the browser claims.
        request.user_id = user_id.to_string();
        if request.validate().is_err() {
            return PasskeyOutcome::Invalid;
        }
        match verify_assertion(&self.0, user_id, Some(ceremony), request).await {
            Ok(()) => PasskeyOutcome::Verified,
            Err(KeystoneApiError::InternalError(e)) => {
                tracing::warn!(error = %e, "oauth2 passkey verification error");
                PasskeyOutcome::Failed
            }
            Err(e) => {
                tracing::debug!(error = %e, "oauth2 passkey verification failed");
                PasskeyOutcome::Invalid
            }
        }
    }
}
