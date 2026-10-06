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
//! # JWS token driver for the `openstack_keystone` crate (ADR 0026 §10, Phase 0)
//!
//! Wire-compatible with Python Keystone's `[token] provider = jws`:
//! ES256-signed reference tokens carrying only identity/scope anchors (no
//! roles, no catalog) — a token *format*, not the OP-issued
//! `OpenStackAccessTokenClaims` later ADR 0026 phases introduce.
use std::fmt;
use std::sync::Arc;

use jsonwebtoken::{Header, Validation, decode, encode};
use openstack_keystone_config::{Config, TokenProviderDriver};
use openstack_keystone_core::plugin_manager::BackendRegistration;
use openstack_keystone_core::token::TokenProviderError;
use openstack_keystone_core::token::backend::TokenBackend;
use openstack_keystone_core_types::token::TokenPayload;
use openstack_keystone_key_repository::asymmetric::{
    ActiveKeys, AsymmetricKeyRepository, FilesystemAsymmetricKeySource, to_decoding_key,
    to_encoding_key,
};

mod claims;
mod config;
pub mod error;

pub use claims::JwsClaims;
pub use config::JwsTokensConfig;
pub use error::JwsDriverError;
pub use openstack_keystone_key_repository::asymmetric::jwt_algorithm;

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

inventory::submit! {
    // Only registered when actually selected (ADR-0026 §10, Phase 0): unlike
    // fernet, a `[jws_tokens]` key repository need not exist for a
    // fernet-only deployment, so this driver must not be eagerly built.
    BackendRegistration::<dyn TokenBackend> {
        name: "jws",
        selected: |cfg| cfg.token.provider == TokenProviderDriver::Jws,
        build: |cfg| {
            let section = cfg.require::<JwsTokensConfig>().cloned();
            Box::pin(async move {
                let mut provider = JwsTokenProvider::new(section?);
                provider.load_keys().await?;
                Ok(Arc::new(provider) as Arc<dyn TokenBackend>)
            })
        },
    }
}

/// JWS token provider.
pub struct JwsTokenProvider {
    repo: AsymmetricKeyRepository<FilesystemAsymmetricKeySource>,
    /// Populated by [`Self::load_keys`]: `encode`/`decode` are synchronous
    /// (called on every request) and require it to have already run,
    /// mirroring `FernetTokenProvider`'s `cached` field.
    active: Option<ActiveKeys>,
}

impl fmt::Debug for JwsTokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("JwsTokenProvider").finish()
    }
}

impl JwsTokenProvider {
    /// Construct a new provider. Call [`Self::load_keys`] before use.
    pub fn new(config: JwsTokensConfig) -> Self {
        let repo =
            AsymmetricKeyRepository::new(FilesystemAsymmetricKeySource::new(config.key_repository));
        Self { repo, active: None }
    }

    /// Load (or reload) the active signing keys from the configured key
    /// repository.
    ///
    /// # Errors
    /// [`JwsDriverError::KeyRepository`] if the repository has no usable
    /// `Primary` key — a `[token] provider = jws` deployment must fail
    /// loudly at startup rather than silently falling back to Fernet.
    pub async fn load_keys(&mut self) -> Result<(), JwsDriverError> {
        self.active = Some(self.repo.load_active().await?);
        Ok(())
    }

    fn active(&self) -> Result<&ActiveKeys, JwsDriverError> {
        self.active.as_ref().ok_or(JwsDriverError::KeysNotLoaded)
    }
}

impl TokenBackend for JwsTokenProvider {
    /// The signing keys are loaded once from the `[jws_tokens]` key
    /// repository; nothing in the core configuration affects them.
    fn set_config(&mut self, _config: Config) {}

    fn decode(&self, credential: &str) -> Result<TokenPayload, TokenProviderError> {
        let active = self.active().map_err(TokenProviderError::from)?;

        // Try Primary first, then Previous (multi-generational tolerance
        // during a rotation's grace window — same principle as ADR 0026
        // §3's JWKS publishing, scoped here to whatever this provider's
        // own key source currently holds).
        let candidates = std::iter::once(&active.primary).chain(active.previous.iter());
        let mut last_error: Option<JwsDriverError> = None;
        for material in candidates {
            let decoding_key = match to_decoding_key(material) {
                Ok(key) => key,
                Err(error) => {
                    last_error = Some(JwsDriverError::from(error));
                    continue;
                }
            };
            let mut validation = Validation::new(jwt_algorithm(material.algorithm));
            validation.validate_exp = true;
            match decode::<JwsClaims>(credential, &decoding_key, &validation) {
                Ok(token_data) => {
                    return token_data.claims.into_token_payload().map_err(|error| {
                        TokenProviderError::InvalidToken {
                            source: Box::new(error),
                        }
                    });
                }
                Err(error) => last_error = Some(JwsDriverError::from(error)),
            }
        }
        match last_error {
            Some(source) => Err(TokenProviderError::InvalidToken {
                source: Box::new(source),
            }),
            None => Err(JwsDriverError::KeysNotLoaded.into()),
        }
    }

    fn encode(&self, token: &TokenPayload) -> Result<String, TokenProviderError> {
        let active = self.active().map_err(TokenProviderError::from)?;
        let claims = JwsClaims::try_from(token).map_err(TokenProviderError::from)?;
        let encoding_key = to_encoding_key(&active.primary)
            .map_err(JwsDriverError::from)
            .map_err(TokenProviderError::from)?;
        let header = Header::new(jwt_algorithm(active.primary.algorithm));
        encode(&header, &claims, &encoding_key)
            .map_err(|e| TokenProviderError::from(JwsDriverError::from(e)))
    }
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core_types::token::{ProjectScopePayload, UnscopedPayload};

    use super::*;

    fn setup_config(dir: &std::path::Path) -> JwsTokensConfig {
        JwsTokensConfig {
            key_repository: dir.to_path_buf(),
            ..Default::default()
        }
    }

    async fn provider_with_keys(dir: &std::path::Path) -> JwsTokenProvider {
        let mut provider = JwsTokenProvider::new(setup_config(dir));
        provider
            .repo
            .setup(openstack_keystone_key_repository::asymmetric::SigningAlgorithm::Es256)
            .await
            .unwrap();
        provider.load_keys().await.unwrap();
        provider
    }

    #[tokio::test]
    async fn test_encode_decode_roundtrip_unscoped() {
        let dir = tempfile::tempdir().unwrap();
        let provider = provider_with_keys(dir.path()).await;

        let token = TokenPayload::Unscoped(UnscopedPayload {
            user_id: "user-1".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["abc123".into()],
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            issued_at: chrono::Utc::now(),
            ..Default::default()
        });

        let encoded = provider.encode(&token).unwrap();
        let decoded = provider.decode(&encoded).unwrap();
        match decoded {
            TokenPayload::Unscoped(p) => assert_eq!(p.user_id, "user-1"),
            other => panic!("expected Unscoped, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_encode_decode_roundtrip_project_scope() {
        let dir = tempfile::tempdir().unwrap();
        let provider = provider_with_keys(dir.path()).await;

        let token = TokenPayload::ProjectScope(ProjectScopePayload {
            user_id: "user-1".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["abc123".into()],
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            issued_at: chrono::Utc::now(),
            project_id: "project-1".into(),
        });

        let encoded = provider.encode(&token).unwrap();
        let decoded = provider.decode(&encoded).unwrap();
        match decoded {
            TokenPayload::ProjectScope(p) => assert_eq!(p.project_id, "project-1"),
            other => panic!("expected ProjectScope, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_decode_before_load_keys_fails() {
        let dir = tempfile::tempdir().unwrap();
        let provider = JwsTokenProvider::new(setup_config(dir.path()));
        assert!(provider.decode("whatever").is_err());
    }

    #[tokio::test]
    async fn test_load_keys_fails_when_repository_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = JwsTokenProvider::new(setup_config(dir.path()));
        assert!(provider.load_keys().await.is_err());
    }

    #[tokio::test]
    async fn test_decode_rejects_tampered_token() {
        let dir = tempfile::tempdir().unwrap();
        let provider = provider_with_keys(dir.path()).await;

        let token = TokenPayload::Unscoped(UnscopedPayload {
            user_id: "user-1".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["abc123".into()],
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            issued_at: chrono::Utc::now(),
            ..Default::default()
        });
        let mut encoded = provider.encode(&token).unwrap();
        encoded.push('x');
        assert!(matches!(
            provider.decode(&encoded),
            Err(TokenProviderError::InvalidToken { .. })
        ));
    }

    #[tokio::test]
    async fn test_decode_falls_back_to_previous_when_primary_is_corrupt()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let mut provider = provider_with_keys(dir.path()).await;
        let token = TokenPayload::Unscoped(UnscopedPayload {
            user_id: "previous-key-user".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["previous-key-audit".into()],
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            issued_at: chrono::Utc::now(),
            ..Default::default()
        });
        let encoded = provider.encode(&token)?;
        let previous = provider.active()?.primary.clone();
        let mut corrupt_primary = previous.clone();
        corrupt_primary.public_key_der = vec![0];
        provider.active = Some(ActiveKeys {
            primary: corrupt_primary,
            previous: Some(previous),
        });

        let decoded = provider.decode(&encoded)?;
        assert!(matches!(
            decoded,
            TokenPayload::Unscoped(payload) if payload.user_id == "previous-key-user"
        ));
        Ok(())
    }
}
