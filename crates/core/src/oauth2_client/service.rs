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
//! # OAuth2 client (relying party registration) provider (ADR 0026 §5)

use std::sync::Arc;

use async_trait::async_trait;
use secrecy::ExposeSecret;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::oauth2_client::*;

use crate::auth::ExecutionContext;
use crate::oauth2_client::backend::Oauth2ClientBackend;
use crate::oauth2_client::crypto;
use crate::oauth2_client::{Oauth2ClientApi, Oauth2ClientProviderError};
use crate::plugin_manager::PluginManagerApi;

/// The only backend name registered for the OAuth2 client provider: like
/// `[oauth2]`'s signing key provider, there is no alternative driver to
/// select between.
const BACKEND_NAME: &str = "raft";

/// Output claim names reserved by `IdTokenClaims`, `OpenStackContext`, and
/// `OpenStackScope` (ADR 0026 §4, "Claim Safety"). A `claims_template` key
/// colliding with one of these is rejected at save time so a client cannot
/// override a baseline claim via `#[serde(flatten)]`.
const RESERVED_CLAIM_NAMES: &[&str] = &[
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "nbf",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "at_hash",
    "c_hash",
    "azp",
    "jti",
    "client_id",
    "keystone_ruleset_version",
    "delegation_context",
    "auth_method",
    "delegated_project_id",
    "token_use",
    "openstack_context",
    "user_id",
    "user_name",
    "user_domain_id",
    "scope_type",
    "project_id",
    "project_domain_id",
    "domain_id",
    "system_id",
    "roles",
];

fn validate_claims_template(
    claims_template: &std::collections::HashMap<String, String>,
) -> Result<(), Oauth2ClientProviderError> {
    for key in claims_template.keys() {
        if RESERVED_CLAIM_NAMES.contains(&key.as_str()) {
            return Err(Oauth2ClientProviderError::Validation(format!(
                "claims_template key `{key}` collides with a reserved claim name"
            )));
        }
    }
    Ok(())
}

/// Validate redirect URI scheme rules (ADR 0026 §5): confidential clients
/// must use `https://` only; public clients may additionally use
/// `http://localhost:*` (logged once, not rejected).
fn validate_redirect_uris(
    redirect_uris: &[String],
    confidential: bool,
) -> Result<(), Oauth2ClientProviderError> {
    for uri in redirect_uris {
        if uri.starts_with("https://") {
            continue;
        }
        if !confidential && uri.starts_with("http://localhost") {
            tracing::warn!(
                redirect_uri = %uri,
                "public OAuth2 client registered with an http://localhost redirect URI"
            );
            continue;
        }
        return Err(Oauth2ClientProviderError::Validation(format!(
            "redirect_uri `{uri}` must use https:// ({}; public clients may additionally use http://localhost:*)",
            if confidential {
                "confidential client"
            } else {
                "public client"
            }
        )));
    }
    Ok(())
}

/// Validate the PKCE requirement (ADR 0026 §5): mandatory for public
/// clients.
fn validate_require_pkce(
    require_pkce: bool,
    confidential: bool,
) -> Result<(), Oauth2ClientProviderError> {
    if !confidential && !require_pkce {
        return Err(Oauth2ClientProviderError::Validation(
            "require_pkce must be true for a public client (no client_secret)".to_string(),
        ));
    }
    Ok(())
}

/// OAuth2 client Provider.
pub struct Oauth2ClientService {
    /// Backend driver.
    backend_driver: Arc<dyn Oauth2ClientBackend>,
    /// `[oauth2]` config, for client secret Argon2id parameters.
    oauth2_config: openstack_keystone_config::Oauth2Provider,
}

impl Oauth2ClientService {
    /// Create a new `Oauth2ClientService`.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, Oauth2ClientProviderError> {
        let backend_driver = plugin_manager
            .get_oauth2_client_backend(BACKEND_NAME)?
            .clone();
        Ok(Self {
            backend_driver,
            oauth2_config: config.oauth2.clone(),
        })
    }
}

#[async_trait]
impl Oauth2ClientApi for Oauth2ClientService {
    async fn create<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        data: OAuth2ClientResourceCreate,
        confidential: bool,
    ) -> Result<(OAuth2ClientResource, Option<String>), Oauth2ClientProviderError> {
        validate_redirect_uris(&data.redirect_uris, confidential)?;
        validate_require_pkce(data.require_pkce, confidential)?;
        validate_claims_template(&data.claims_template)?;

        let mut data = data;
        data.client_id = uuid::Uuid::new_v4().to_string();

        let plaintext_secret = if confidential {
            let secret = crypto::generate_secret();
            data.client_secret_hash =
                Some(crypto::hash_secret(&secret, &self.oauth2_config).await?);
            Some(secret.expose_secret().to_string())
        } else {
            data.client_secret_hash = None;
            None
        };

        let created = self.backend_driver.create(ctx.state(), data).await?;
        Ok((created, plaintext_secret))
    }

    async fn delete<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError> {
        self.backend_driver
            .delete(ctx.state(), domain_id, provider_id)
            .await
    }

    async fn get<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<Option<OAuth2ClientResource>, Oauth2ClientProviderError> {
        self.backend_driver
            .get(ctx.state(), domain_id, provider_id)
            .await
    }

    async fn get_by_client_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        client_id: &'a str,
    ) -> Result<Option<OAuth2ClientResource>, Oauth2ClientProviderError> {
        self.backend_driver
            .get_by_client_id(ctx.state(), client_id)
            .await
    }

    async fn list<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &OAuth2ClientResourceListParameters,
    ) -> Result<Vec<OAuth2ClientResource>, Oauth2ClientProviderError> {
        self.backend_driver.list(ctx.state(), params).await
    }

    async fn rotate_secret<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<(OAuth2ClientResource, String), Oauth2ClientProviderError> {
        let current = self
            .backend_driver
            .get(ctx.state(), domain_id, provider_id)
            .await?
            .ok_or_else(|| Oauth2ClientProviderError::NotFound(provider_id.to_string()))?;
        if current.deleted_at.is_some() {
            return Err(Oauth2ClientProviderError::Conflict(
                "cannot rotate a secret for a revoked (soft-deleted) OAuth2 client".to_string(),
            ));
        }
        if current.client_secret_hash.is_none() {
            return Err(Oauth2ClientProviderError::Validation(
                "cannot rotate a secret for a public client (no client_secret)".to_string(),
            ));
        }

        let secret = crypto::generate_secret();
        let hash = crypto::hash_secret(&secret, &self.oauth2_config).await?;
        let updated = self
            .backend_driver
            .rotate_secret(ctx.state(), domain_id, provider_id, hash)
            .await?;
        Ok((updated, secret.expose_secret().to_string()))
    }

    async fn update<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
        data: OAuth2ClientResourceUpdate,
    ) -> Result<OAuth2ClientResource, Oauth2ClientProviderError> {
        let current = self
            .backend_driver
            .get(ctx.state(), domain_id, provider_id)
            .await?
            .ok_or_else(|| Oauth2ClientProviderError::NotFound(provider_id.to_string()))?;
        // Soft-delete is the revocation path (mirrors ADR 0021 §5.C for
        // api_key) and MUST NOT be reversible or bypassable through the
        // ordinary update surface -- a revoked client must stay revoked.
        if current.deleted_at.is_some() {
            return Err(Oauth2ClientProviderError::Conflict(
                "cannot update a revoked (soft-deleted) OAuth2 client".to_string(),
            ));
        }
        let confidential = current.client_secret_hash.is_some();

        if let Some(redirect_uris) = &data.redirect_uris {
            validate_redirect_uris(redirect_uris, confidential)?;
        }
        let effective_pkce = data.require_pkce.unwrap_or(current.require_pkce);
        validate_require_pkce(effective_pkce, confidential)?;
        if let Some(claims_template) = &data.claims_template {
            validate_claims_template(claims_template)?;
        }

        self.backend_driver
            .update(ctx.state(), domain_id, provider_id, data)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2_client::backend::MockOauth2ClientBackend;
    use crate::tests::get_mocked_state;
    use std::collections::HashMap;

    fn sample_create() -> OAuth2ClientResourceCreate {
        OAuth2ClientResourceCreate {
            client_id: String::new(),
            provider_id: "provider-1".into(),
            domain_id: "domain-1".into(),
            client_secret_hash: None,
            redirect_uris: vec!["https://rp.example.com/callback".into()],
            token_endpoint_auth_method: "client_secret_basic".into(),
            grant_types: vec![GrantType::AuthorizationCode],
            require_pkce: true,
            allowed_scopes: vec!["openid".into()],
            pre_authorized: false,
            claims_template: HashMap::new(),
        }
    }

    fn service_with(mock: MockOauth2ClientBackend) -> Oauth2ClientService {
        Oauth2ClientService {
            backend_driver: Arc::new(mock),
            oauth2_config: openstack_keystone_config::Oauth2Provider {
                argon2_memory_kib: 8,
                argon2_time_cost: 1,
                argon2_parallelism: 1,
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn test_create_confidential_client_returns_plaintext_secret_once() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_create()
            .returning(|_, data| Ok(sample_resource_from(data)));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        let (created, secret) = service.create(&ctx, sample_create(), true).await.unwrap();
        assert!(created.client_secret_hash.is_some());
        assert!(secret.unwrap().starts_with("kosc_"));
    }

    #[tokio::test]
    async fn test_create_public_client_has_no_secret() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_create()
            .returning(|_, data| Ok(sample_resource_from(data)));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        let (created, secret) = service.create(&ctx, sample_create(), false).await.unwrap();
        assert!(created.client_secret_hash.is_none());
        assert!(secret.is_none());
    }

    #[tokio::test]
    async fn test_create_rejects_non_https_redirect_uri_for_confidential_client() {
        let service = service_with(MockOauth2ClientBackend::new());
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        let mut req = sample_create();
        req.redirect_uris = vec!["http://insecure.example.com/callback".into()];
        let result = service.create(&ctx, req, true).await;
        assert!(matches!(
            result,
            Err(Oauth2ClientProviderError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn test_create_rejects_public_client_without_pkce() {
        let service = service_with(MockOauth2ClientBackend::new());
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        let mut req = sample_create();
        req.require_pkce = false;
        let result = service.create(&ctx, req, false).await;
        assert!(matches!(
            result,
            Err(Oauth2ClientProviderError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn test_create_rejects_reserved_claims_template_key() {
        let service = service_with(MockOauth2ClientBackend::new());
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        let mut req = sample_create();
        req.claims_template
            .insert("sub".to_string(), "${user.id}".to_string());
        let result = service.create(&ctx, req, true).await;
        assert!(matches!(
            result,
            Err(Oauth2ClientProviderError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn test_rotate_secret_rejects_public_client() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_get().returning(|_, _, _| {
            Ok(Some(sample_resource_from(OAuth2ClientResourceCreate {
                client_secret_hash: None,
                ..sample_create()
            })))
        });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        let result = service.rotate_secret(&ctx, "domain-1", "provider-1").await;
        assert!(matches!(
            result,
            Err(Oauth2ClientProviderError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn test_rotate_secret_rejects_revoked_client() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_get().returning(|_, _, _| {
            Ok(Some(OAuth2ClientResource {
                deleted_at: Some(1),
                enabled: false,
                ..sample_resource_from(sample_create())
            }))
        });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        let result = service.rotate_secret(&ctx, "domain-1", "provider-1").await;
        assert!(matches!(
            result,
            Err(Oauth2ClientProviderError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn test_update_rejects_revoked_client() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_get().returning(|_, _, _| {
            Ok(Some(OAuth2ClientResource {
                deleted_at: Some(1),
                enabled: false,
                ..sample_resource_from(sample_create())
            }))
        });
        // `expect_update` deliberately not configured: mockall panics if
        // it's called, proving the guard short-circuits before reaching
        // the backend.
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        let result = service
            .update(
                &ctx,
                "domain-1",
                "provider-1",
                OAuth2ClientResourceUpdate {
                    enabled: Some(true),
                    ..Default::default()
                },
            )
            .await;
        assert!(matches!(
            result,
            Err(Oauth2ClientProviderError::Conflict(_))
        ));
    }

    fn sample_resource_from(data: OAuth2ClientResourceCreate) -> OAuth2ClientResource {
        OAuth2ClientResource {
            client_id: if data.client_id.is_empty() {
                "client-1".into()
            } else {
                data.client_id
            },
            provider_id: data.provider_id,
            domain_id: data.domain_id,
            client_secret_hash: data.client_secret_hash,
            redirect_uris: data.redirect_uris,
            token_endpoint_auth_method: data.token_endpoint_auth_method,
            grant_types: data.grant_types,
            require_pkce: data.require_pkce,
            allowed_scopes: data.allowed_scopes,
            pre_authorized: data.pre_authorized,
            enabled: true,
            claims_template: data.claims_template,
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }
}
