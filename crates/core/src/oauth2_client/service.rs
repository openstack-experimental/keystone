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
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::oauth2_client::*;
use openstack_keystone_core_types::oauth2_session::RefreshTokenRevocationReason;

use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
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
pub(crate) const RESERVED_CLAIM_NAMES: &[&str] = &[
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

/// Build the audit event for an operation on one client registration. The
/// payload carries IDs only, never the secret or its hash.
fn oauth2_client_event(operation: Operation, domain_id: &str, provider_id: &str) -> Event {
    Event::new(
        operation,
        EventPayload::Oauth2Client {
            domain_id: domain_id.to_string(),
            provider_id: provider_id.to_string(),
        },
    )
}

fn validate_claims_template(
    claims_template: &std::collections::HashMap<String, String>,
) -> Result<(), Oauth2ClientProviderError> {
    for (key, template) in claims_template {
        if RESERVED_CLAIM_NAMES.contains(&key.as_str()) {
            return Err(Oauth2ClientProviderError::Validation(format!(
                "claims_template key `{key}` collides with a reserved claim name"
            )));
        }
        super::id_token::validate_template(template).map_err(|reason| {
            Oauth2ClientProviderError::Validation(format!(
                "claims_template value for `{key}` is invalid: {reason}"
            ))
        })?;
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

const NAME_MAX_CHARS: usize = 128;
const DESCRIPTION_MAX_CHARS: usize = 1024;
const URI_MAX_CHARS: usize = 2048;
const CONTACTS_MAX: usize = 10;
const CONTACT_MAX_CHARS: usize = 256;

/// Validate a display name (RFC 7591 `client_name`): 1-128 characters, no
/// control characters.
fn validate_name(name: &str) -> Result<(), Oauth2ClientProviderError> {
    let len = name.trim().chars().count();
    if len == 0 || name.chars().count() > NAME_MAX_CHARS || name.chars().any(char::is_control) {
        return Err(Oauth2ClientProviderError::Validation(format!(
            "name must be 1-{NAME_MAX_CHARS} characters without control characters"
        )));
    }
    Ok(())
}

/// Validate a display `*_uri` field: an absolute `https://` URL without
/// embedded credentials. An empty string (clearing the field on update) is
/// accepted.
fn validate_https_uri(field: &str, uri: &str) -> Result<(), Oauth2ClientProviderError> {
    if uri.is_empty() {
        return Ok(());
    }
    let invalid =
        |reason: &str| Oauth2ClientProviderError::Validation(format!("{field} `{uri}` {reason}"));
    if uri.chars().count() > URI_MAX_CHARS {
        return Err(invalid("is too long"));
    }
    let parsed = url::Url::parse(uri).map_err(|_| invalid("is not a valid URL"))?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() {
        return Err(invalid("must be an https:// URL"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid("must not contain credentials"));
    }
    Ok(())
}

/// Validate the user-facing registration metadata. `name` is `None` on an
/// update that leaves it unchanged.
fn validate_display(
    name: Option<&str>,
    description: Option<&str>,
    logo_uri: Option<&str>,
    policy_uri: Option<&str>,
    tos_uri: Option<&str>,
    contacts: Option<&[String]>,
) -> Result<(), Oauth2ClientProviderError> {
    if let Some(name) = name {
        validate_name(name)?;
    }
    if let Some(description) = description
        && (description.chars().count() > DESCRIPTION_MAX_CHARS
            || description.chars().any(|c| c.is_control() && c != '\n'))
    {
        return Err(Oauth2ClientProviderError::Validation(format!(
            "description must be at most {DESCRIPTION_MAX_CHARS} characters"
        )));
    }
    for (field, value) in [
        ("logo_uri", logo_uri),
        ("policy_uri", policy_uri),
        ("tos_uri", tos_uri),
    ] {
        if let Some(value) = value {
            validate_https_uri(field, value)?;
        }
    }
    if let Some(contacts) = contacts {
        if contacts.len() > CONTACTS_MAX {
            return Err(Oauth2ClientProviderError::Validation(format!(
                "at most {CONTACTS_MAX} contacts are allowed"
            )));
        }
        if contacts.iter().any(|c| {
            c.trim().is_empty()
                || c.chars().count() > CONTACT_MAX_CHARS
                || c.chars().any(char::is_control)
        }) {
            return Err(Oauth2ClientProviderError::Validation(format!(
                "each contact must be 1-{CONTACT_MAX_CHARS} characters without control characters"
            )));
        }
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
    #[tracing::instrument(name = "provider.oauth2_client.create", level = "debug", skip_all)]
    async fn create<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        data: OAuth2ClientResourceCreate,
        confidential: bool,
    ) -> Result<(OAuth2ClientResource, Option<String>), Oauth2ClientProviderError> {
        validate_redirect_uris(&data.redirect_uris, confidential)?;
        validate_require_pkce(data.require_pkce, confidential)?;
        validate_claims_template(&data.claims_template)?;
        validate_display(
            Some(&data.name),
            data.description.as_deref(),
            data.logo_uri.as_deref(),
            data.policy_uri.as_deref(),
            data.tos_uri.as_deref(),
            Some(&data.contacts),
        )?;

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

        let event = oauth2_client_event(Operation::Create, &data.domain_id, &data.provider_id);
        let op = async { self.backend_driver.create(ctx.state(), data).await };
        let created = crate::audited_if_ctx! {
            ctx: ctx,
            event: event,
            operation: op,
            on_audit_error: |_: AuditDispatchError| Oauth2ClientProviderError::AuditUnavailable,
        }?;
        Ok((created, plaintext_secret))
    }

    #[tracing::instrument(name = "provider.oauth2_client.delete", level = "debug", skip_all, fields(domain_id = %domain_id, provider_id = %provider_id))]
    async fn delete<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
    ) -> Result<(OAuth2ClientResource, usize), Oauth2ClientProviderError> {
        let op = async {
            let deleted = self
                .backend_driver
                .delete(ctx.state(), domain_id, provider_id)
                .await?;
            let revoked = revoke_client_families(ctx, &deleted.client_id).await?;
            Ok::<_, Oauth2ClientProviderError>((deleted, revoked))
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: oauth2_client_event(Operation::Delete, domain_id, provider_id),
            operation: op,
            on_audit_error: |_: AuditDispatchError| Oauth2ClientProviderError::AuditUnavailable,
        }
    }

    #[tracing::instrument(name = "provider.oauth2_client.get", level = "debug", skip_all, fields(domain_id = %domain_id, provider_id = %provider_id))]
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

    #[tracing::instrument(name = "provider.oauth2_client.get_by_client_id", level = "debug", skip_all, fields(client_id = %client_id))]
    async fn get_by_client_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        client_id: &'a str,
    ) -> Result<Option<OAuth2ClientResource>, Oauth2ClientProviderError> {
        self.backend_driver
            .get_by_client_id(ctx.state(), client_id)
            .await
    }

    #[tracing::instrument(name = "provider.oauth2_client.list", level = "debug", skip_all, fields(params = ?params))]
    async fn list<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &OAuth2ClientResourceListParameters,
    ) -> Result<Vec<OAuth2ClientResource>, Oauth2ClientProviderError> {
        self.backend_driver.list(ctx.state(), params).await
    }

    #[tracing::instrument(name = "provider.oauth2_client.rotate_secret", level = "debug", skip_all, fields(domain_id = %domain_id, provider_id = %provider_id))]
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
        let op = async {
            self.backend_driver
                .rotate_secret(ctx.state(), domain_id, provider_id, hash)
                .await
        };
        let updated = crate::audited_if_ctx! {
            ctx: ctx,
            event: oauth2_client_event(
                Operation::Other("rotate_secret".to_string()),
                domain_id,
                provider_id,
            ),
            operation: op,
            on_audit_error: |_: AuditDispatchError| Oauth2ClientProviderError::AuditUnavailable,
        }?;
        Ok((updated, secret.expose_secret().to_string()))
    }

    #[tracing::instrument(name = "provider.oauth2_client.update", level = "debug", skip_all, fields(domain_id = %domain_id, provider_id = %provider_id))]
    async fn update<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        provider_id: &'a str,
        data: OAuth2ClientResourceUpdate,
    ) -> Result<(OAuth2ClientResource, usize), Oauth2ClientProviderError> {
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
        validate_display(
            data.name.as_deref(),
            data.description.as_deref(),
            data.logo_uri.as_deref(),
            data.policy_uri.as_deref(),
            data.tos_uri.as_deref(),
            data.contacts.as_deref(),
        )?;

        // Revoke on every explicit disable, not only on the enabled ->
        // disabled transition: revocation is idempotent, and gating on the
        // transition would make a retry after a failed revocation (the
        // client is already disabled by then) a silent no-op.
        let disabling = data.enabled == Some(false);

        let op = async {
            let updated = self
                .backend_driver
                .update(ctx.state(), domain_id, provider_id, data)
                .await?;
            // A disabled client must not keep live refresh families.
            let revoked = if disabling {
                revoke_client_families(ctx, &updated.client_id).await?
            } else {
                0
            };
            Ok::<_, Oauth2ClientProviderError>((updated, revoked))
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: oauth2_client_event(
                if disabling { Operation::Disable } else { Operation::Update },
                domain_id,
                provider_id,
            ),
            operation: op,
            on_audit_error: |_: AuditDispatchError| Oauth2ClientProviderError::AuditUnavailable,
        }
    }
}

/// Tombstone every refresh token family of `client_id` (reason
/// `client_revoked`) and return how many were revoked. Pending device
/// grants and pre-auth sessions are not purged here: they are short-lived,
/// re-validate the client at redemption and are removed by the janitor.
async fn revoke_client_families<'a>(
    ctx: &ExecutionContext<'a>,
    client_id: &str,
) -> Result<usize, Oauth2ClientProviderError> {
    ctx.state()
        .provider
        .get_oauth2_session_provider()
        .revoke_refresh_token_families_by_client(
            ctx.state(),
            client_id,
            RefreshTokenRevocationReason::ClientRevoked,
        )
        .await
        .map_err(|e| Oauth2ClientProviderError::FamilyRevocation(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2_client::backend::MockOauth2ClientBackend;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;
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
            name: "Test client".into(),
            description: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
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
    async fn test_create_rejects_invalid_display_metadata() {
        let service = service_with(MockOauth2ClientBackend::new());
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        type Mutation = Box<dyn Fn(&mut OAuth2ClientResourceCreate)>;
        let cases: Vec<Mutation> = vec![
            Box::new(|r| r.name = String::new()),
            Box::new(|r| r.name = "   ".into()),
            Box::new(|r| r.name = "x".repeat(129)),
            Box::new(|r| r.name = "bad\nname".into()),
            Box::new(|r| r.logo_uri = Some("http://rp.example.com/logo.png".into())),
            Box::new(|r| r.policy_uri = Some("javascript:alert(1)".into())),
            Box::new(|r| r.tos_uri = Some("https://user:pw@rp.example.com/tos".into())),
            Box::new(|r| r.tos_uri = Some("not a url".into())),
            Box::new(|r| r.description = Some("d".repeat(1025))),
            Box::new(|r| r.contacts = vec![String::new()]),
            Box::new(|r| r.contacts = vec!["a@example.com".into(); 11]),
        ];
        for (i, mutate) in cases.iter().enumerate() {
            let mut req = sample_create();
            mutate(&mut req);
            assert!(
                matches!(
                    service.create(&ctx, req, true).await,
                    Err(Oauth2ClientProviderError::Validation(_))
                ),
                "case {i} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn test_create_accepts_display_metadata() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_create()
            .returning(|_, data| Ok(sample_resource_from(data)));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        let mut req = sample_create();
        req.logo_uri = Some("https://rp.example.com/logo.png".into());
        req.policy_uri = Some("https://rp.example.com/privacy".into());
        req.tos_uri = Some("https://rp.example.com/tos".into());
        req.description = Some("An app".into());
        req.contacts = vec!["ops@example.com".into()];
        let (created, _) = service.create(&ctx, req, true).await.unwrap();
        assert_eq!(created.name, "Test client");
        assert_eq!(
            created.logo_uri.as_deref(),
            Some("https://rp.example.com/logo.png")
        );
        assert_eq!(created.contacts, vec!["ops@example.com".to_string()]);
    }

    #[tokio::test]
    async fn test_update_rejects_invalid_display_metadata() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_get()
            .returning(|_, _, _| Ok(Some(sample_resource_from(sample_create()))));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        for update in [
            OAuth2ClientResourceUpdate {
                name: Some(String::new()),
                ..Default::default()
            },
            OAuth2ClientResourceUpdate {
                logo_uri: Some("http://rp.example.com/logo.png".into()),
                ..Default::default()
            },
        ] {
            assert!(matches!(
                service.update(&ctx, "domain-1", "provider-1", update).await,
                Err(Oauth2ClientProviderError::Validation(_))
            ));
        }
    }

    #[test]
    fn test_with_update_sets_and_clears_display_metadata() {
        let mut client = sample_resource_from(sample_create());
        client.logo_uri = Some("https://rp.example.com/logo.png".into());
        let updated = client.with_update(
            OAuth2ClientResourceUpdate {
                name: Some("Renamed".into()),
                logo_uri: Some(String::new()),
                tos_uri: Some("https://rp.example.com/tos".into()),
                ..Default::default()
            },
            5,
        );
        assert_eq!(updated.name, "Renamed");
        assert_eq!(updated.logo_uri, None);
        assert_eq!(
            updated.tos_uri.as_deref(),
            Some("https://rp.example.com/tos")
        );
    }

    #[test]
    fn test_display_name_falls_back_to_provider_id() {
        let mut client = sample_resource_from(sample_create());
        client.name = String::new();
        assert_eq!(client.display_name(), "provider-1");
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

    async fn state_with_session(mock: MockOauth2SessionProvider) -> crate::keystone::ServiceState {
        get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_oauth2_session(mock)),
        )
        .await
    }

    #[tokio::test]
    async fn test_delete_revokes_client_families() {
        let mut backend = MockOauth2ClientBackend::new();
        backend.expect_delete().returning(|_, _, _| {
            Ok(OAuth2ClientResource {
                enabled: false,
                deleted_at: Some(1),
                ..sample_resource_from(sample_create())
            })
        });
        let mut session = MockOauth2SessionProvider::new();
        session
            .expect_revoke_refresh_token_families_by_client()
            .withf(|_, client_id, reason| {
                client_id == "client-1" && *reason == RefreshTokenRevocationReason::ClientRevoked
            })
            .times(1)
            .returning(|_, _, _| Ok(3));
        let service = service_with(backend);
        let state = state_with_session(session).await;
        let ctx = ExecutionContext::internal(&state);

        let (deleted, revoked) = service
            .delete(&ctx, "domain-1", "provider-1")
            .await
            .unwrap();
        assert!(deleted.deleted_at.is_some());
        assert_eq!(revoked, 3);
    }

    #[tokio::test]
    async fn test_delete_propagates_revocation_failure() {
        let mut backend = MockOauth2ClientBackend::new();
        backend
            .expect_delete()
            .returning(|_, _, _| Ok(sample_resource_from(sample_create())));
        let mut session = MockOauth2SessionProvider::new();
        session
            .expect_revoke_refresh_token_families_by_client()
            .returning(|_, _, _| {
                Err(crate::oauth2_session::Oauth2SessionProviderError::RaftNotAvailable)
            });
        let service = service_with(backend);
        let state = state_with_session(session).await;
        let ctx = ExecutionContext::internal(&state);

        let result = service.delete(&ctx, "domain-1", "provider-1").await;
        assert!(matches!(
            result,
            Err(Oauth2ClientProviderError::FamilyRevocation(_))
        ));
    }

    #[tokio::test]
    async fn test_update_disable_revokes_client_families() {
        let mut backend = MockOauth2ClientBackend::new();
        backend
            .expect_get()
            .returning(|_, _, _| Ok(Some(sample_resource_from(sample_create()))));
        backend.expect_update().returning(|_, _, _, _| {
            Ok(OAuth2ClientResource {
                enabled: false,
                ..sample_resource_from(sample_create())
            })
        });
        let mut session = MockOauth2SessionProvider::new();
        session
            .expect_revoke_refresh_token_families_by_client()
            .withf(|_, client_id, reason| {
                client_id == "client-1" && *reason == RefreshTokenRevocationReason::ClientRevoked
            })
            .times(1)
            .returning(|_, _, _| Ok(2));
        let service = service_with(backend);
        let state = state_with_session(session).await;
        let ctx = ExecutionContext::internal(&state);

        let (updated, revoked) = service
            .update(
                &ctx,
                "domain-1",
                "provider-1",
                OAuth2ClientResourceUpdate {
                    enabled: Some(false),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(!updated.enabled);
        assert_eq!(revoked, 2);
    }

    #[tokio::test]
    async fn test_update_without_disable_does_not_revoke() {
        let mut backend = MockOauth2ClientBackend::new();
        backend
            .expect_get()
            .returning(|_, _, _| Ok(Some(sample_resource_from(sample_create()))));
        backend
            .expect_update()
            .returning(|_, _, _, _| Ok(sample_resource_from(sample_create())));
        // No expectation on the session provider: mockall panics on call.
        let service = service_with(backend);
        let state = state_with_session(MockOauth2SessionProvider::new()).await;
        let ctx = ExecutionContext::internal(&state);

        let (_, revoked) = service
            .update(
                &ctx,
                "domain-1",
                "provider-1",
                OAuth2ClientResourceUpdate {
                    enabled: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(revoked, 0);
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
            name: data.name,
            description: data.description,
            logo_uri: data.logo_uri,
            policy_uri: data.policy_uri,
            tos_uri: data.tos_uri,
            contacts: data.contacts,
        }
    }

    // ---- audit (ADR 0023): fail-closed around the provider operation ----

    #[tokio::test]
    async fn test_create_with_security_context_records_attempt_and_success() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_create()
            .returning(|_, data| Ok(sample_resource_from(data)));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;
        let hook = crate::tests::RecordingAuditHook::new();
        state.event_dispatcher.subscribe_audit(hook.clone()).await;
        let vsc = crate::tests::test_vsc();
        let ctx = ExecutionContext::from_auth(&state, &vsc);

        service.create(&ctx, sample_create(), true).await.unwrap();

        assert_eq!(hook.outcomes(), ["Attempt", "Success"]);
        let (operation, payload, _) = &hook.seen()[0];
        assert_eq!(operation, "Create");
        assert!(payload.contains("Oauth2Client"), "{payload}");
        assert!(payload.contains("provider-1"), "{payload}");
        assert!(!payload.contains("kosc_"), "secret leaked: {payload}");
        assert!(!payload.contains("argon2"), "hash leaked: {payload}");
    }

    #[tokio::test]
    async fn test_delete_failure_is_recorded_with_static_reason() {
        let mut backend = MockOauth2ClientBackend::new();
        backend
            .expect_delete()
            .returning(|_, _, _| Err(Oauth2ClientProviderError::NotFound("provider-1".into())));
        let service = service_with(backend);
        let state = get_mocked_state(None, None).await;
        let hook = crate::tests::RecordingAuditHook::new();
        state.event_dispatcher.subscribe_audit(hook.clone()).await;
        let vsc = crate::tests::test_vsc();
        let ctx = ExecutionContext::from_auth(&state, &vsc);

        assert!(
            service
                .delete(&ctx, "domain-1", "provider-1")
                .await
                .is_err()
        );

        let outcomes = hook.outcomes();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0], "Attempt");
        assert!(outcomes[1].contains("NotFound"), "{outcomes:?}");
        assert!(!outcomes[1].contains("provider-1"), "{outcomes:?}");
    }

    #[tokio::test]
    async fn test_create_fails_closed_when_the_pre_audit_is_refused() {
        // No `expect_create`: the backend must not be reached.
        let service = service_with(MockOauth2ClientBackend::new());
        let state = get_mocked_state(None, None).await;
        let hook = crate::tests::RecordingAuditHook::refusing();
        state.event_dispatcher.subscribe_audit(hook.clone()).await;
        let vsc = crate::tests::test_vsc();
        let ctx = ExecutionContext::from_auth(&state, &vsc);

        let err = service
            .create(&ctx, sample_create(), true)
            .await
            .unwrap_err();

        assert!(matches!(err, Oauth2ClientProviderError::AuditUnavailable));
        assert!(hook.seen().is_empty());
    }
}
