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
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
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
    "sid",
    "fid",
    "azp",
    "jti",
    "client_id",
    "keystone_ruleset_version",
    "delegation_context",
    "auth_method",
    "delegated_project_id",
    "act",
    "grant_id",
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

/// `provider_id` of the audit event for the per-domain settings, which are
/// not tied to one client registration.
const DOMAIN_SETTINGS_TARGET: &str = "domain-settings";

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

const POST_LOGOUT_URIS_MAX: usize = 10;

/// Validate `post_logout_redirect_uris`: at most 10, the same scheme rules as
/// `redirect_uris`, absolute, and neither credentials nor a fragment.
fn validate_post_logout_redirect_uris(
    uris: &[String],
    confidential: bool,
) -> Result<(), Oauth2ClientProviderError> {
    if uris.len() > POST_LOGOUT_URIS_MAX {
        return Err(Oauth2ClientProviderError::Validation(format!(
            "at most {POST_LOGOUT_URIS_MAX} post_logout_redirect_uris are allowed"
        )));
    }
    validate_redirect_uris(uris, confidential)?;
    for uri in uris {
        let parsed = url::Url::parse(uri).map_err(|_| {
            Oauth2ClientProviderError::Validation(format!(
                "post_logout_redirect_uri `{uri}` is not a valid URL"
            ))
        })?;
        if parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || uri.chars().count() > URI_MAX_CHARS
        {
            return Err(Oauth2ClientProviderError::Validation(format!(
                "post_logout_redirect_uri `{uri}` must not contain credentials or a fragment"
            )));
        }
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

/// Validate a logout endpoint registration: the URI (if any) must be a
/// plain `https://` URL and `session_required` needs an endpoint.
fn validate_logout_endpoint(
    field: &str,
    uri: Option<&str>,
    session_required: bool,
) -> Result<(), Oauth2ClientProviderError> {
    let uri = uri.filter(|u| !u.is_empty());
    if let Some(uri) = uri {
        validate_https_uri(field, uri)?;
    } else if session_required {
        return Err(Oauth2ClientProviderError::Validation(format!(
            "{field}_session_required requires {field}"
        )));
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

/// Token endpoint authentication method of delegatable service clients:
/// mutual TLS with a SPIFFE X.509-SVID (ADR 0036 §3.1).
pub const TLS_CLIENT_AUTH: &str = "tls_client_auth";

/// Upper bound on `delegation.max_role_ids`.
const MAX_DELEGATION_ROLE_IDS: usize = 64;

/// Validate the delegation registration of a client (ADR 0036 §3, §3.1) on
/// its effective state.
///
/// A client with `spiffe_ids` or a `delegation` policy must authenticate
/// with `tls_client_auth`; a delegation policy needs at least one SPIFFE ID
/// pattern; `on_behalf_of` needs `max_operation_lifetime`.
///
/// Patterns are checked against `trust_domains` (the internal interface's
/// trust domains, i.e. the deployment's own) only when `check_patterns` is
/// set, i.e. when the write changes them. Otherwise a later change of the
/// deployment's trust domains would block every edit of a stored client,
/// including disabling it.
fn validate_delegation(
    token_endpoint_auth_method: &str,
    spiffe_ids: &[String],
    delegation: Option<&DelegationPolicy>,
    trust_domains: &[String],
    check_patterns: bool,
) -> Result<(), Oauth2ClientProviderError> {
    let validation = |msg: String| Oauth2ClientProviderError::Validation(msg);
    if (delegation.is_some() || !spiffe_ids.is_empty())
        && token_endpoint_auth_method != TLS_CLIENT_AUTH
    {
        return Err(validation(format!(
            "spiffe_ids and delegation require token_endpoint_auth_method `{TLS_CLIENT_AUTH}`"
        )));
    }
    if token_endpoint_auth_method == TLS_CLIENT_AUTH && spiffe_ids.is_empty() {
        return Err(validation(format!(
            "token_endpoint_auth_method `{TLS_CLIENT_AUTH}` requires spiffe_ids"
        )));
    }
    if check_patterns {
        for pattern in spiffe_ids {
            validate_spiffe_id_pattern(pattern, trust_domains).map_err(validation)?;
        }
    }
    if let Some(delegation) = delegation {
        if delegation.on_behalf_of && delegation.max_operation_lifetime.is_none() {
            return Err(validation(
                "delegation.on_behalf_of requires delegation.max_operation_lifetime".to_string(),
            ));
        }
        if delegation.max_grant_lifetime == Some(0)
            || delegation.max_operation_lifetime == Some(0)
            || delegation.max_grants_per_project == Some(0)
        {
            return Err(validation(
                "delegation lifetimes and limits must be positive".to_string(),
            ));
        }
        if delegation.max_role_ids.len() > MAX_DELEGATION_ROLE_IDS {
            return Err(validation(format!(
                "delegation.max_role_ids must not have more than {MAX_DELEGATION_ROLE_IDS} entries"
            )));
        }
        if delegation.max_role_ids.iter().any(|r| r.trim().is_empty()) {
            return Err(validation(
                "delegation.max_role_ids must not contain empty ids".to_string(),
            ));
        }
    }
    Ok(())
}

/// Reject `max_role_ids` entries that are not existing roles (ADR 0036
/// §3): a ceiling naming a role that does not exist would silently
/// delegate less than the registrant meant (a typo, or a role later
/// recreated under another id).
///
/// Ids in `unchanged` (the stored ceiling) are skipped: a role deleted
/// since registration must not block an edit that leaves it in place.
async fn ensure_roles_exist(
    ctx: &ExecutionContext<'_>,
    delegation: Option<&DelegationPolicy>,
    unchanged: &[String],
) -> Result<(), Oauth2ClientProviderError> {
    let Some(delegation) = delegation else {
        return Ok(());
    };
    let roles = ctx.state().provider.get_role_provider();
    // One lookup per role, concurrently: the ceiling holds up to 64 ids.
    let ids: Vec<&String> = delegation
        .max_role_ids
        .iter()
        .filter(|id| !unchanged.contains(id))
        .collect();
    let found = futures_util::future::try_join_all(ids.iter().map(|id| roles.get_role(ctx, id)))
        .await
        .map_err(|e| Oauth2ClientProviderError::Dependency(e.to_string()))?;
    if let Some((role_id, _)) = ids.iter().zip(found).find(|(_, role)| role.is_none()) {
        return Err(Oauth2ClientProviderError::Validation(format!(
            "delegation.max_role_ids names an unknown role: {role_id}"
        )));
    }
    Ok(())
}

/// A `tls_client_auth` client has no secret and is exempt from the PKCE
/// rule, so it must not use the browser and device grants, which rely on
/// one of the two to bind the code to the client. Without those grants,
/// redirect URIs are meaningless.
fn validate_mtls_client(
    grant_types: &[GrantType],
    redirect_uris: &[String],
) -> Result<(), Oauth2ClientProviderError> {
    if !redirect_uris.is_empty() {
        return Err(Oauth2ClientProviderError::Validation(format!(
            "a `{TLS_CLIENT_AUTH}` client cannot have redirect_uris"
        )));
    }
    if grant_types
        .iter()
        .any(|g| matches!(g, GrantType::AuthorizationCode | GrantType::DeviceCode))
    {
        return Err(Oauth2ClientProviderError::Validation(format!(
            "a `{TLS_CLIENT_AUTH}` client cannot use the authorization_code or device_code grant"
        )));
    }
    Ok(())
}

/// SPIFFE trust domains of the internal interface, the only interface a
/// delegatable service authenticates on. Empty when the interface is not
/// configured with a SPIFFE listener.
fn internal_trust_domains(config: &Config) -> Vec<String> {
    match config.interface_internal.as_ref().map(|i| &i.listener) {
        Some(openstack_keystone_config::ListenerConfig::Spiffe(spiffe)) => {
            spiffe.trust_domains.clone()
        }
        _ => Vec::new(),
    }
}

/// First of `candidates` overlapping a pattern of a different live client.
///
/// The message names the holder: a client whose domain is gone is invisible
/// to the per-domain listing, so this is the only way to find it to delete it.
fn find_spiffe_conflict(
    candidates: &[String],
    existing: &[OAuth2ClientResource],
    own: Option<(&str, &str)>,
) -> Option<String> {
    existing
        .iter()
        .filter(|c| own != Some((c.domain_id.as_str(), c.provider_id.as_str())))
        .find_map(|c| {
            c.spiffe_ids.iter().find_map(|theirs| {
                candidates
                    .iter()
                    .find(|mine| spiffe_id_patterns_overlap(mine, theirs))
                    .map(|mine| {
                        format!(
                            "spiffe_ids pattern `{mine}` overlaps `{theirs}` of client `{}` in domain `{}`",
                            c.provider_id, c.domain_id
                        )
                    })
            })
        })
}

/// How long the DPoP mode of a domain is reused before the stored settings
/// are read again. The mode is read on every `/token` request, so without
/// this every request would cost a storage read, also where DPoP is not in
/// use. A change made on this node takes effect at once (the entry is
/// dropped); one made on another node is seen within this time. A domain
/// that raises its mode is therefore enforced everywhere within a few
/// seconds, and one that lowers it keeps the stricter value for as long.
const DOMAIN_MODE_CACHE_TTL: Duration = Duration::from_secs(5);

/// Bound on the cached domains. The entries of domains that were looked up
/// once and never again are not worth tracking: past the bound the cache is
/// emptied and refills from the requests that follow.
const DOMAIN_MODE_CACHE_MAX_ENTRIES: usize = 10_000;

/// OAuth2 client Provider.
pub struct Oauth2ClientService {
    /// Backend driver.
    backend_driver: Arc<dyn Oauth2ClientBackend>,
    /// `[oauth2]` config, for client secret Argon2id parameters.
    oauth2_config: openstack_keystone_config::Oauth2Provider,
    /// Trust domains SPIFFE ID patterns may name (ADR 0036 §3.1).
    internal_trust_domains: Vec<String>,
    /// Domain DPoP mode by domain id, with the time it was read.
    domain_dpop_modes: DashMap<String, (openstack_keystone_config::DpopMode, Instant)>,
    /// Per domain, bumped on every settings write to it. A reader that
    /// started its backend lookup before a write must not cache what it
    /// read: the value may be the one the write just replaced. Per domain, so
    /// writes to one do not discard what readers of the others just cached;
    /// holds only domains that were written to.
    domain_dpop_epochs: DashMap<String, u64>,
}

impl Oauth2ClientService {
    /// Forget the cached DPoP mode of a domain after a settings write.
    fn invalidate_domain_dpop_mode(&self, domain_id: &str) {
        *self
            .domain_dpop_epochs
            .entry(domain_id.to_string())
            .or_insert(0) += 1;
        self.domain_dpop_modes.remove(domain_id);
    }

    /// The write generation of the settings of a domain.
    fn domain_dpop_epoch(&self, domain_id: &str) -> u64 {
        self.domain_dpop_epochs
            .get(domain_id)
            .map_or(0, |epoch| *epoch)
    }

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
            internal_trust_domains: internal_trust_domains(config),
            domain_dpop_modes: DashMap::new(),
            domain_dpop_epochs: DashMap::new(),
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
        validate_delegation(
            &data.token_endpoint_auth_method,
            &data.spiffe_ids,
            data.delegation.as_ref(),
            &self.internal_trust_domains,
            true,
        )?;
        ensure_roles_exist(ctx, data.delegation.as_ref(), &[]).await?;
        // A `tls_client_auth` client authenticates with its SVID: it never
        // gets a secret and is exempt from the PKCE rule.
        let mtls = data.token_endpoint_auth_method == TLS_CLIENT_AUTH;
        let confidential = confidential && !mtls;
        validate_redirect_uris(&data.redirect_uris, confidential)?;
        if mtls {
            validate_mtls_client(&data.grant_types, &data.redirect_uris)?;
        } else {
            validate_require_pkce(data.require_pkce, confidential)?;
        }
        validate_post_logout_redirect_uris(&data.post_logout_redirect_uris, confidential)?;
        validate_logout_endpoint(
            "backchannel_logout_uri",
            data.backchannel_logout_uri.as_deref(),
            data.backchannel_logout_session_required,
        )?;
        validate_logout_endpoint(
            "frontchannel_logout_uri",
            data.frontchannel_logout_uri.as_deref(),
            data.frontchannel_logout_session_required,
        )?;
        validate_claims_template(&data.claims_template)?;
        validate_display(
            Some(&data.name),
            data.description.as_deref(),
            data.logo_uri.as_deref(),
            data.policy_uri.as_deref(),
            data.tos_uri.as_deref(),
            Some(&data.contacts),
        )?;

        if !data.spiffe_ids.is_empty() {
            let existing = self.backend_driver.list_spiffe_clients(ctx.state()).await?;
            if let Some(msg) = find_spiffe_conflict(&data.spiffe_ids, &existing, None) {
                return Err(Oauth2ClientProviderError::Conflict(msg));
            }
        }

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
            // Remembered consents of a deleted client are of no use and would
            // keep showing up in the users' list of connected applications.
            ctx.state()
                .provider
                .get_oauth2_session_provider()
                .delete_consents_by_client(ctx.state(), &deleted.client_id)
                .await
                .map_err(|e| Oauth2ClientProviderError::FamilyRevocation(e.to_string()))?;
            Ok::<_, Oauth2ClientProviderError>((deleted, revoked))
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: oauth2_client_event(Operation::Delete, domain_id, provider_id),
            operation: op,
            on_audit_error: |_: AuditDispatchError| Oauth2ClientProviderError::AuditUnavailable,
        }
    }

    #[tracing::instrument(name = "provider.oauth2_client.delete_domain_settings", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn delete_domain_settings<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
    ) -> Result<(), Oauth2ClientProviderError> {
        let op = self
            .backend_driver
            .delete_domain_settings(ctx.state(), domain_id);
        let result = crate::audited_if_ctx! {
            ctx: ctx,
            event: oauth2_client_event(Operation::Delete, domain_id, DOMAIN_SETTINGS_TARGET),
            operation: op,
            on_audit_error: |_: AuditDispatchError| Oauth2ClientProviderError::AuditUnavailable,
        };
        self.invalidate_domain_dpop_mode(domain_id);
        result
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

    #[tracing::instrument(name = "provider.oauth2_client.effective_dpop_mode", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn effective_dpop_mode<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        client_bound_access_tokens: bool,
    ) -> Result<openstack_keystone_config::DpopMode, Oauth2ClientProviderError> {
        let global = self.oauth2_config.dpop;
        // Nothing can be stricter than `required`: skip the lookup.
        if global == openstack_keystone_config::DpopMode::Required || client_bound_access_tokens {
            return Ok(openstack_keystone_config::DpopMode::Required);
        }
        let cached = self
            .domain_dpop_modes
            .get(domain_id)
            .filter(|e| e.1.elapsed() < DOMAIN_MODE_CACHE_TTL)
            .map(|e| e.0);
        let domain = match cached {
            Some(mode) => mode,
            None => {
                let epoch = self.domain_dpop_epoch(domain_id);
                let mode = self
                    .backend_driver
                    .get_domain_settings(ctx.state(), domain_id)
                    .await?
                    .map(|s| s.dpop)
                    .unwrap_or_default();
                if self.domain_dpop_modes.len() >= DOMAIN_MODE_CACHE_MAX_ENTRIES {
                    self.domain_dpop_modes.clear();
                }
                self.domain_dpop_modes
                    .insert(domain_id.to_string(), (mode, Instant::now()));
                // A write raced with the lookup: what was just cached may be
                // stale. Insert-then-check pairs with the write's bump-then-
                // remove, so one of the two always drops the entry.
                if self.domain_dpop_epoch(domain_id) != epoch {
                    self.domain_dpop_modes.remove(domain_id);
                }
                mode
            }
        };
        Ok(super::dpop_mode::effective_dpop_mode(global, domain, false))
    }

    #[tracing::instrument(name = "provider.oauth2_client.get_domain_settings", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn get_domain_settings<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
    ) -> Result<OAuth2DomainSettings, Oauth2ClientProviderError> {
        Ok(self
            .backend_driver
            .get_domain_settings(ctx.state(), domain_id)
            .await?
            .unwrap_or_else(|| OAuth2DomainSettings::default_for(domain_id)))
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

    #[tracing::instrument(
        name = "provider.oauth2_client.list_delegatable",
        level = "debug",
        skip_all
    )]
    async fn list_delegatable<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
    ) -> Result<Vec<OAuth2ClientResource>, Oauth2ClientProviderError> {
        self.backend_driver.list_delegatable(ctx.state()).await
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
        let mtls = current.token_endpoint_auth_method == TLS_CLIENT_AUTH;
        if data.remove_delegation && data.delegation.is_some() {
            return Err(Oauth2ClientProviderError::Validation(
                "delegation and remove_delegation are mutually exclusive".to_string(),
            ));
        }
        validate_delegation(
            &current.token_endpoint_auth_method,
            data.spiffe_ids.as_deref().unwrap_or(&current.spiffe_ids),
            if data.remove_delegation {
                None
            } else {
                data.delegation.as_ref().or(current.delegation.as_ref())
            },
            &self.internal_trust_domains,
            data.spiffe_ids.is_some(),
        )?;
        // Only role ids this update adds are checked: one already in the
        // stored ceiling may name a role deleted since, which must not
        // block unrelated edits.
        if !data.remove_delegation {
            let stored = current
                .delegation
                .as_ref()
                .map_or(&[][..], |d| d.max_role_ids.as_slice());
            ensure_roles_exist(ctx, data.delegation.as_ref(), stored).await?;
        }
        if let Some(spiffe_ids) = data.spiffe_ids.as_deref().filter(|ids| !ids.is_empty()) {
            let existing = self.backend_driver.list_spiffe_clients(ctx.state()).await?;
            if let Some(msg) = find_spiffe_conflict(
                spiffe_ids,
                &existing,
                Some((&current.domain_id, &current.provider_id)),
            ) {
                return Err(Oauth2ClientProviderError::Conflict(msg));
            }
        }

        if let Some(redirect_uris) = &data.redirect_uris {
            validate_redirect_uris(redirect_uris, confidential)?;
        }
        // Validate the effective post-update state (`None` = unchanged,
        // empty string = clear).
        validate_logout_endpoint(
            "backchannel_logout_uri",
            data.backchannel_logout_uri
                .as_deref()
                .or(current.backchannel_logout_uri.as_deref()),
            data.backchannel_logout_session_required
                .unwrap_or(current.backchannel_logout_session_required),
        )?;
        validate_logout_endpoint(
            "frontchannel_logout_uri",
            data.frontchannel_logout_uri
                .as_deref()
                .or(current.frontchannel_logout_uri.as_deref()),
            data.frontchannel_logout_session_required
                .unwrap_or(current.frontchannel_logout_session_required),
        )?;
        if let Some(uris) = &data.post_logout_redirect_uris {
            validate_post_logout_redirect_uris(uris, confidential)?;
        }
        let effective_pkce = data.require_pkce.unwrap_or(current.require_pkce);
        if mtls {
            validate_mtls_client(
                data.grant_types.as_deref().unwrap_or(&current.grant_types),
                data.redirect_uris
                    .as_deref()
                    .unwrap_or(&current.redirect_uris),
            )?;
        } else {
            validate_require_pkce(effective_pkce, confidential)?;
        }
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

    #[tracing::instrument(name = "provider.oauth2_client.update_domain_settings", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn update_domain_settings<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        data: OAuth2DomainSettingsUpdate,
    ) -> Result<OAuth2DomainSettings, Oauth2ClientProviderError> {
        // Settings of an unknown domain would never be cleaned up: the
        // domain-delete hook only fires for domains that existed.
        if ctx
            .state()
            .provider
            .get_resource_provider()
            .get_domain(ctx, domain_id)
            .await
            .map_err(|e| Oauth2ClientProviderError::Dependency(e.to_string()))?
            .is_none()
        {
            return Err(Oauth2ClientProviderError::NotFound(format!(
                "domain {domain_id}"
            )));
        }
        let op = self
            .backend_driver
            .update_domain_settings(ctx.state(), domain_id, data);
        let result = crate::audited_if_ctx! {
            ctx: ctx,
            event: oauth2_client_event(Operation::Update, domain_id, DOMAIN_SETTINGS_TARGET),
            operation: op,
            on_audit_error: |_: AuditDispatchError| Oauth2ClientProviderError::AuditUnavailable,
        };
        // Whether or not the write went through, the next request reads the
        // stored value again.
        self.invalidate_domain_dpop_mode(domain_id);
        result
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
    use openstack_keystone_core_types::role::RoleBuilder;
    use std::collections::HashMap;

    fn sample_create() -> OAuth2ClientResourceCreate {
        OAuth2ClientResourceCreate {
            post_logout_redirect_uris: Default::default(),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            spiffe_ids: vec![],
            delegation: None,
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
            dpop_bound_access_tokens: false,
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
            internal_trust_domains: vec!["cloud.example".into()],
            domain_dpop_modes: DashMap::new(),
            domain_dpop_epochs: DashMap::new(),
        }
    }

    fn sample_service_create() -> OAuth2ClientResourceCreate {
        let mut req = sample_create();
        req.token_endpoint_auth_method = TLS_CLIENT_AUTH.into();
        req.redirect_uris = vec![];
        req.grant_types = vec![];
        req.require_pkce = false;
        req.spiffe_ids = vec!["spiffe://cloud.example/ns/nova/sa/*".into()];
        req.delegation = Some(DelegationPolicy {
            service_grants: true,
            ..Default::default()
        });
        req
    }

    fn state_with_roles(
        known: &'static [&'static str],
    ) -> impl std::future::Future<Output = crate::keystone::ServiceState> {
        let mut roles = crate::role::MockRoleProvider::default();
        roles.expect_get_role().returning(move |_, id| {
            Ok(known
                .contains(&id)
                .then(|| RoleBuilder::default().id(id).name(id).build().unwrap()))
        });
        get_mocked_state(
            None,
            Some(crate::provider::Provider::mocked_builder().mock_role(roles)),
        )
    }

    #[tokio::test]
    async fn test_create_rejects_unknown_max_role_id() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_list_spiffe_clients().returning(|_| Ok(vec![]));
        mock.expect_create()
            .returning(|_, data| Ok(sample_resource_from(data)));
        let service = service_with(mock);
        let state = state_with_roles(&["member"]).await;
        let ctx = ExecutionContext::internal(&state);

        let mut req = sample_service_create();
        req.delegation = Some(DelegationPolicy {
            service_grants: true,
            max_role_ids: vec!["member".into(), "membr".into()],
            ..Default::default()
        });
        assert!(matches!(
            service.create(&ctx, req.clone(), false).await,
            Err(Oauth2ClientProviderError::Validation(msg)) if msg.contains("membr")
        ));

        req.delegation = Some(DelegationPolicy {
            service_grants: true,
            max_role_ids: vec!["member".into()],
            ..Default::default()
        });
        assert!(service.create(&ctx, req, false).await.is_ok());
    }

    fn resource_with_ceiling(ids: &[&str]) -> OAuth2ClientResource {
        let mut req = sample_service_create();
        req.delegation = Some(DelegationPolicy {
            service_grants: true,
            max_role_ids: ids.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        });
        sample_resource_from(req)
    }

    fn update_with_ceiling(ids: &[&str]) -> OAuth2ClientResourceUpdate {
        OAuth2ClientResourceUpdate {
            delegation: Some(DelegationPolicy {
                service_grants: true,
                max_role_ids: ids.iter().map(|s| s.to_string()).collect(),
                max_grant_lifetime: Some(60),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_update_checks_only_added_max_role_ids() {
        let mut mock = MockOauth2ClientBackend::new();
        // Stored ceiling names `gone`, which no longer exists.
        mock.expect_get()
            .returning(|_, _, _| Ok(Some(resource_with_ceiling(&["member", "gone"]))));
        mock.expect_update()
            .returning(|_, _, _, _| Ok(resource_with_ceiling(&["member", "gone"])));
        let service = service_with(mock);
        let state = state_with_roles(&["member", "reader"]).await;
        let ctx = ExecutionContext::internal(&state);

        // Same ids, other delegation field changed: not re-checked.
        assert!(
            service
                .update(&ctx, "d", "p", update_with_ceiling(&["member", "gone"]))
                .await
                .is_ok()
        );
        // A new existing id is accepted.
        assert!(
            service
                .update(&ctx, "d", "p", update_with_ceiling(&["gone", "reader"]))
                .await
                .is_ok()
        );
        // A new unknown id is rejected.
        assert!(matches!(
            service
                .update(&ctx, "d", "p", update_with_ceiling(&["member", "membr"]))
                .await,
            Err(Oauth2ClientProviderError::Validation(msg)) if msg.contains("membr")
        ));
    }

    #[tokio::test]
    async fn test_role_lookup_failure_is_dependency_error() {
        let mut roles = crate::role::MockRoleProvider::default();
        roles.expect_get_role().returning(|_, _| {
            Err(openstack_keystone_core_types::role::RoleProviderError::Driver("boom".into()))
        });
        let state = get_mocked_state(
            None,
            Some(crate::provider::Provider::mocked_builder().mock_role(roles)),
        )
        .await;
        let ctx = ExecutionContext::internal(&state);
        let mut req = sample_service_create();
        req.delegation = Some(DelegationPolicy {
            service_grants: true,
            max_role_ids: vec!["member".into()],
            ..Default::default()
        });
        let service = service_with(MockOauth2ClientBackend::new());
        assert!(matches!(
            service.create(&ctx, req, false).await,
            Err(Oauth2ClientProviderError::Dependency(_))
        ));
    }

    #[tokio::test]
    async fn test_create_delegatable_service_has_no_secret() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_list_spiffe_clients().returning(|_| Ok(vec![]));
        mock.expect_create()
            .returning(|_, data| Ok(sample_resource_from(data)));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        // Even when the caller asks for a confidential client, an mTLS
        // client never gets a secret, and PKCE is not required.
        let (created, secret) = service
            .create(&ctx, sample_service_create(), true)
            .await
            .unwrap();
        assert!(secret.is_none());
        assert!(created.client_secret_hash.is_none());
        assert!(created.service_grant_policy().is_some());
    }

    #[tokio::test]
    async fn test_create_rejects_invalid_delegation() {
        let service = service_with(MockOauth2ClientBackend::new());
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        let cases: Vec<fn(&mut OAuth2ClientResourceCreate)> = vec![
            // Delegation needs tls_client_auth.
            (|r| r.token_endpoint_auth_method = "client_secret_basic".into()),
            // ... and SPIFFE ID patterns.
            (|r| r.spiffe_ids = vec![]),
            // Foreign trust domain.
            (|r| r.spiffe_ids = vec!["spiffe://evil.example/ns/nova".into()]),
            // Wildcard not in the final segment.
            (|r| r.spiffe_ids = vec!["spiffe://cloud.example/ns/*/sa".into()]),
            // on_behalf_of without an operation lifetime.
            (|r| {
                r.delegation = Some(DelegationPolicy {
                    on_behalf_of: true,
                    ..Default::default()
                })
            }),
            // Browser grant without a secret or PKCE.
            (|r| r.grant_types = vec![GrantType::AuthorizationCode]),
            // Redirect URIs are meaningless without the browser grants.
            (|r| r.redirect_uris = vec!["https://rp.example.com/cb".into()]),
            // Characters outside the SPIFFE ID charset.
            (|r| r.spiffe_ids = vec!["spiffe://cloud.example/ns/a b".into()]),
            // Zero limits.
            (|r| {
                r.delegation = Some(DelegationPolicy {
                    service_grants: true,
                    max_grant_lifetime: Some(0),
                    ..Default::default()
                })
            }),
        ];
        for (idx, mutate) in cases.iter().enumerate() {
            let mut req = sample_service_create();
            mutate(&mut req);
            assert!(
                matches!(
                    service.create(&ctx, req, false).await,
                    Err(Oauth2ClientProviderError::Validation(_))
                ),
                "case {idx}"
            );
        }
    }

    #[tokio::test]
    async fn test_create_rejects_spiffe_ids_without_internal_interface() {
        let mut service = service_with(MockOauth2ClientBackend::new());
        service.internal_trust_domains = vec![];
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);
        assert!(matches!(
            service.create(&ctx, sample_service_create(), false).await,
            Err(Oauth2ClientProviderError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn test_create_rejects_overlapping_spiffe_ids() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_list_spiffe_clients().returning(|_| {
            let mut other = sample_resource_from(sample_service_create());
            other.spiffe_ids = vec!["spiffe://cloud.example/ns/nova/sa/compute".into()];
            Ok(vec![other])
        });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        // The wildcard covers the other client's exact ID.
        assert!(matches!(
            service.create(&ctx, sample_service_create(), false).await,
            Err(Oauth2ClientProviderError::Conflict(_))
        ));
    }

    #[test]
    fn test_spiffe_conflict_names_the_holder() {
        let mut other = sample_resource_from(sample_service_create());
        other.domain_id = "gone-domain".into();
        other.provider_id = "stale".into();
        other.spiffe_ids = vec!["spiffe://cloud.example/ns/nova/sa/compute".into()];
        let msg = find_spiffe_conflict(
            &["spiffe://cloud.example/ns/nova/sa/*".into()],
            &[other],
            None,
        )
        .unwrap_or_default();
        assert!(
            msg.contains("`stale`") && msg.contains("`gone-domain`"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn test_update_spiffe_ids_ignores_own_patterns() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_get()
            .returning(|_, _, _| Ok(Some(sample_resource_from(sample_service_create()))));
        mock.expect_list_spiffe_clients()
            .returning(|_| Ok(vec![sample_resource_from(sample_service_create())]));
        mock.expect_update()
            .returning(|_, _, _, _| Ok(sample_resource_from(sample_service_create())));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        let update = OAuth2ClientResourceUpdate {
            spiffe_ids: Some(vec!["spiffe://cloud.example/ns/nova/sa/*".into()]),
            ..Default::default()
        };
        assert!(
            service
                .update(&ctx, "domain-1", "provider-1", update)
                .await
                .is_ok()
        );
    }

    fn domain_settings_returning(
        mode: openstack_keystone_config::DpopMode,
    ) -> MockOauth2ClientBackend {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_get_domain_settings().returning(move |_, id| {
            Ok(Some(OAuth2DomainSettings {
                domain_id: id.into(),
                dpop: mode,
                updated_at: 1,
            }))
        });
        mock
    }

    #[tokio::test]
    async fn test_effective_dpop_mode_combines_levels() {
        use openstack_keystone_config::DpopMode::*;
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        // Domain raises a global `optional`.
        let mut service = service_with(domain_settings_returning(Required));
        service.oauth2_config.dpop = Optional;
        assert_eq!(
            service
                .effective_dpop_mode(&ctx, "domain-1", false)
                .await
                .unwrap(),
            Required
        );

        // The global value is a floor for a weaker domain value.
        let mut service = service_with(domain_settings_returning(Disabled));
        service.oauth2_config.dpop = Optional;
        assert_eq!(
            service
                .effective_dpop_mode(&ctx, "domain-1", false)
                .await
                .unwrap(),
            Optional
        );

        // No stored record: the global value applies.
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_get_domain_settings().returning(|_, _| Ok(None));
        let mut service = service_with(mock);
        service.oauth2_config.dpop = Optional;
        assert_eq!(
            service
                .effective_dpop_mode(&ctx, "domain-1", false)
                .await
                .unwrap(),
            Optional
        );
    }

    #[tokio::test]
    async fn test_effective_dpop_mode_skips_lookup_when_already_required() {
        use openstack_keystone_config::DpopMode::*;
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        // The mock has no expectation: any backend call would panic.
        let mut service = service_with(MockOauth2ClientBackend::new());
        service.oauth2_config.dpop = Required;
        assert_eq!(
            service
                .effective_dpop_mode(&ctx, "domain-1", false)
                .await
                .unwrap(),
            Required
        );
        let service = service_with(MockOauth2ClientBackend::new());
        assert_eq!(
            service
                .effective_dpop_mode(&ctx, "domain-1", true)
                .await
                .unwrap(),
            Required
        );
    }

    #[tokio::test]
    async fn test_get_domain_settings_defaults_when_not_stored() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_get_domain_settings().returning(|_, _| Ok(None));
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        let settings = service.get_domain_settings(&ctx, "domain-1").await.unwrap();
        assert_eq!(settings.domain_id, "domain-1");
        assert_eq!(settings.dpop, openstack_keystone_config::DpopMode::Disabled);
    }

    #[tokio::test]
    async fn test_get_domain_settings_returns_stored() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_get_domain_settings().returning(|_, domain_id| {
            Ok(Some(OAuth2DomainSettings {
                domain_id: domain_id.into(),
                dpop: openstack_keystone_config::DpopMode::Required,
                updated_at: 5,
            }))
        });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        let settings = service.get_domain_settings(&ctx, "domain-1").await.unwrap();
        assert_eq!(settings.dpop, openstack_keystone_config::DpopMode::Required);
    }

    #[tokio::test]
    async fn test_effective_dpop_mode_reuses_the_domain_mode_until_it_changes() {
        use openstack_keystone_config::DpopMode::*;
        let mut mock = MockOauth2ClientBackend::new();
        // One read for the first two requests, one more after the update.
        mock.expect_get_domain_settings()
            .times(2)
            .returning(|_, id| Ok(Some(OAuth2DomainSettings::default_for(id))));
        mock.expect_update_domain_settings()
            .times(1)
            .returning(
                |_, id, data| Ok(OAuth2DomainSettings::default_for(id).with_update(data, 7)),
            );
        let service = service_with(mock);
        let state = state_with_domains(&["domain-1"]).await;
        let ctx = ExecutionContext::internal(&state);

        for _ in 0..2 {
            assert_eq!(
                service
                    .effective_dpop_mode(&ctx, "domain-1", false)
                    .await
                    .unwrap(),
                Disabled
            );
        }
        service
            .update_domain_settings(
                &ctx,
                "domain-1",
                OAuth2DomainSettingsUpdate {
                    dpop: Some(Required),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        service
            .effective_dpop_mode(&ctx, "domain-1", false)
            .await
            .unwrap();
    }

    /// A settings write that lands while a lookup is in flight must not be
    /// undone by the lookup caching the value it read before the write.
    #[tokio::test]
    async fn test_effective_dpop_mode_does_not_cache_a_value_read_across_a_write() {
        use std::sync::OnceLock;

        let service_cell: Arc<OnceLock<Arc<Oauth2ClientService>>> = Arc::new(OnceLock::new());
        let mut mock = MockOauth2ClientBackend::new();
        let cell = service_cell.clone();
        mock.expect_get_domain_settings().returning(move |_, id| {
            // The write completes between the read and the cache insert.
            if let Some(service) = cell.get() {
                service.invalidate_domain_dpop_mode(id);
            }
            Ok(Some(OAuth2DomainSettings::default_for(id)))
        });
        let service = Arc::new(service_with(mock));
        assert!(service_cell.set(service.clone()).is_ok());
        let state = state_with_domains(&["domain-1"]).await;
        let ctx = ExecutionContext::internal(&state);

        service
            .effective_dpop_mode(&ctx, "domain-1", false)
            .await
            .unwrap();
        assert!(service.domain_dpop_modes.is_empty());
    }

    /// A write to another domain does not cost this one its cache entry.
    #[tokio::test]
    async fn test_effective_dpop_mode_cache_survives_a_write_to_another_domain() {
        use std::sync::OnceLock;

        let service_cell: Arc<OnceLock<Arc<Oauth2ClientService>>> = Arc::new(OnceLock::new());
        let mut mock = MockOauth2ClientBackend::new();
        let cell = service_cell.clone();
        mock.expect_get_domain_settings().returning(move |_, id| {
            if let Some(service) = cell.get() {
                service.invalidate_domain_dpop_mode("domain-2");
            }
            Ok(Some(OAuth2DomainSettings::default_for(id)))
        });
        let service = Arc::new(service_with(mock));
        assert!(service_cell.set(service.clone()).is_ok());
        let state = state_with_domains(&["domain-1", "domain-2"]).await;
        let ctx = ExecutionContext::internal(&state);

        service
            .effective_dpop_mode(&ctx, "domain-1", false)
            .await
            .unwrap();
        assert!(service.domain_dpop_modes.contains_key("domain-1"));
    }

    #[tokio::test]
    async fn test_update_and_delete_domain_settings_delegate_to_backend() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_update_domain_settings()
            .withf(|_, domain_id, data| {
                domain_id == "domain-1"
                    && data.dpop == Some(openstack_keystone_config::DpopMode::Optional)
            })
            .times(1)
            .returning(|_, domain_id, data| {
                Ok(OAuth2DomainSettings::default_for(domain_id).with_update(data, 7))
            });
        mock.expect_delete_domain_settings()
            .withf(|_, domain_id| domain_id == "domain-1")
            .times(1)
            .returning(|_, _| Ok(()));
        let service = service_with(mock);
        let state = state_with_domains(&["domain-1"]).await;
        let ctx = ExecutionContext::internal(&state);

        let updated = service
            .update_domain_settings(
                &ctx,
                "domain-1",
                OAuth2DomainSettingsUpdate {
                    dpop: Some(openstack_keystone_config::DpopMode::Optional),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.dpop, openstack_keystone_config::DpopMode::Optional);
        service
            .delete_domain_settings(&ctx, "domain-1")
            .await
            .unwrap();
    }

    fn state_with_domains(
        known: &'static [&'static str],
    ) -> impl std::future::Future<Output = crate::keystone::ServiceState> {
        let mut resource = crate::resource::MockResourceProvider::default();
        resource.expect_get_domain().returning(move |_, id| {
            Ok(known.contains(&id).then(|| {
                openstack_keystone_core_types::resource::DomainBuilder::default()
                    .id(id)
                    .name(id)
                    .enabled(true)
                    .build()
                    .unwrap()
            }))
        });
        get_mocked_state(
            None,
            Some(crate::provider::Provider::mocked_builder().mock_resource(resource)),
        )
    }

    #[tokio::test]
    async fn test_update_domain_settings_rejects_unknown_domain() {
        // No backend expectation: the backend must not be reached.
        let service = service_with(MockOauth2ClientBackend::new());
        let state = state_with_domains(&[]).await;
        let ctx = ExecutionContext::internal(&state);

        let err = service
            .update_domain_settings(&ctx, "nope", OAuth2DomainSettingsUpdate::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Oauth2ClientProviderError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_update_unrelated_field_ignores_trust_domain_drift() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_get()
            .returning(|_, _, _| Ok(Some(sample_resource_from(sample_service_create()))));
        mock.expect_update()
            .returning(|_, _, _, _| Ok(sample_resource_from(sample_service_create())));
        let mut service = service_with(mock);
        // The deployment's trust domains changed since registration.
        service.internal_trust_domains = vec!["new.example".into()];
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        let update = OAuth2ClientResourceUpdate {
            description: Some("renamed".into()),
            ..Default::default()
        };
        assert!(
            service
                .update(&ctx, "domain-1", "provider-1", update)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_update_validates_effective_delegation() {
        let mut mock = MockOauth2ClientBackend::new();
        mock.expect_get().returning(|_, _, _| {
            Ok(Some(sample_resource_from(OAuth2ClientResourceCreate {
                spiffe_ids: vec![],
                delegation: None,
                ..sample_create()
            })))
        });
        let service = service_with(mock);
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        // A client_secret_basic client cannot become a delegatable service.
        let update = OAuth2ClientResourceUpdate {
            delegation: Some(DelegationPolicy {
                service_grants: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(matches!(
            service.update(&ctx, "domain-1", "provider-1", update).await,
            Err(Oauth2ClientProviderError::Validation(_))
        ));

        // Setting and removing in one patch is rejected.
        let update = OAuth2ClientResourceUpdate {
            delegation: Some(DelegationPolicy::default()),
            remove_delegation: true,
            ..Default::default()
        };
        assert!(matches!(
            service.update(&ctx, "domain-1", "provider-1", update).await,
            Err(Oauth2ClientProviderError::Validation(_))
        ));
    }

    #[test]
    fn test_with_update_sets_and_removes_delegation() {
        let current = sample_resource_from(sample_service_create());
        let removed = current.clone().with_update(
            OAuth2ClientResourceUpdate {
                remove_delegation: true,
                ..Default::default()
            },
            1,
        );
        assert!(removed.delegation.is_none());
        assert_eq!(removed.spiffe_ids, current.spiffe_ids);
        let kept = current
            .clone()
            .with_update(OAuth2ClientResourceUpdate::default(), 1);
        assert_eq!(kept.delegation, current.delegation);
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
    async fn test_create_validates_backchannel_logout_uri() {
        let service = service_with(MockOauth2ClientBackend::new());
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        for bad in [
            "http://rp.example.com/bc",
            "https://user:pw@rp.example.com/bc",
            "not a url",
        ] {
            let mut req = sample_create();
            req.backchannel_logout_uri = Some(bad.into());
            assert!(
                matches!(
                    service.create(&ctx, req, true).await,
                    Err(Oauth2ClientProviderError::Validation(_))
                ),
                "{bad} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn test_create_validates_post_logout_redirect_uris() {
        let service = service_with(MockOauth2ClientBackend::new());
        let state = get_mocked_state(None, None).await;
        let ctx = ExecutionContext::internal(&state);

        for bad in [
            vec!["http://insecure.example.com/bye".to_string()],
            vec!["https://rp.example.com/bye#fragment".to_string()],
            vec!["https://user:pw@rp.example.com/bye".to_string()],
            vec!["https://rp.example.com/bye".to_string(); 11],
        ] {
            let mut req = sample_create();
            req.post_logout_redirect_uris = bad.clone();
            assert!(
                matches!(
                    service.create(&ctx, req, true).await,
                    Err(Oauth2ClientProviderError::Validation(_))
                ),
                "{bad:?} must be rejected"
            );
        }
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
        session
            .expect_delete_consents_by_client()
            .withf(|_, client_id| client_id == "client-1")
            .times(1)
            .returning(|_, _| Ok(2));
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
            post_logout_redirect_uris: data.post_logout_redirect_uris,
            backchannel_logout_uri: data.backchannel_logout_uri,
            backchannel_logout_session_required: data.backchannel_logout_session_required,
            frontchannel_logout_uri: data.frontchannel_logout_uri,
            frontchannel_logout_session_required: data.frontchannel_logout_session_required,
            spiffe_ids: data.spiffe_ids,
            delegation: data.delegation,
            dpop_bound_access_tokens: false,
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
