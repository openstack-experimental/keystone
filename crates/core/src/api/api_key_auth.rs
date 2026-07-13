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
//! # API Key (SCIM ingress) authentication extractor (ADR 0021)
//!
//! [`ApiKeyAuth`] is deliberately separate from the shared [`super::Auth`]
//! extractor: per ADR 0021 §4 (Sub-Router Isolation), API keys must be
//! accepted *only* on the SCIM sub-router, never on core OpenStack
//! endpoints. Mounting this extractor exclusively on SCIM route handlers
//! achieves that isolation structurally, without needing a path allowlist.
use std::net::IpAddr;
use std::ops::Deref;

use axum::extract::{FromRef, FromRequestParts, Path};
use axum::http::request::Parts;
use governor::clock::Clock as _;
use ipnet::IpNet;
use tracing::warn;

use openstack_keystone_core_types::api_key::ApiClientResource;
use openstack_keystone_core_types::auth::AuthenticationError;
use openstack_keystone_core_types::mapping::auth::MappingAuthRequest;
use openstack_keystone_core_types::mapping::authorization::Authorization;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;
use openstack_keystone_core_types::mapping::virtual_user::MatchResult;

use crate::api::KeystoneApiError;
use crate::api_key::{crypto, token};
use crate::auth::{ExecutionContext, ValidatedSecurityContext};
use crate::keystone::ServiceState;
use crate::mapping::engine;
use crate::net::{public_ingress_peer_addr, resolve_client_ip_from_headers};

/// Ephemeral, single-scope [`ValidatedSecurityContext`] hydrated from a
/// verified API Key, for use exclusively on the SCIM sub-router.
#[derive(Debug, Clone)]
pub struct ApiKeyAuth(pub ValidatedSecurityContext);

impl Deref for ApiKeyAuth {
    type Target = ValidatedSecurityContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for ApiKeyAuth
where
    ServiceState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = KeystoneApiError;

    #[tracing::instrument(skip(state), err)]
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = ServiceState::from_ref(state);
        let (_domain_id, resource) = resolve_verified_api_client(parts, &state).await?;

        // Step 4: ephemeral context hydration (anti-bleed scoping).
        hydrate_ephemeral_context(&state, &resource).await
    }
}

/// Realm-aware ephemeral security context, additive to [`ApiKeyAuth`] (ADR
/// 0024 §2.C amendment to ADR 0021 §3 Step 4).
///
/// Used exclusively by the `/SCIM/v2` resource handlers (Users/Groups)
/// introduced by ADR 0024 — never by the diagnostic `whoami` route, which
/// keeps using the plain [`ApiKeyAuth`] extractor and accepts any scope.
/// Enforces two additional invariants beyond [`ApiKeyAuth`]:
///
/// 1. **Domain-only scope** (ADR 0024 §2.C): the resolved authorization must be
///    `ScopeInfo::Domain` matching the path's `{domain_id}` — SCIM resource
///    provisioning is a domain-level operation, never project-scoped.
/// 2. **Realm Activation Gate** (ADR 0024 §2.B): `data:scim_realm:v1:
///    <domain_id>:<provider_id>` must exist and be `enabled`, checked before
///    any User/Group storage access.
#[derive(Debug, Clone)]
pub struct ScimRealmAuth {
    /// The hydrated ephemeral security context (same as [`ApiKeyAuth`]).
    pub ctx: ValidatedSecurityContext,
    /// The realm coordinate the request authenticated under.
    pub realm: ScimRealmContext,
}

impl Deref for ScimRealmAuth {
    type Target = ValidatedSecurityContext;

    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}

/// The `(domain_id, provider_id)` coordinate a [`ScimRealmAuth`] resolved
/// under (ADR 0024 §2.C).
#[derive(Debug, Clone)]
pub struct ScimRealmContext {
    pub domain_id: String,
    pub provider_id: String,
}

impl<S> FromRequestParts<S> for ScimRealmAuth
where
    ServiceState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = KeystoneApiError;

    #[tracing::instrument(skip(state), err)]
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = ServiceState::from_ref(state);
        let (domain_id, resource) = resolve_verified_api_client(parts, &state).await?;
        let provider_id = resource.provider_id.clone();

        let ApiKeyAuth(ctx) = hydrate_ephemeral_context(&state, &resource).await?;

        // Invariant 1: Domain-only scope (ADR 0024 §2.C).
        if !is_domain_scoped(&ctx, &domain_id) {
            return Err(AuthenticationError::Unauthorized.into());
        }

        // Invariant 2: Realm Activation Gate (ADR 0024 §2.B). Checked before
        // any User/Group storage access.
        let exec = ExecutionContext::internal(&state);
        let realm = state
            .provider
            .get_scim_realm_provider()
            .get_realm(&exec, &domain_id, &provider_id)
            .await
            .map_err(|e| {
                warn!(error = %e, "scim_realm lookup failed");
                AuthenticationError::Unauthorized
            })?;
        match realm {
            Some(realm) if realm.enabled => {}
            _ => return Err(AuthenticationError::Unauthorized.into()),
        }

        Ok(ScimRealmAuth {
            ctx,
            realm: ScimRealmContext {
                domain_id,
                provider_id,
            },
        })
    }
}

/// Steps 1–3 of the API Key ingress pipeline (ADR 0021 §3): format check +
/// rate limiting, database lookup + IP allowlisting, cryptographic
/// verification. Shared by [`ApiKeyAuth`] and [`ScimRealmAuth`] so both
/// extractors authenticate identically before diverging on scope/realm
/// policy (ADR 0024 §2.C).
async fn resolve_verified_api_client(
    parts: &mut Parts,
    state: &ServiceState,
) -> Result<(String, ApiClientResource), KeystoneApiError> {
    // The SCIM route is domain-scoped: `/SCIM/v2/{domain_id}/...`. The
    // key lookup keyspace is partitioned by domain_id (ADR 0021 §2.A),
    // so it must be known before any storage access.
    //
    // Extracted as a map rather than `Path<String>`: axum's `Path<T>` for a
    // scalar `T` requires the *entire* matched route (including nested
    // routers) to carry exactly one dynamic segment. ADR 0024's resource
    // routes (e.g. `/{domain_id}/Users/{id}`) have two, which would
    // otherwise make this extraction fail with `WrongNumberOfParameters`
    // for every show/update/delete request.
    let Path(params) =
        Path::<std::collections::HashMap<String, String>>::from_request_parts(parts, state)
            .await
            .map_err(|_| KeystoneApiError::from(AuthenticationError::Unauthorized))?;
    let domain_id = params
        .get("domain_id")
        .ok_or(KeystoneApiError::from(AuthenticationError::Unauthorized))?
        .clone();

    let peer_ip = public_ingress_peer_addr(&parts.extensions).map(|addr| addr.ip());

    let presented_token = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(KeystoneApiError::UnauthorizedNoContext)?;

    let cfg = state.config_manager.config.read().await.api_key.clone();

    // Step 1: format check + hash-based rate limiting (ADR 0021 §3 Step 1).
    let parsed = match token::parse(presented_token) {
        Ok(parsed) => parsed,
        Err(_) => {
            // No valid entropy: key the limiter on source IP instead, so
            // brute-force garbage traffic doesn't bypass rate limiting by
            // sending malformed tokens.
            if let Some(ip) = peer_ip
                && let Err(not_until) = state.api_key_rate_limiter.check_key(&ip.to_string())
            {
                let retry_after = not_until
                    .wait_time_from(state.api_key_rate_limiter.clock().now())
                    .as_secs()
                    .max(1);
                return Err(KeystoneApiError::TooManyRequests { retry_after });
            }
            return Err(AuthenticationError::Unauthorized.into());
        }
    };

    if let Err(not_until) = state.api_key_rate_limiter.check_key(&parsed.lookup_hash) {
        let retry_after = not_until
            .wait_time_from(state.api_key_rate_limiter.clock().now())
            .as_secs()
            .max(1);
        return Err(KeystoneApiError::TooManyRequests { retry_after });
    }

    // Step 2: database lookup & IP allowlisting.
    use secrecy::ExposeSecret;
    let entropy = parsed.entropy.expose_secret();

    let resource = state
        .provider
        .get_api_key_provider()
        .get_by_lookup_hash(state, &domain_id, &parsed.lookup_hash)
        .await
        .map_err(|e| {
            warn!(error = %e, "api_key lookup failed");
            AuthenticationError::Unauthorized
        })?;

    let Some(resource) = resource else {
        // Dummy hash: burn the same Argon2id cost as a real verification
        // to prevent timing-based enumeration of valid lookup hashes
        // (ADR 0021 Invariant 7).
        let _ = crypto::generate_dummy_hash(&cfg).await;
        return Err(AuthenticationError::Unauthorized.into());
    };

    let now = chrono::Utc::now().timestamp();
    if !resource.is_active(now) {
        let _ = crypto::generate_dummy_hash(&cfg).await;
        return Err(AuthenticationError::Unauthorized.into());
    }

    // Resolve the effective client IP using only the header this trust
    // boundary explicitly configured its proxies to sanitize.
    let effective_ip = resolve_client_ip_from_headers(
        &parts.headers,
        peer_ip,
        &cfg.trusted_proxies,
        cfg.trusted_header,
    );
    if !ip_allowed(effective_ip, &resource.allowed_ips) {
        return Err(AuthenticationError::Unauthorized.into());
    }

    // Step 3: cryptographic verification & lazy re-hash.
    let verified = crypto::verify_secret(entropy, &resource.secret_hash)
        .await
        .map_err(|e| {
            warn!(error = %e, "api_key argon2 verification errored");
            AuthenticationError::Unauthorized
        })?;
    if !verified {
        return Err(AuthenticationError::Unauthorized.into());
    }

    spawn_lazy_rehash(state, &resource, entropy.to_string(), cfg.clone());
    spawn_last_used_update(state, &resource, now);

    Ok((domain_id, resource))
}

/// Fire-and-forget re-hash of the stored secret if its PHC parameters fall
/// below the configured floor (ADR 0021 Invariant 8). Never blocks the
/// request on this maintenance work.
fn spawn_lazy_rehash(
    state: &ServiceState,
    resource: &ApiClientResource,
    entropy: String,
    cfg: openstack_keystone_config::ApiKeyProvider,
) {
    if crypto::params_meet_minimums(&resource.secret_hash, &cfg).unwrap_or(true) {
        return;
    }
    let state = state.clone();
    let domain_id = resource.domain_id.clone();
    let lookup_hash = resource.lookup_hash.clone();
    tokio::spawn(async move {
        match crypto::hash_secret(&entropy, &cfg).await {
            Ok(new_hash) => {
                if let Err(e) = state
                    .provider
                    .get_api_key_provider()
                    .update_secret_hash(&state, &domain_id, &lookup_hash, new_hash)
                    .await
                {
                    warn!(error = %e, "api_key lazy re-hash persist failed");
                }
            }
            Err(e) => warn!(error = %e, "api_key lazy re-hash failed"),
        }
    });
}

/// Fire-and-forget `last_used_at` update (ADR 0021 §3 Step 3). Async writes
/// may occasionally drop under pressure; the janitor grace period absorbs
/// this documented drift (ADR 0021 §6.F).
fn spawn_last_used_update(state: &ServiceState, resource: &ApiClientResource, now: i64) {
    let state = state.clone();
    let domain_id = resource.domain_id.clone();
    let lookup_hash = resource.lookup_hash.clone();
    tokio::spawn(async move {
        if let Err(e) = state
            .provider
            .get_api_key_provider()
            .update_last_used(&state, &domain_id, &lookup_hash, now)
            .await
        {
            warn!(error = %e, "api_key last_used_at update failed");
        }
    });
}

/// Whether `client_ip` satisfies the key's `allowed_ips` CIDR allowlist.
/// `None` (missing field) means no restriction applies (ADR 0021 Invariant
/// 5); a missing field and `Some(vec![])` are treated identically.
fn ip_allowed(client_ip: Option<IpAddr>, allowed_ips: &Option<Vec<String>>) -> bool {
    let Some(allowed) = allowed_ips else {
        return true;
    };
    if allowed.is_empty() {
        return true;
    }
    let Some(ip) = client_ip else {
        return false;
    };
    allowed
        .iter()
        .filter_map(|c| c.parse::<IpNet>().ok())
        .any(|net| net.contains(&ip))
}

/// Whether a hydrated [`ValidatedSecurityContext`] resolved to exactly
/// `ScopeInfo::Domain` matching `domain_id` (ADR 0024 §2.C Domain-only scope
/// restriction). A missing authorization, or any other scope variant
/// (Project/System/Unscoped/TrustProject), is never domain-scoped.
fn is_domain_scoped(ctx: &ValidatedSecurityContext, domain_id: &str) -> bool {
    ctx.inner()
        .authorization()
        .map(|authz| {
            matches!(
                &authz.scope,
                openstack_keystone_core_types::auth::ScopeInfo::Domain(d) if d.id == domain_id
            )
        })
        .unwrap_or(false)
}

/// Evaluate the API Key's bound mapping ruleset and hydrate an
/// [`ApiKeyAuth`] under exactly one scope (ADR 0021 §3 Step 4).
async fn hydrate_ephemeral_context(
    state: &ServiceState,
    resource: &ApiClientResource,
) -> Result<ApiKeyAuth, KeystoneApiError> {
    let source = IdentitySource::ApiClient {
        provider_id: resource.provider_id.clone(),
    };
    let exec = ExecutionContext::internal(state);

    let ruleset = state
        .provider
        .get_mapping_provider()
        .get_ruleset_by_source(&exec, &resource.domain_id, &source)
        .await
        .map_err(|e| {
            warn!(error = %e, "api_key mapping ruleset lookup failed");
            AuthenticationError::Unauthorized
        })?
        .ok_or(AuthenticationError::Unauthorized)?;

    if !ruleset.enabled {
        return Err(AuthenticationError::Unauthorized.into());
    }

    let mut claims = std::collections::HashMap::new();
    claims.insert(
        "api_client.client_id".to_string(),
        vec![resource.client_id.clone()],
    );
    claims.insert(
        "api_client.provider_id".to_string(),
        vec![resource.provider_id.clone()],
    );

    // Pre-evaluate to enforce the API-Key-specific invariants (1–3) before
    // hydrating any context. `authenticate_by_mapping` below independently
    // re-evaluates the same (ruleset, claims) pair — evaluation is pure, so
    // this is deterministic; the small duplicated cost buys enforcement of
    // invariants the generic mapping engine does not itself know about.
    let match_result: Option<MatchResult> =
        engine::evaluate_ruleset(&ruleset, &claims, ruleset.domain_id.as_deref(), None).map_err(
            |e| {
                warn!(error = %e, "api_key mapping evaluation failed");
                AuthenticationError::Unauthorized
            },
        )?;

    let authorization = match &match_result {
        // Invariant 1: no-authorizations → authentication failure.
        None => return Err(AuthenticationError::NoAuthorizationsFound.into()),
        Some(mr) if mr.authorizations.is_empty() => {
            return Err(AuthenticationError::NoAuthorizationsFound.into());
        }
        // Invariant 2: single-scope enforcement.
        Some(mr) if mr.authorizations.len() > 1 => {
            return Err(AuthenticationError::MultipleScopesForbidden.into());
        }
        Some(mr) => &mr.authorizations[0],
    };

    // Invariant 3: system scope prohibited at API-Key ingress.
    if matches!(authorization, Authorization::System { .. }) {
        return Err(AuthenticationError::SystemScopeForbiddenForApiKey.into());
    }

    // Invariant: API Keys are domain-owned machine identities (ADR 0021 §2);
    // only a domain-scoped authorization is accepted at ingress. This is an
    // allowlist, not a per-type denylist, so any non-domain authorization
    // (including `Authorization::Project`) is rejected here. The write-time
    // prohibition (ADR 0021 §6.C) is defense-in-depth, not a substitute for
    // this runtime check.
    let Authorization::Domain { domain_id, .. } = authorization else {
        return Err(AuthenticationError::NonDomainScopeForbiddenForApiKey.into());
    };
    let scope = openstack_keystone_core_types::auth::ScopeInfo::Domain(
        openstack_keystone_core_types::resource::Domain {
            id: domain_id.clone(),
            name: String::new(),
            description: None,
            enabled: true,
            extra: Default::default(),
        },
    );
    scope.validate()?;

    // Invariant 6: user_id derived exclusively from client_id, never from
    // provider_id — `unique_workload_id` here is the key's public UUID.
    let mapping_req = MappingAuthRequest {
        domain_id: Some(resource.domain_id.clone()),
        source,
        unique_workload_id: resource.client_id.clone(),
        claims,
        rule_name: None,
    };

    let auth_result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&exec, &mapping_req)
        .await
        .map_err(|e| {
            warn!(error = %e, "api_key mapping authentication failed");
            AuthenticationError::Unauthorized
        })?;

    let ctx = openstack_keystone_core_types::auth::SecurityContext::try_from(auth_result)?;

    let vsc = ValidatedSecurityContext::new_for_scope(ctx, scope, state).await?;
    Ok(ApiKeyAuth(vsc))
}

#[cfg(test)]
mod tests {
    use super::*;

    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalInfo, ScopeInfo,
        SecurityContext, UserIdentityInfoBuilder,
    };
    use openstack_keystone_core_types::resource::Domain;

    fn vsc_with_scope(scope: ScopeInfo) -> ValidatedSecurityContext {
        let user = UserIdentityInfoBuilder::default()
            .user_id("uid".to_string())
            .build()
            .unwrap();
        let authz = AuthzInfoBuilder::default()
            .scope(scope)
            .roles(Vec::new())
            .build()
            .unwrap();
        let sc = SecurityContext::test_build()
            .authentication_context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(user),
            })
            .authorization(authz)
            .build();
        ValidatedSecurityContext::test_new(sc)
    }

    // ---------------------------------------------------------------------
    // is_domain_scoped (ADR 0024 §2.C Domain-only scope restriction)
    // ---------------------------------------------------------------------

    #[test]
    fn domain_scope_matching_domain_id_is_domain_scoped() {
        let vsc = vsc_with_scope(ScopeInfo::Domain(Domain {
            id: "domain-1".to_string(),
            name: String::new(),
            description: None,
            enabled: true,
            extra: Default::default(),
        }));
        assert!(is_domain_scoped(&vsc, "domain-1"));
    }

    #[test]
    fn domain_scope_mismatched_domain_id_is_not_domain_scoped() {
        let vsc = vsc_with_scope(ScopeInfo::Domain(Domain {
            id: "domain-1".to_string(),
            name: String::new(),
            description: None,
            enabled: true,
            extra: Default::default(),
        }));
        assert!(!is_domain_scoped(&vsc, "domain-2"));
    }

    #[test]
    fn project_scope_is_never_domain_scoped() {
        let vsc = vsc_with_scope(ScopeInfo::Project {
            project: openstack_keystone_core_types::resource::Project {
                id: "project-1".to_string(),
                domain_id: "domain-1".to_string(),
                name: String::new(),
                description: None,
                enabled: true,
                is_domain: false,
                parent_id: None,
                extra: Default::default(),
            },
            project_domain: Domain {
                id: "domain-1".to_string(),
                name: String::new(),
                description: None,
                enabled: true,
                extra: Default::default(),
            },
        });
        assert!(!is_domain_scoped(&vsc, "domain-1"));
    }

    #[test]
    fn unscoped_is_never_domain_scoped() {
        let vsc = vsc_with_scope(ScopeInfo::Unscoped);
        assert!(!is_domain_scoped(&vsc, "domain-1"));
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ---------------------------------------------------------------------
    // ip_allowed (ADR 0021 Invariant 5)
    // ---------------------------------------------------------------------

    #[test]
    fn none_allowed_ips_means_unrestricted() {
        assert!(ip_allowed(Some(ip("203.0.113.1")), &None));
        assert!(ip_allowed(None, &None));
    }

    #[test]
    fn empty_allowed_ips_means_unrestricted() {
        // `Some(vec![])` MUST behave identically to `None` per Invariant 5.
        assert!(ip_allowed(Some(ip("203.0.113.1")), &Some(vec![])));
    }

    #[test]
    fn ip_within_allowlist_is_allowed() {
        let allowed = Some(vec!["10.0.0.0/8".to_string()]);
        assert!(ip_allowed(Some(ip("10.1.2.3")), &allowed));
    }

    #[test]
    fn ip_outside_allowlist_is_denied() {
        let allowed = Some(vec!["10.0.0.0/8".to_string()]);
        assert!(!ip_allowed(Some(ip("203.0.113.1")), &allowed));
    }

    #[test]
    fn missing_client_ip_with_restriction_is_denied() {
        let allowed = Some(vec!["10.0.0.0/8".to_string()]);
        assert!(!ip_allowed(None, &allowed));
    }

    #[test]
    fn internal_connect_info_cannot_satisfy_api_key_allowlist() {
        use axum::extract::ConnectInfo;
        use openstack_keystone_config::{Interface, ProxyHeader};

        let mut extensions = axum::http::Extensions::new();
        extensions.insert(ConnectInfo(
            "10.0.0.9:8443".parse::<std::net::SocketAddr>().unwrap(),
        ));
        extensions.insert(Interface::Internal);

        let peer_ip = public_ingress_peer_addr(&extensions).map(|addr| addr.ip());
        let effective_ip = resolve_client_ip_from_headers(
            &axum::http::HeaderMap::new(),
            peer_ip,
            &[],
            ProxyHeader::XForwardedFor,
        );
        assert!(!ip_allowed(
            effective_ip,
            &Some(vec!["10.0.0.0/8".to_string()])
        ));
    }
}
