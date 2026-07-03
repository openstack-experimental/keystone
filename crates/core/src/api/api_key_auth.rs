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
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;

use axum::extract::{ConnectInfo, FromRef, FromRequestParts, Path};
use axum::http::request::Parts;
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

        // The SCIM route is domain-scoped: `/SCIM/v2/{domain_id}/...`. The
        // key lookup keyspace is partitioned by domain_id (ADR 0021 §2.A),
        // so it must be known before any storage access.
        let Path(domain_id) = Path::<String>::from_request_parts(parts, &state)
            .await
            .map_err(|_| KeystoneApiError::from(AuthenticationError::Unauthorized))?;

        let peer_ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip());

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
                    && state
                        .api_key_rate_limiter
                        .check_key(&ip.to_string())
                        .is_err()
                {
                    return Err(KeystoneApiError::TooManyRequests);
                }
                return Err(AuthenticationError::Unauthorized.into());
            }
        };

        if state
            .api_key_rate_limiter
            .check_key(&parsed.lookup_hash)
            .is_err()
        {
            return Err(KeystoneApiError::TooManyRequests);
        }

        // Step 2: database lookup & IP allowlisting.
        use secrecy::ExposeSecret;
        let entropy = parsed.entropy.expose_secret();

        let resource = state
            .provider
            .get_api_key_provider()
            .get_by_lookup_hash(&state, &domain_id, &parsed.lookup_hash)
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

        let effective_ip = resolve_client_ip(&parts.headers, peer_ip, &cfg.trusted_proxies);
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

        spawn_lazy_rehash(&state, &resource, entropy.to_string(), cfg.clone());
        spawn_last_used_update(&state, &resource, now);

        // Step 4: ephemeral context hydration (anti-bleed scoping).
        hydrate_ephemeral_context(&state, &resource).await
    }
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

/// Compute the effective client IP using the rightmost-non-trusted-proxy
/// algorithm (ADR 0021 §3 Step 2, §6.E, Invariant 4): append the raw TCP
/// peer to the right of the `X-Forwarded-For` chain, then walk right to
/// left, returning the first address not in `trusted_proxies`. If the raw
/// TCP peer itself is not trusted, it is used directly without consulting
/// XFF at all.
fn resolve_client_ip(
    headers: &axum::http::HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_proxies: &[String],
) -> Option<IpAddr> {
    let trusted: Vec<IpNet> = trusted_proxies
        .iter()
        .filter_map(|c| c.parse::<IpNet>().ok())
        .collect();

    let is_trusted = |ip: &IpAddr| trusted.iter().any(|net| net.contains(ip));

    let peer = peer_ip?;
    if !is_trusted(&peer) {
        return Some(peer);
    }

    let xff_chain: Vec<IpAddr> = headers
        .get(axum::http::header::HeaderName::from_static(
            "x-forwarded-for",
        ))
        .and_then(|h| h.to_str().ok())
        .map(|h| {
            h.split(',')
                .filter_map(|s| s.trim().parse::<IpAddr>().ok())
                .collect()
        })
        .unwrap_or_default();

    let mut chain = xff_chain;
    chain.push(peer);

    chain
        .into_iter()
        .rev()
        .find(|ip| !is_trusted(ip))
        .or(Some(peer))
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
    use axum::http::HeaderMap;

    fn headers_with_xff(xff: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HeaderName::from_static("x-forwarded-for"),
            xff.parse().unwrap(),
        );
        headers
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ---------------------------------------------------------------------
    // resolve_client_ip (ADR 0021 §3 Step 2, §6.E, Invariant 4)
    // ---------------------------------------------------------------------

    #[test]
    fn untrusted_peer_ignores_xff_entirely() {
        // Peer itself is not a trusted proxy: XFF must not be consulted at
        // all, even if present (prevents spoofing via an untrusted hop).
        let headers = headers_with_xff("1.2.3.4");
        let peer = Some(ip("203.0.113.5"));
        let trusted = vec!["10.0.0.0/8".to_string()];
        assert_eq!(
            resolve_client_ip(&headers, peer, &trusted),
            Some(ip("203.0.113.5"))
        );
    }

    #[test]
    fn trusted_peer_walks_xff_rightmost_non_trusted() {
        // Chain (left to right): 1.2.3.4 (attacker-controlled), 10.0.0.5
        // (trusted intermediate hop), peer 10.0.0.1 (trusted, terminal
        // proxy). Effective IP must be 10.0.0.5's predecessor scanning
        // right-to-left: append peer, walk right-to-left, first non-trusted.
        let headers = headers_with_xff("1.2.3.4, 10.0.0.5");
        let peer = Some(ip("10.0.0.1"));
        let trusted = vec!["10.0.0.0/8".to_string()];
        assert_eq!(
            resolve_client_ip(&headers, peer, &trusted),
            Some(ip("1.2.3.4"))
        );
    }

    #[test]
    fn trusted_peer_all_hops_trusted_falls_back_to_peer() {
        let headers = headers_with_xff("10.0.0.9");
        let peer = Some(ip("10.0.0.1"));
        let trusted = vec!["10.0.0.0/8".to_string()];
        assert_eq!(
            resolve_client_ip(&headers, peer, &trusted),
            Some(ip("10.0.0.1"))
        );
    }

    #[test]
    fn leftmost_xff_entry_is_never_trusted_blindly() {
        // Regression guard for the leftmost-take vulnerability (ADR 0021 F2):
        // an attacker prepending a spoofed IP as the leftmost XFF entry must
        // not be accepted just because it's present.
        let headers = headers_with_xff("203.0.113.99, 1.2.3.4, 10.0.0.5");
        let peer = Some(ip("10.0.0.1"));
        let trusted = vec!["10.0.0.0/8".to_string()];
        let effective = resolve_client_ip(&headers, peer, &trusted);
        assert_ne!(effective, Some(ip("203.0.113.99")));
        assert_eq!(effective, Some(ip("1.2.3.4")));
    }

    #[test]
    fn no_peer_ip_resolves_to_none() {
        let headers = HeaderMap::new();
        assert_eq!(resolve_client_ip(&headers, None, &[]), None);
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
}
