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
//! ADR 0025 Phase 1 (PR 1.1): [`CoreHostFunctions`] implements
//! `openstack_keystone_auth_plugin_runtime::HostFunctions` - all four
//! host functions (§6 A-D) - against this crate's real
//! `IdentityApi`/`AssignmentApi`/`RoleApi`/`ResourceApi`/
//! `DynamicPluginIdentityApi`, with namespace-scoped storage (a raft-backed
//! index decoupled from whichever `IdentityBackend` is configured, see
//! `crate::auth_plugin_identity`), `provision_domain_id`/
//! `allowed_provision_domains` enforcement (§6.B/D), connect-time SSRF
//! hardening for `http_fetch` (§6.A), and mandatory CADF audit (§6.E).
//!
//! Not yet implemented: wiring a
//! [`WasmPluginRegistry`](openstack_keystone_auth_plugin_runtime::WasmPluginRegistry)
//! into process startup / live auth dispatch - that's Phase 1's PR 1.2,
//! which is also where this crate's `HostFunctions` implementation first
//! becomes reachable from a live auth request.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use governor::clock::Clock;
use governor::{DefaultDirectRateLimiter, DefaultKeyedRateLimiter, Quota, RateLimiter};
use hmac::{Hmac, KeyInit, Mac};
use openstack_keystone_audit::{CadfEventPayload, Observer, Target};
use sha2::Sha256;
use tokio::sync::Semaphore;
use uuid::Uuid;

use openstack_keystone_auth_plugin_runtime::{
    AssignRoleRequest, GuestUserCreate, HostFunctions, HttpFetchRequest, HttpFetchResponse,
    ProvisionUserRequest, ResolvedIdentityHandle, RoleAssignmentTarget,
};
use openstack_keystone_config::DynamicPluginConfig;
use openstack_keystone_core_types::assignment::{AssignmentCreateBuilder, AssignmentType};
use openstack_keystone_core_types::identity::{UserCreateBuilder, UserType};
use openstack_keystone_core_types::role::RoleListParameters;

use crate::auth::ExecutionContext;
use crate::auth_plugin_http::DynamicPluginHttpFetcher;
use crate::cadf_hook::build_initiator_unknown;
use crate::keystone::ServiceState;

type HmacSha256 = Hmac<Sha256>;

/// Claims embedded in a [`ResolvedIdentityHandle`], HMAC-signed by
/// [`CoreHostFunctions::handle_key`] so a plugin can never fabricate one
/// (ADR 0025 §4 "Identity Binding"). A self-describing signed token rather
/// than an in-memory `handle -> (user_id, domain_id)` map: `extism`
/// registers host functions once per *compiled* module (shared across
/// every concurrent invocation of that plugin, see
/// `auth-plugin-runtime`'s `host_functions.rs`), not per `Store`, so
/// there is no per-invocation-scoped place to keep such a map safely
/// isolated between concurrent requests. A signed token gives the same
/// security property - unforgeable, resolves only to exactly what a prior
/// `provision_user`/`find_user` call in *this* plugin's namespace actually
/// returned - without relying on shared mutable state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct HandleClaims {
    plugin_name: String,
    user_id: String,
    domain_id: String,
    /// Unix-seconds expiry. A handle is only meant to survive the single
    /// `authenticate` round-trip that produced it, but host functions are
    /// shared across invocations (no per-`Store` state to scope a one-shot
    /// nonce to - see this struct's own rationale for signing rather than
    /// mapping), so there is no cheap place to record "this handle was
    /// consumed." A short TTL is the replay bound instead: past this instant
    /// [`CoreHostFunctions::verify_handle`] rejects the handle, so one
    /// captured by a buggy or compromised plugin cannot be re-presented in a
    /// later invocation to skip [`CoreHostFunctions::find_user`]'s
    /// live-`domain_id` re-check (ADR 0025 §4 "Admin-Authorized External
    /// Identity Linking").
    expires_at: i64,
}

/// How long a [`ResolvedIdentityHandle`] stays valid after issuance. Sized
/// generously against a plugin's own `timeout_ms` budget (the handle is
/// produced and echoed back within one `authenticate` invocation) while
/// still bounding replay to a small window regardless of process lifetime.
const HANDLE_TTL_SECS: i64 = 60;

#[derive(Debug, thiserror::Error)]
enum DynamicPluginHostError {
    #[error("no [auth_plugin.{0}] configuration found")]
    UnknownPlugin(String),
    #[error("domain {domain_id} is outside plugin {plugin_name}'s provisioning domain(s)")]
    DomainNotAllowed {
        plugin_name: String,
        domain_id: String,
    },
    #[error("identity backend error: {0}")]
    Identity(#[from] crate::identity::IdentityProviderError),
    #[error("dynamic plugin identity index error: {0}")]
    DynamicPluginIdentity(#[from] crate::auth_plugin_identity::AuthPluginIdentityProviderError),
    #[error("invalid or forged resolved_identity handle")]
    InvalidHandle,
    #[error("role {role} is not in plugin {plugin_name}'s assign_role_allowed list")]
    RoleNotAllowed { plugin_name: String, role: String },
    #[error("role {0} does not exist")]
    RoleNotFound(String),
    #[error("role {0} is ambiguous (multiple roles share this name)")]
    AmbiguousRole(String),
    #[error("project {0} does not exist")]
    ProjectNotFound(String),
    #[error("assignment backend error: {0}")]
    Assignment(#[from] crate::assignment::AssignmentProviderError),
    #[error("role backend error: {0}")]
    Role(#[from] crate::role::RoleProviderError),
    #[error("resource backend error: {0}")]
    Resource(#[from] crate::resource::ResourceProviderError),
    #[error("building assignment: {0}")]
    Builder(String),
    #[error("url {0} is not http(s)")]
    UnsupportedScheme(String),
    #[error("host {0} is not in this plugin's allowed_hosts")]
    HostNotAllowed(String),
    #[error("method {0} is not a supported HTTP method")]
    UnsupportedMethod(String),
    #[error("no allowed IP address resolved for host {0}")]
    NoAllowedAddress(String),
    #[error("http_fetch request error: {0}")]
    Http(String),
    #[error("http_fetch response exceeded the {0}-byte size cap")]
    ResponseTooLarge(usize),
    #[error("audit dispatch failed")]
    AuditChannelDead,
}

/// Emit a mandatory CADF audit record for a auth-plugin-related event
/// (ADR 0025 §6.E) - shared by [`CoreHostFunctions`]'s own host-function
/// audit trail and by `crate::auth_plugin_auth`'s `authenticate`
/// dispatch, so both paths produce audit events in exactly the same shape.
/// `Err(())` means the audit channel itself is dead (fail-closed
/// consideration is the caller's responsibility, per §6.E "mandatory
/// audit").
pub(crate) async fn emit_wasm_plugin_audit(
    state: &ServiceState,
    plugin_name: &str,
    host_function: &str,
    outcome: &str,
    outcome_reason: Option<String>,
) -> Result<(), ()> {
    let dispatcher = &state.audit_dispatcher;
    let node_id = dispatcher.node_id().to_string();
    let payload = CadfEventPayload::new(
        format!("{node_id}:{}", Uuid::new_v4()),
        "1.0".to_string(),
        "default".to_string(),
        Uuid::new_v4().to_string(),
        chrono::Utc::now().to_rfc3339(),
        format!("wasm_plugin.{host_function}"),
        outcome.to_string(),
        outcome_reason,
        build_initiator_unknown(),
        Target {
            id: plugin_name.to_string(),
            type_uri: "data/security/identity/wasm-plugin".to_string(),
        },
        Observer {
            node_id: node_id.clone(),
            id: format!("service/security/keystone/{node_id}"),
        },
    );
    let event = payload.sign(dispatcher);
    dispatcher.dispatch_critical(event).await.map_err(|_| ())
}

/// Emit a mandatory CADF audit record for a `route`-mode invocation (ADR
/// 0025 §4 "Guest Contract - `route` Mode", "Audit") - records the client's
/// originally-requested method list and, for a `Route` decision, the
/// resulting `target_method`, distinct from the eventually-dispatched
/// method's own audit trail, so an operator investigating a routing plugin
/// gone wrong doesn't see only the routed-to method as if the client had
/// requested it directly. Encoded into [`emit_wasm_plugin_audit`]'s
/// `outcome_reason` free-text field rather than widening the CADF payload
/// schema.
pub(crate) async fn emit_wasm_route_audit(
    state: &ServiceState,
    plugin_name: &str,
    requested_methods: &[String],
    decision: &str,
    target_method: Option<&str>,
    reason: Option<String>,
) -> Result<(), ()> {
    let mut outcome_reason = format!("requested_methods={requested_methods:?}");
    if let Some(target) = target_method {
        outcome_reason.push_str(&format!(" target_method={target}"));
    }
    if let Some(reason) = reason {
        outcome_reason.push_str(&format!(" reason={reason}"));
    }
    emit_wasm_plugin_audit(state, plugin_name, "route", decision, Some(outcome_reason)).await
}

/// Why a `authenticate` invocation was rejected before ever reaching the
/// plugin (ADR 0025 §7 "Invocation Rate Limiting & Concurrency").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitBound {
    PerSource,
    PerPlugin,
    Concurrency,
}

impl RateLimitBound {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PerSource => "per_source",
            Self::PerPlugin => "per_plugin",
            Self::Concurrency => "concurrency",
        }
    }
}

/// Per-plugin invocation bounds (ADR 0025 §7): a source-scoped token bucket,
/// a plugin-wide token bucket, and a concurrency semaphore, checked in that
/// order before a plugin's `authenticate` entry point is ever invoked - a
/// compromised or merely popular plugin cannot exhaust host resources or
/// amplify DoS/SSRF traffic (via `http_fetch`) by being invoked without
/// bound, and one plugin's exhausted budget never affects another's.
pub struct PluginInvocationLimiter {
    per_source: DefaultKeyedRateLimiter<String>,
    per_plugin: DefaultDirectRateLimiter,
    concurrency: Semaphore,
}

impl PluginInvocationLimiter {
    pub(crate) fn new(config: &DynamicPluginConfig) -> Self {
        let per_source_quota = Quota::per_minute(
            config
                .invocation_rate_limit_per_source_per_minute
                .try_into()
                .unwrap_or(std::num::NonZeroU32::MAX),
        );
        let per_plugin_quota = Quota::per_minute(
            config
                .invocation_rate_limit_per_minute
                .try_into()
                .unwrap_or(std::num::NonZeroU32::MAX),
        );
        Self {
            per_source: RateLimiter::keyed(per_source_quota),
            per_plugin: RateLimiter::direct(per_plugin_quota),
            concurrency: Semaphore::new(config.max_concurrent_invocations as usize),
        }
    }

    /// Bound 1 (only meaningful when `remote_addr` is known - a `None`
    /// caller silently skips this bound, falling back to bounds 2/3, per
    /// ADR §7's documented accepted gap for un-proxied deployments).
    ///
    /// On rejection, the paired [`Duration`] is the real wait time governor
    /// reports (`NotUntil::wait_time_from`), mirroring
    /// `RateLimitState::check_ip`'s ADR-0022 pattern so both limiter
    /// families surface an accurate `Retry-After` rather than a guess.
    pub(crate) fn check_per_source(
        &self,
        remote_addr: Option<&str>,
    ) -> Result<(), (RateLimitBound, std::time::Duration)> {
        match remote_addr {
            Some(addr) => self
                .per_source
                .check_key(&addr.to_string())
                .map_err(|not_until| {
                    let wait = not_until.wait_time_from(self.per_source.clock().now());
                    (RateLimitBound::PerSource, wait)
                }),
            None => Ok(()),
        }
    }

    /// Bound 2.
    pub(crate) fn check_per_plugin(&self) -> Result<(), (RateLimitBound, std::time::Duration)> {
        self.per_plugin.check().map_err(|not_until| {
            let wait = not_until.wait_time_from(self.per_plugin.clock().now());
            (RateLimitBound::PerPlugin, wait)
        })
    }

    /// Bound 3 - rejects immediately when saturated, never queues (ADR §7:
    /// "to avoid building an unbounded backlog of pending authentications
    /// under load"). A semaphore has no token-bucket refill schedule, so
    /// there's no real wait time to report; callers get a fixed 1-second
    /// hint, the same floor `check_ip` applies to its own worst case.
    pub(crate) fn try_acquire_concurrency_permit(
        &self,
    ) -> Result<tokio::sync::SemaphorePermit<'_>, (RateLimitBound, std::time::Duration)> {
        self.concurrency.try_acquire().map_err(|_| {
            (
                RateLimitBound::Concurrency,
                std::time::Duration::from_secs(1),
            )
        })
    }

    /// Drop per-source (bound 1) rate-limit state for source addresses that
    /// haven't been seen recently. Every distinct `remote_addr` bound 1 sees
    /// (necessarily including anonymous, pre-authentication callers - ADR §1
    /// Threat Model actor 2) allocates an entry in the keyed store that
    /// `governor` never expires on its own; left uncalled, a long-running
    /// process accumulates one entry per distinct source address forever.
    /// Intended to be called periodically (e.g. from the process's existing
    /// minute-scale cleanup tick), not per-request.
    pub fn shrink_idle_sources(&self) {
        self.per_source.retain_recent();
        self.per_source.shrink_to_fit();
    }
}

/// `openstack_keystone_auth_plugin_runtime::HostFunctions` implementation
/// backed by this crate's real `IdentityApi`/`AuditDispatcher`.
pub struct CoreHostFunctions {
    state: ServiceState,
    /// Process-lifetime random key signing [`HandleClaims`] (ADR §4
    /// "Identity Binding") - never persisted, never derived from
    /// operator-supplied config, so a handle cannot outlive the process
    /// that issued it, matching the ADR's "expires with that invocation"
    /// intent as closely as a stateless signed token can.
    handle_key: [u8; 32],
    /// Wire-level HTTP sender for `http_fetch` (ADR §6.A) - `reqwest`-free
    /// boundary, see `crate::auth_plugin_http`.
    http_fetcher: Arc<dyn DynamicPluginHttpFetcher>,
}

impl CoreHostFunctions {
    pub fn new(state: ServiceState, http_fetcher: Arc<dyn DynamicPluginHttpFetcher>) -> Self {
        use rand::RngExt;
        let mut handle_key = [0u8; 32];
        rand::rng().fill(&mut handle_key);
        Self {
            state,
            handle_key,
            http_fetcher,
        }
    }

    fn sign_handle(
        &self,
        plugin_name: &str,
        user_id: &str,
        domain_id: &str,
    ) -> ResolvedIdentityHandle {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

        let claims = HandleClaims {
            plugin_name: plugin_name.to_string(),
            user_id: user_id.to_string(),
            domain_id: domain_id.to_string(),
            expires_at: (chrono::Utc::now() + chrono::TimeDelta::seconds(HANDLE_TTL_SECS))
                .timestamp(),
        };
        let payload = serde_json::to_vec(&claims).expect("HandleClaims always serializes");
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&self.handle_key)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(&payload);
        let tag = mac.finalize().into_bytes();
        ResolvedIdentityHandle(format!("{}.{}", B64.encode(payload), B64.encode(tag)))
    }

    /// Verify a handle a plugin presented back via `Allow.resolved_identity`
    /// (ADR §4 step 3) and that it was issued for `plugin_name` - used by
    /// Phase 1's PR 1.2 auth-method dispatch, not by this crate itself yet.
    pub fn verify_handle(
        &self,
        plugin_name: &str,
        handle: &ResolvedIdentityHandle,
    ) -> Option<(String, String)> {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

        let (payload_b64, tag_b64) = handle.0.split_once('.')?;
        let payload = B64.decode(payload_b64).ok()?;
        let tag = B64.decode(tag_b64).ok()?;

        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&self.handle_key).ok()?;
        mac.update(&payload);
        mac.verify_slice(&tag).ok()?;

        let claims: HandleClaims = serde_json::from_slice(&payload).ok()?;
        if claims.plugin_name != plugin_name {
            return None;
        }
        // Reject an expired handle (replay past its issuance window) - see
        // `HandleClaims::expires_at`.
        if chrono::Utc::now().timestamp() > claims.expires_at {
            return None;
        }
        Some((claims.user_id, claims.domain_id))
    }

    async fn plugin_config(
        &self,
        plugin_name: &str,
    ) -> Result<DynamicPluginConfig, DynamicPluginHostError> {
        self.state
            .config_manager
            .config
            .read()
            .await
            .auth_plugin
            .get(plugin_name)
            .cloned()
            .ok_or_else(|| DynamicPluginHostError::UnknownPlugin(plugin_name.to_string()))
    }

    fn domain_allowed(config: &DynamicPluginConfig, domain_id: &str) -> bool {
        config.provision_domain_id.as_deref() == Some(domain_id)
            || config
                .allowed_provision_domains
                .iter()
                .any(|d| d == domain_id)
    }

    async fn audit(
        &self,
        plugin_name: &str,
        host_function: &str,
        outcome: &str,
        outcome_reason: Option<String>,
    ) -> Result<(), DynamicPluginHostError> {
        emit_wasm_plugin_audit(
            &self.state,
            plugin_name,
            host_function,
            outcome,
            outcome_reason,
        )
        .await
        .map_err(|()| DynamicPluginHostError::AuditChannelDead)
    }

    async fn provision_user_async(
        &self,
        plugin_name: &str,
        request: ProvisionUserRequest,
    ) -> Result<ResolvedIdentityHandle, DynamicPluginHostError> {
        let result = self.provision_user_inner(plugin_name, &request).await;
        match &result {
            Ok(_) => {
                self.audit(plugin_name, "provision_user", "success", None)
                    .await?;
            }
            Err(e) => {
                self.audit(
                    plugin_name,
                    "provision_user",
                    "failure",
                    Some(e.to_string()),
                )
                .await?;
            }
        }
        result
    }

    async fn provision_user_inner(
        &self,
        plugin_name: &str,
        request: &ProvisionUserRequest,
    ) -> Result<ResolvedIdentityHandle, DynamicPluginHostError> {
        let config = self.plugin_config(plugin_name).await?;
        if !Self::domain_allowed(&config, &request.user.domain_id) {
            return Err(DynamicPluginHostError::DomainNotAllowed {
                plugin_name: plugin_name.to_string(),
                domain_id: request.user.domain_id.clone(),
            });
        }

        let ctx = ExecutionContext::internal(&self.state);
        let identity = self.state.provider.get_identity_provider();
        let dpi = self.state.provider.get_auth_plugin_identity_provider();

        // Idempotent: a repeat call for an already-provisioned external_id
        // must resolve the same user, never create a duplicate (ADR §6.B).
        if let Some(user_id) = dpi.find(&ctx, plugin_name, &request.external_id).await? {
            let domain_id = identity.get_user_domain_id(&ctx, &user_id).await?;
            // Domain restriction is re-checked at *resolve* time, not only
            // at (initial) provisioning time (ADR §4 "Admin-Authorized
            // External Identity Linking" - the same live-domain re-check
            // `find_user_inner` applies below). This entry is not
            // necessarily one this plugin itself created via
            // `provision_user`: an admin may have linked a pre-existing
            // user to this `(plugin_name, external_id)` mapping, and that
            // user's domain can move after linking. Without this check, a
            // repeat `provision_user` call for the same `external_id` would
            // keep signing a handle for a user this plugin is no longer
            // configured to reach - the exact gap `find_user_inner` closes,
            // reopened one call path over.
            if !Self::domain_allowed(&config, &domain_id) {
                return Err(DynamicPluginHostError::DomainNotAllowed {
                    plugin_name: plugin_name.to_string(),
                    domain_id,
                });
            }
            return Ok(self.sign_handle(plugin_name, &user_id, &domain_id));
        }

        let GuestUserCreate {
            domain_id,
            name,
            enabled,
            extra,
        } = request.user.clone();
        let mut builder = UserCreateBuilder::default();
        builder
            .domain_id(domain_id)
            .name(name)
            .extra(extra)
            .user_type(UserType::Local);
        if let Some(enabled) = enabled {
            builder.enabled(enabled);
        }
        let user_create = builder.build().map_err(|e| {
            DynamicPluginHostError::Identity(crate::identity::IdentityProviderError::Driver(
                format!("building UserCreate for dynamic plugin provisioning: {e}"),
            ))
        })?;
        let created = identity.create_user(&ctx, user_create).await?;

        // Atomic on (plugin_name, external_id) - a concurrent provisioning
        // call for the same external_id may have already won; the mapping
        // insert's CAS is the serialization point, not this
        // check-then-create sequence (ADR §6.B).
        let canonical_user_id = dpi
            .create_or_resolve(&ctx, plugin_name, &request.external_id, &created.id)
            .await?;

        let (user_id, domain_id) = if canonical_user_id == created.id {
            (created.id, created.domain_id)
        } else {
            // Lost the race: best-effort clean up the orphaned user this
            // call created, and resolve the canonical winner's domain.
            let _ = identity.delete_user(&ctx, &created.id).await;
            let domain_id = identity
                .get_user_domain_id(&ctx, &canonical_user_id)
                .await?;
            (canonical_user_id, domain_id)
        };

        Ok(self.sign_handle(plugin_name, &user_id, &domain_id))
    }

    async fn find_user_async(
        &self,
        plugin_name: &str,
        external_id: String,
    ) -> Result<Option<ResolvedIdentityHandle>, DynamicPluginHostError> {
        let result = self.find_user_inner(plugin_name, &external_id).await;
        match &result {
            Ok(_) => {
                self.audit(plugin_name, "find_user", "success", None)
                    .await?;
            }
            Err(e) => {
                self.audit(plugin_name, "find_user", "failure", Some(e.to_string()))
                    .await?;
            }
        }
        result
    }

    async fn find_user_inner(
        &self,
        plugin_name: &str,
        external_id: &str,
    ) -> Result<Option<ResolvedIdentityHandle>, DynamicPluginHostError> {
        let config = self.plugin_config(plugin_name).await?;
        let ctx = ExecutionContext::internal(&self.state);
        let identity = self.state.provider.get_identity_provider();
        let dpi = self.state.provider.get_auth_plugin_identity_provider();

        let Some(user_id) = dpi.find(&ctx, plugin_name, external_id).await? else {
            return Ok(None);
        };

        // Lazy self-heal: unlike SCIM's raft index, this mapping has no
        // DB-level FK/cascade to the `user` table (ADR 0025 - decoupled from
        // whichever IdentityBackend is configured), so a hard-deleted user
        // is only *usually* caught proactively by
        // `DynamicPluginIdentityHook` (fire-and-forget, best-effort). This
        // read-time check is the correctness backstop: if the user is gone,
        // treat the mapping as absent and best-effort purge the stale entry.
        let Some(user) = identity.get_user(&ctx, &user_id).await? else {
            let _ = dpi.purge(&ctx, plugin_name, external_id).await;
            return Ok(None);
        };

        // Domain restriction is re-checked at *resolve* time, not only at
        // link time (ADR §4 "Admin-Authorized External Identity Linking") -
        // a user moved outside the plugin's configured domain(s) since
        // being linked/provisioned is no longer reachable.
        let domain_id = user.domain_id;
        if !Self::domain_allowed(&config, &domain_id) {
            return Ok(None);
        }

        Ok(Some(self.sign_handle(plugin_name, &user_id, &domain_id)))
    }

    async fn assign_role_async(
        &self,
        plugin_name: &str,
        request: AssignRoleRequest,
    ) -> Result<(), DynamicPluginHostError> {
        let result = self.assign_role_inner(plugin_name, &request).await;
        match &result {
            Ok(()) => {
                self.audit(plugin_name, "assign_role", "success", None)
                    .await?;
            }
            Err(e) => {
                self.audit(plugin_name, "assign_role", "failure", Some(e.to_string()))
                    .await?;
            }
        }
        result
    }

    async fn assign_role_inner(
        &self,
        plugin_name: &str,
        request: &AssignRoleRequest,
    ) -> Result<(), DynamicPluginHostError> {
        let config = self.plugin_config(plugin_name).await?;

        // Axis 1: which role (ADR §6.D "Which role").
        if !config
            .assign_role_allowed
            .iter()
            .any(|r| r == &request.role)
        {
            return Err(DynamicPluginHostError::RoleNotAllowed {
                plugin_name: plugin_name.to_string(),
                role: request.role.clone(),
            });
        }

        // Anti-impersonation: the actor must be a handle this exact plugin
        // itself resolved (same constraint as provision_user/find_user).
        let (user_id, _handle_domain_id) = self
            .verify_handle(plugin_name, &request.resolved_identity)
            .ok_or(DynamicPluginHostError::InvalidHandle)?;

        let ctx = ExecutionContext::internal(&self.state);

        // Axis 2: which target project/domain (ADR §6.D "Which target
        // project/domain") - resolved to the *domain* that governs it, so
        // both a direct domain target and a project's owning domain are
        // checked against the same provision_domain_id/
        // allowed_provision_domains set as provision_user.
        //
        // Axis 3: which scope type (ADR §6.D "Which scope type") is
        // enforced structurally, not by a runtime check: `RoleAssignmentTarget`
        // has no `System` variant at all, so there is no code path by which
        // a plugin invocation can even express a system-scope request.
        let (target_id, target_domain_id, assignment_type) = match &request.target {
            RoleAssignmentTarget::Domain { domain_id } => (
                domain_id.clone(),
                domain_id.clone(),
                AssignmentType::UserDomain,
            ),
            RoleAssignmentTarget::Project { project_id } => {
                let project = self
                    .state
                    .provider
                    .get_resource_provider()
                    .get_project(&ctx, project_id)
                    .await?
                    .ok_or_else(|| DynamicPluginHostError::ProjectNotFound(project_id.clone()))?;
                (
                    project_id.clone(),
                    project.domain_id,
                    AssignmentType::UserProject,
                )
            }
        };
        if !Self::domain_allowed(&config, &target_domain_id) {
            return Err(DynamicPluginHostError::DomainNotAllowed {
                plugin_name: plugin_name.to_string(),
                domain_id: target_domain_id,
            });
        }

        let roles = self
            .state
            .provider
            .get_role_provider()
            .list_roles(
                &ctx,
                &RoleListParameters {
                    name: Some(request.role.clone()),
                    ..Default::default()
                },
            )
            .await?;
        let role = match roles.as_slice() {
            [only] => only,
            [] => return Err(DynamicPluginHostError::RoleNotFound(request.role.clone())),
            _ => return Err(DynamicPluginHostError::AmbiguousRole(request.role.clone())),
        };

        let grant = AssignmentCreateBuilder::default()
            .actor_id(user_id)
            .role_id(role.id.clone())
            .role_name(request.role.clone())
            .target_id(target_id)
            .r#type(assignment_type)
            .inherited(false)
            .build()
            .map_err(|e| DynamicPluginHostError::Builder(e.to_string()))?;
        self.state
            .provider
            .get_assignment_provider()
            .create_grant(&ctx, grant)
            .await?;
        Ok(())
    }

    async fn http_fetch_async(
        &self,
        plugin_name: &str,
        request: HttpFetchRequest,
    ) -> Result<HttpFetchResponse, DynamicPluginHostError> {
        let result = self.http_fetch_inner(plugin_name, &request).await;
        // Never log the full URL (query strings can carry sensitive
        // parameters) - the host only, which is already known from config.
        let host_only = url::Url::parse(&request.url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_default();
        match &result {
            Ok(_) => {
                self.audit(plugin_name, "http_fetch", "success", Some(host_only))
                    .await?;
            }
            Err(e) => {
                self.audit(
                    plugin_name,
                    "http_fetch",
                    "failure",
                    Some(format!("{host_only}: {e}")),
                )
                .await?;
            }
        }
        result
    }

    async fn http_fetch_inner(
        &self,
        plugin_name: &str,
        request: &HttpFetchRequest,
    ) -> Result<HttpFetchResponse, DynamicPluginHostError> {
        const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
        const MAX_REDIRECTS: u8 = 5;

        let config = self.plugin_config(plugin_name).await?;
        let method = parse_method(&request.method)?;

        let mut current_url = url::Url::parse(&request.url)
            .map_err(|e| DynamicPluginHostError::Http(e.to_string()))?;
        let mut hops_remaining = if config.http_fetch_follow_redirects {
            MAX_REDIRECTS
        } else {
            0
        };
        // A per-hop timeout of `timeout_ms` each would let a chain of
        // redirects cost up to `MAX_REDIRECTS + 1` times the plugin's
        // configured budget in wall-clock time - this call's total
        // wall-clock cost (already counted against the plugin's overall
        // invocation `timeout_ms` per §7) must stay bounded to that single
        // budget regardless of how many hops it takes.
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(config.timeout_ms);

        let auth_header = match (
            &config.http_fetch_auth_header,
            &config.http_fetch_auth_secret_env,
        ) {
            (Some(header), Some(secret_env)) => {
                let secret = std::env::var(secret_env)
                    .map_err(|_| DynamicPluginHostError::Http(format!("{secret_env} not set")))?;
                Some((header.clone(), secret))
            }
            _ => None,
        };

        loop {
            let host = current_url
                .host_str()
                .ok_or_else(|| DynamicPluginHostError::UnsupportedScheme(current_url.to_string()))?
                .to_string();
            if current_url.scheme() != "http" && current_url.scheme() != "https" {
                return Err(DynamicPluginHostError::UnsupportedScheme(
                    current_url.scheme().to_string(),
                ));
            }
            if !config.allowed_hosts.iter().any(|h| h == &host) {
                return Err(DynamicPluginHostError::HostNotAllowed(host));
            }

            let port = current_url
                .port_or_known_default()
                .ok_or_else(|| DynamicPluginHostError::UnsupportedScheme(host.clone()))?;
            let addr = resolve_validated_addr(&host, port).await?;

            let remaining_ms = deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_millis() as u64;
            if remaining_ms == 0 {
                return Err(DynamicPluginHostError::Http(
                    "timeout_ms budget exhausted following redirects".to_string(),
                ));
            }

            let response = self
                .http_fetcher
                .fetch(
                    method,
                    current_url.as_str(),
                    addr,
                    &request.headers,
                    request.body.as_deref(),
                    remaining_ms,
                    auth_header.as_ref().map(|(h, s)| (h.as_str(), s.as_str())),
                    MAX_RESPONSE_BYTES,
                )
                .await
                .map_err(DynamicPluginHostError::Http)?;

            if (300..400).contains(&response.status)
                && hops_remaining > 0
                && let Some(location) = response
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                    .map(|(_, v)| v.clone())
                && let Ok(next) = current_url.join(&location)
            {
                current_url = next;
                hops_remaining -= 1;
                continue;
            }

            if let Some(len) = response.content_length
                && len as usize > MAX_RESPONSE_BYTES
            {
                return Err(DynamicPluginHostError::ResponseTooLarge(MAX_RESPONSE_BYTES));
            }
            if response.body.len() > MAX_RESPONSE_BYTES {
                return Err(DynamicPluginHostError::ResponseTooLarge(MAX_RESPONSE_BYTES));
            }

            return Ok(HttpFetchResponse {
                status: response.status,
                headers: response.headers.into_iter().collect(),
                body: String::from_utf8_lossy(&response.body).into_owned(),
            });
        }
    }
}

/// Connect-time IP re-validation (ADR 0025 §6.A): re-resolves `host` on
/// every call (no long-lived resolution cache) and rejects it if every
/// candidate address falls in a private/loopback/link-local/multicast/
/// cloud-metadata range. Returns the first allowed address - the caller
/// then hands that exact `SocketAddr` to `DynamicPluginHttpFetcher::fetch`,
/// never letting the HTTP client resolve the hostname a second time, which
/// is the load-bearing property that closes the standard DNS-rebinding
/// bypass of a hostname-only allowlist.
async fn resolve_validated_addr(
    host: &str,
    port: u16,
) -> Result<SocketAddr, DynamicPluginHostError> {
    let mut candidates = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| DynamicPluginHostError::Http(e.to_string()))?;
    candidates
        .find(|addr| !is_disallowed_ip(&addr.ip()))
        .ok_or_else(|| DynamicPluginHostError::NoAllowedAddress(host.to_string()))
}

/// True if `ip` falls in a private, loopback, link-local (which includes
/// the `169.254.169.254` cloud-metadata address), multicast, or otherwise
/// non-public range that `http_fetch` must never connect to (ADR §6.A).
fn is_disallowed_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                // Shared address space / carrier-grade NAT, 100.64.0.0/10
                // (RFC 6598) - routable inside many provider networks, so a
                // hostname-only allowlist could otherwise reach internal
                // infrastructure through it.
                || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
                // IETF protocol assignments, 192.0.0.0/24 (RFC 6890).
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                // Benchmarking, 198.18.0.0/15 (RFC 2544).
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                // Reserved / future use, 240.0.0.0/4 (RFC 1112);
                // 255.255.255.255 is already caught by `is_broadcast`.
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || (seg[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (seg[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                // IPv4-mapped ::ffff:0:0/96 - recurse on the embedded v4.
                || v6.to_ipv4_mapped().is_some_and(|v4| is_disallowed_ip(&IpAddr::V4(v4)))
                // IPv4-compatible ::/96 (deprecated) and NAT64 64:ff9b::/96
                // (RFC 6052) both carry an embedded v4 in the low 32 bits
                // that `to_ipv4_mapped` does not decode - recurse on it so a
                // private/loopback target can't be smuggled through either.
                // (`::`/`::1` are already caught by the unspecified/loopback
                // checks above and short-circuit before reaching here.)
                || ((seg[0..6] == [0, 0, 0, 0, 0, 0]
                    || seg[0..6] == [0x0064, 0xff9b, 0, 0, 0, 0])
                    && is_disallowed_ip(&IpAddr::V4(embedded_v4(seg[6], seg[7]))))
                // 6to4, 2002::/16 (RFC 3056) - embedded v4 is segments 1-2.
                || (seg[0] == 0x2002 && is_disallowed_ip(&IpAddr::V4(embedded_v4(seg[1], seg[2]))))
        }
    }
}

/// Reassemble an IPv4 address from the two 16-bit segments that carry it in
/// an IPv4-in-IPv6 encoding (mapped, compatible, NAT64, or 6to4).
fn embedded_v4(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8)
}

fn parse_method(method: &str) -> Result<&'static str, DynamicPluginHostError> {
    match method.to_ascii_uppercase().as_str() {
        "GET" => Ok("GET"),
        "POST" => Ok("POST"),
        "PUT" => Ok("PUT"),
        "PATCH" => Ok("PATCH"),
        "DELETE" => Ok("DELETE"),
        "HEAD" => Ok("HEAD"),
        other => Err(DynamicPluginHostError::UnsupportedMethod(other.to_string())),
    }
}

impl HostFunctions for CoreHostFunctions {
    fn provision_user(
        &self,
        plugin_name: &str,
        request: ProvisionUserRequest,
    ) -> Result<ResolvedIdentityHandle, String> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(self.provision_user_async(plugin_name, request))
        })
        .map_err(|e| e.to_string())
    }

    fn find_user(
        &self,
        plugin_name: &str,
        external_id: String,
    ) -> Result<Option<ResolvedIdentityHandle>, String> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(self.find_user_async(plugin_name, external_id))
        })
        .map_err(|e| e.to_string())
    }

    fn assign_role(&self, plugin_name: &str, request: AssignRoleRequest) -> Result<(), String> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.assign_role_async(plugin_name, request))
        })
        .map_err(|e| e.to_string())
    }

    fn http_fetch(
        &self,
        plugin_name: &str,
        request: HttpFetchRequest,
    ) -> Result<HttpFetchResponse, String> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.http_fetch_async(plugin_name, request))
        })
        .map_err(|e| e.to_string())
    }
}

/// Convenience for callers that only have an `Arc<CoreHostFunctions>` but
/// need `Arc<dyn HostFunctions>` (the type
/// `WasmPluginRegistry::load` expects).
pub fn as_host_functions(host: Arc<CoreHostFunctions>) -> Arc<dyn HostFunctions> {
    host
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use openstack_keystone_audit::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager};
    use openstack_keystone_core_types::identity::UserResponseBuilder;

    use crate::auth_plugin_identity::MockDynamicPluginIdentityProvider;
    use crate::identity::MockIdentityProvider;
    use crate::keystone::Service;
    use crate::policy::MockPolicy;
    use crate::provider::Provider;

    use super::*;

    fn plugin_config(extra: &str) -> DynamicPluginConfig {
        use config::{Config as RawConfig, File, FileFormat};

        #[derive(serde::Deserialize)]
        struct Wrapper {
            auth_plugin: HashMap<String, DynamicPluginConfig>,
        }

        let ini = format!(
            "[auth_plugin.acme]\npath = /nonexistent\nsha256 = {}\nmode = full_auth\ncapabilities = provision_user,find_user\n{extra}\n",
            "0".repeat(64),
        );
        let c = RawConfig::builder()
            .add_source(File::from_str(&ini, FileFormat::Ini))
            .build()
            .unwrap();
        let wrapper: Wrapper = c.try_deserialize().unwrap();
        wrapper.auth_plugin.into_iter().next().unwrap().1
    }

    /// Builds a `CoreHostFunctions` over a mocked `IdentityApi` and a
    /// *live* (non-noop) `AuditDispatcher` - unlike `AuditDispatcher::noop()`,
    /// whose receivers are dropped immediately, causing every
    /// `dispatch_critical` call to fail with `AuditChannelDead`. The
    /// receivers are kept alive (held, never drained) so the bounded
    /// channel doesn't fail sends for the small number of events a test
    /// emits.
    async fn host_functions(
        identity_mock: MockIdentityProvider,
        dpi_mock: MockDynamicPluginIdentityProvider,
        plugin_config_ini: &str,
    ) -> (
        CoreHostFunctions,
        openstack_keystone_audit::AuditChannelReceivers,
    ) {
        host_functions_with_provider(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_auth_plugin_identity(dpi_mock),
            plugin_config_ini,
        )
        .await
    }

    async fn host_functions_with_provider(
        provider: crate::provider::ProviderBuilder,
        plugin_config_ini: &str,
    ) -> (
        CoreHostFunctions,
        openstack_keystone_audit::AuditChannelReceivers,
    ) {
        host_functions_with_provider_and_fetcher(
            provider,
            plugin_config_ini,
            Arc::new(UnreachableHttpFetcher),
        )
        .await
    }

    async fn host_functions_with_provider_and_fetcher(
        provider: crate::provider::ProviderBuilder,
        plugin_config_ini: &str,
        http_fetcher: Arc<dyn DynamicPluginHttpFetcher>,
    ) -> (
        CoreHostFunctions,
        openstack_keystone_audit::AuditChannelReceivers,
    ) {
        let mut cfg = Config::default();
        cfg.auth_plugin
            .insert("acme".to_string(), plugin_config(plugin_config_ini));

        let (audit_dispatcher, receivers) = AuditDispatcher::new(
            "test-node",
            uuid::Uuid::new_v4().to_string(),
            Arc::from(b"test-hmac-key-32-bytes-long!!!!".as_slice()),
            0,
        );

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(cfg),
                sea_orm::DatabaseConnection::default(),
                provider.build().unwrap(),
                Arc::new(MockPolicy::default()),
                audit_dispatcher,
                None,
            )
            .await
            .unwrap(),
        );
        (CoreHostFunctions::new(state, http_fetcher), receivers)
    }

    /// Stub [`DynamicPluginHttpFetcher`] for tests whose assertions must
    /// short-circuit before ever reaching the wire (host/scheme/IP
    /// rejections) - panics if actually called, so a test that regresses
    /// into calling the network fails loudly instead of silently.
    struct UnreachableHttpFetcher;

    #[async_trait::async_trait]
    impl DynamicPluginHttpFetcher for UnreachableHttpFetcher {
        async fn fetch(
            &self,
            _method: &str,
            _url: &str,
            _resolved_addr: std::net::SocketAddr,
            _headers: &HashMap<String, String>,
            _body: Option<&str>,
            _timeout_ms: u64,
            _auth_header: Option<(&str, &str)>,
            _max_body_bytes: usize,
        ) -> Result<crate::auth_plugin_http::FetchResponse, String> {
            panic!("this test's http_fetch call must be rejected before reaching the wire")
        }
    }

    /// Scripted [`DynamicPluginHttpFetcher`] returning one canned response
    /// per call, used by tests that need `http_fetch` to actually complete.
    struct ScriptedHttpFetcher {
        responses:
            std::sync::Mutex<std::collections::VecDeque<crate::auth_plugin_http::FetchResponse>>,
        /// `(method, url, guest_headers, auth_header)` per call, for tests
        /// to assert core correctly separated guest headers from the
        /// host-injected auth header (attaching them in the right order is
        /// the `reqwest`-impl's job, not core's - core's job is only to
        /// pass both through distinctly).
        calls: std::sync::Mutex<
            Vec<(
                String,
                String,
                HashMap<String, String>,
                Option<(String, String)>,
            )>,
        >,
    }

    impl ScriptedHttpFetcher {
        /// `responses` are returned in order, one per call.
        fn new(responses: Vec<crate::auth_plugin_http::FetchResponse>) -> Self {
            Self {
                responses: std::sync::Mutex::new(responses.into()),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn calls(
            &self,
        ) -> Vec<(
            String,
            String,
            HashMap<String, String>,
            Option<(String, String)>,
        )> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl DynamicPluginHttpFetcher for ScriptedHttpFetcher {
        async fn fetch(
            &self,
            method: &str,
            url: &str,
            _resolved_addr: std::net::SocketAddr,
            headers: &HashMap<String, String>,
            _body: Option<&str>,
            _timeout_ms: u64,
            auth_header: Option<(&str, &str)>,
            _max_body_bytes: usize,
        ) -> Result<crate::auth_plugin_http::FetchResponse, String> {
            self.calls.lock().unwrap().push((
                method.to_string(),
                url.to_string(),
                headers.clone(),
                auth_header.map(|(n, v)| (n.to_string(), v.to_string())),
            ));
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| "ScriptedHttpFetcher ran out of canned responses".to_string())
        }
    }

    fn user_response(
        id: &str,
        domain_id: &str,
    ) -> openstack_keystone_core_types::identity::UserResponse {
        UserResponseBuilder::default()
            .id(id.to_string())
            .domain_id(domain_id.to_string())
            .name("dave".to_string())
            .enabled(true)
            .build()
            .unwrap()
    }

    fn provision_request(external_id: &str, domain_id: &str) -> ProvisionUserRequest {
        ProvisionUserRequest {
            external_id: external_id.to_string(),
            user: GuestUserCreate {
                domain_id: domain_id.to_string(),
                name: "Dave".to_string(),
                enabled: Some(true),
                extra: HashMap::new(),
            },
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_provision_user_creates_new_user_and_signs_handle() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_create_user()
            .returning(|_, _| Ok(user_response("u1", "d1")));

        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        dpi_mock.expect_find().returning(|_, _, _| Ok(None));
        dpi_mock
            .expect_create_or_resolve()
            .returning(|_, _, _, user_id| Ok(user_id.to_string()));

        let (host, _receivers) =
            host_functions(identity_mock, dpi_mock, "provision_domain_id = d1\n").await;

        let handle = host
            .provision_user("acme", provision_request("ext-1", "d1"))
            .expect("provisioning should succeed");
        let (user_id, domain_id) = host
            .verify_handle("acme", &handle)
            .expect("handle should verify");
        assert_eq!(user_id, "u1");
        assert_eq!(domain_id, "d1");

        // A handle issued for one plugin must never verify for another -
        // the plugin-name binding is what keeps one plugin from presenting a
        // handle another plugin minted (ADR 0025 §4 "Identity Binding").
        assert!(
            host.verify_handle("other_plugin", &handle).is_none(),
            "a handle must not verify under a different plugin_name"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_expired_handle_is_rejected() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

        let (host, _receivers) = host_functions(
            MockIdentityProvider::default(),
            MockDynamicPluginIdentityProvider::default(),
            "provision_domain_id = d1\n",
        )
        .await;

        // Hand-mint a handle that expired an hour ago, signed with the host's
        // real key, to prove `verify_handle` rejects on the TTL and not only
        // on a bad signature - i.e. a valid handle captured and replayed
        // outside its window (ADR 0025 §4 "Identity Binding") is refused.
        let claims = HandleClaims {
            plugin_name: "acme".to_string(),
            user_id: "u1".to_string(),
            domain_id: "d1".to_string(),
            expires_at: (chrono::Utc::now() - chrono::TimeDelta::hours(1)).timestamp(),
        };
        let payload = serde_json::to_vec(&claims).unwrap();
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&host.handle_key).unwrap();
        mac.update(&payload);
        let tag = mac.finalize().into_bytes();
        let handle =
            ResolvedIdentityHandle(format!("{}.{}", B64.encode(&payload), B64.encode(tag)));

        assert!(
            host.verify_handle("acme", &handle).is_none(),
            "an expired handle must not verify even with a valid signature"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_provision_user_is_idempotent() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user_domain_id()
            .returning(|_, _| Ok("d1".to_string()));
        identity_mock.expect_create_user().never();

        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        dpi_mock
            .expect_find()
            .returning(|_, _, _| Ok(Some("u1".to_string())));
        dpi_mock.expect_create_or_resolve().never();

        let (host, _receivers) =
            host_functions(identity_mock, dpi_mock, "provision_domain_id = d1\n").await;

        let handle = host
            .provision_user("acme", provision_request("ext-1", "d1"))
            .expect("repeat provisioning should resolve the existing mapping");
        let (user_id, _) = host.verify_handle("acme", &handle).unwrap();
        assert_eq!(user_id, "u1");
    }

    /// The idempotent repeat-call path (an entry already exists in the
    /// `(plugin_name, external_id)` mapping, whether from this plugin's own
    /// prior `provision_user` or an admin-authorized identity link) must
    /// re-check the resolved user's *live* domain, exactly like
    /// `find_user` does - a user moved outside the plugin's configured
    /// domain(s) since being linked/provisioned must stop being reachable
    /// immediately, not just via `find_user` (ADR §4 "Admin-Authorized
    /// External Identity Linking": "Domain restriction is re-checked at
    /// resolve time, not only at link time").
    #[tokio::test(flavor = "multi_thread")]
    async fn test_provision_user_repeat_call_denies_after_domain_move() {
        let mut identity_mock = MockIdentityProvider::default();
        // The user has since moved outside the plugin's configured domain.
        identity_mock
            .expect_get_user_domain_id()
            .returning(|_, _| Ok("some-other-domain".to_string()));
        identity_mock.expect_create_user().never();

        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        dpi_mock
            .expect_find()
            .returning(|_, _, _| Ok(Some("u1".to_string())));
        dpi_mock.expect_create_or_resolve().never();

        let (host, _receivers) =
            host_functions(identity_mock, dpi_mock, "provision_domain_id = d1\n").await;

        let err = host
            .provision_user("acme", provision_request("ext-1", "d1"))
            .expect_err("a user moved outside the plugin's domain(s) must not resolve a handle");
        assert!(err.contains("outside plugin"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_provision_user_domain_violation_fails_closed_without_touching_identity_backend() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_create_user().never();

        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        dpi_mock.expect_find().never();
        dpi_mock.expect_create_or_resolve().never();

        let (host, _receivers) =
            host_functions(identity_mock, dpi_mock, "provision_domain_id = d1\n").await;

        let err = host
            .provision_user("acme", provision_request("ext-1", "some-other-domain"))
            .expect_err("a domain outside provision_domain_id must be rejected");
        assert!(err.contains("outside plugin"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_provision_user_race_lost_deletes_orphan_and_resolves_winner() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_create_user()
            .returning(|_, _| Ok(user_response("loser", "d1")));
        identity_mock
            .expect_delete_user()
            .withf(|_, id| id == "loser")
            .times(1)
            .returning(|_, _| Ok(()));
        identity_mock
            .expect_get_user_domain_id()
            .withf(|_, id| id == "winner")
            .returning(|_, _| Ok("d1".to_string()));

        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        dpi_mock.expect_find().returning(|_, _, _| Ok(None));
        // A concurrent call already won the race for this external_id.
        dpi_mock
            .expect_create_or_resolve()
            .returning(|_, _, _, _| Ok("winner".to_string()));

        let (host, _receivers) =
            host_functions(identity_mock, dpi_mock, "provision_domain_id = d1\n").await;

        let handle = host
            .provision_user("acme", provision_request("ext-1", "d1"))
            .expect("provisioning should still succeed, resolving to the race winner");
        let (user_id, _) = host.verify_handle("acme", &handle).unwrap();
        assert_eq!(user_id, "winner");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_find_user_not_provisioned_returns_none() {
        let identity_mock = MockIdentityProvider::default();

        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        dpi_mock.expect_find().returning(|_, _, _| Ok(None));

        let (host, _receivers) =
            host_functions(identity_mock, dpi_mock, "provision_domain_id = d1\n").await;

        let found = host
            .find_user("acme", "ext-1".to_string())
            .expect("lookup itself should not error");
        assert!(found.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_find_user_denies_after_domain_move() {
        let mut identity_mock = MockIdentityProvider::default();
        // The user has since moved outside the plugin's configured domain.
        identity_mock
            .expect_get_user()
            .returning(|_, _| Ok(Some(user_response("u1", "some-other-domain"))));

        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        dpi_mock
            .expect_find()
            .returning(|_, _, _| Ok(Some("u1".to_string())));

        let (host, _receivers) =
            host_functions(identity_mock, dpi_mock, "provision_domain_id = d1\n").await;

        let found = host
            .find_user("acme", "ext-1".to_string())
            .expect("lookup itself should not error");
        assert!(
            found.is_none(),
            "a live domain mismatch must fail closed, resolving to not-found"
        );
    }

    /// Lazy self-heal (ADR 0025 orphan protection backstop): the raft index
    /// has no DB-level FK/cascade to `user`, so a mapping surviving past its
    /// user's hard-delete is possible if `DynamicPluginIdentityHook`'s
    /// fire-and-forget cleanup was dropped. `find_user` must still resolve
    /// to not-found (never hand back a handle for a nonexistent user), and
    /// must best-effort purge the stale entry it just detected.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_find_user_purges_stale_mapping_for_a_deleted_user() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| Ok(None));

        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        dpi_mock
            .expect_find()
            .returning(|_, _, _| Ok(Some("deleted-user".to_string())));
        dpi_mock
            .expect_purge()
            .withf(|_, plugin_name, external_id| plugin_name == "acme" && external_id == "ext-1")
            .times(1)
            .returning(|_, _, _| Ok(()));

        let (host, _receivers) =
            host_functions(identity_mock, dpi_mock, "provision_domain_id = d1\n").await;

        let found = host
            .find_user("acme", "ext-1".to_string())
            .expect("lookup itself should not error");
        assert!(
            found.is_none(),
            "a mapping pointing at a since-deleted user must resolve to not-found"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_verify_handle_rejects_wrong_plugin_name() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_create_user()
            .returning(|_, _| Ok(user_response("u1", "d1")));

        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        dpi_mock.expect_find().returning(|_, _, _| Ok(None));
        dpi_mock
            .expect_create_or_resolve()
            .returning(|_, _, _, user_id| Ok(user_id.to_string()));

        let (host, _receivers) =
            host_functions(identity_mock, dpi_mock, "provision_domain_id = d1\n").await;

        let handle = host
            .provision_user("acme", provision_request("ext-1", "d1"))
            .unwrap();
        assert!(
            host.verify_handle("a-different-plugin", &handle).is_none(),
            "a handle minted for one plugin must not verify for another"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_verify_handle_rejects_tampered_handle() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_create_user()
            .returning(|_, _| Ok(user_response("u1", "d1")));

        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        dpi_mock.expect_find().returning(|_, _, _| Ok(None));
        dpi_mock
            .expect_create_or_resolve()
            .returning(|_, _, _, user_id| Ok(user_id.to_string()));

        let (host, _receivers) =
            host_functions(identity_mock, dpi_mock, "provision_domain_id = d1\n").await;

        let handle = host
            .provision_user("acme", provision_request("ext-1", "d1"))
            .unwrap();
        let tampered = ResolvedIdentityHandle(format!("{}x", handle.0));
        assert!(host.verify_handle("acme", &tampered).is_none());
    }

    fn role(id: &str, name: &str) -> openstack_keystone_core_types::role::Role {
        openstack_keystone_core_types::role::RoleBuilder::default()
            .id(id.to_string())
            .name(name.to_string())
            .build()
            .unwrap()
    }

    fn project(id: &str, domain_id: &str) -> openstack_keystone_core_types::resource::Project {
        openstack_keystone_core_types::resource::ProjectBuilder::default()
            .id(id.to_string())
            .domain_id(domain_id.to_string())
            .enabled(true)
            .name("proj".to_string())
            .build()
            .unwrap()
    }

    fn assignment(
        params: &openstack_keystone_core_types::assignment::AssignmentCreate,
    ) -> openstack_keystone_core_types::assignment::Assignment {
        openstack_keystone_core_types::assignment::AssignmentBuilder::default()
            .actor_id(params.actor_id.clone())
            .role_id(params.role_id.clone())
            .target_id(params.target_id.clone())
            .r#type(params.r#type.clone())
            .build()
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_assign_role_grants_on_project_within_domain() {
        let mut role_mock = crate::role::MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .returning(|_, _| Ok(vec![role("role-1", "reader")]));

        let mut resource_mock = crate::resource::MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, id| id == "proj-1")
            .returning(|_, _| Ok(Some(project("proj-1", "d1"))));

        let mut assignment_mock = crate::assignment::MockAssignmentProvider::default();
        assignment_mock
            .expect_create_grant()
            .returning(|_, params| {
                assert_eq!(params.actor_id, "u1");
                assert_eq!(params.role_id, "role-1");
                assert_eq!(params.target_id, "proj-1");
                assert_eq!(
                    params.r#type,
                    openstack_keystone_core_types::assignment::AssignmentType::UserProject
                );
                Ok(assignment(&params))
            });

        let (host, _receivers) = host_functions_with_provider(
            Provider::mocked_builder()
                .mock_role(role_mock)
                .mock_resource(resource_mock)
                .mock_assignment(assignment_mock),
            "provision_domain_id = d1\nassign_role_allowed = reader\n",
        )
        .await;

        let handle = host.sign_handle("acme", "u1", "d1");
        host.assign_role(
            "acme",
            AssignRoleRequest {
                resolved_identity: handle,
                role: "reader".to_string(),
                target: RoleAssignmentTarget::Project {
                    project_id: "proj-1".to_string(),
                },
            },
        )
        .expect("assign_role should succeed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_assign_role_rejects_role_outside_allowlist() {
        let (host, _receivers) = host_functions_with_provider(
            Provider::mocked_builder(),
            "provision_domain_id = d1\nassign_role_allowed = reader\n",
        )
        .await;

        let handle = host.sign_handle("acme", "u1", "d1");
        let err = host
            .assign_role(
                "acme",
                AssignRoleRequest {
                    resolved_identity: handle,
                    role: "admin".to_string(),
                    target: RoleAssignmentTarget::Domain {
                        domain_id: "d1".to_string(),
                    },
                },
            )
            .expect_err("a role outside assign_role_allowed must be rejected");
        assert!(err.contains("assign_role_allowed"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_assign_role_rejects_project_outside_provisioning_domain() {
        let mut resource_mock = crate::resource::MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .returning(|_, _| Ok(Some(project("proj-1", "some-other-domain"))));

        let (host, _receivers) = host_functions_with_provider(
            Provider::mocked_builder().mock_resource(resource_mock),
            "provision_domain_id = d1\nassign_role_allowed = reader\n",
        )
        .await;

        let handle = host.sign_handle("acme", "u1", "d1");
        let err = host
            .assign_role(
                "acme",
                AssignRoleRequest {
                    resolved_identity: handle,
                    role: "reader".to_string(),
                    target: RoleAssignmentTarget::Project {
                        project_id: "proj-1".to_string(),
                    },
                },
            )
            .expect_err("a project outside the plugin's provisioning domain must be rejected");
        assert!(err.contains("outside plugin"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_assign_role_rejects_handle_from_a_different_plugin() {
        let (host, _receivers) = host_functions_with_provider(
            Provider::mocked_builder(),
            "provision_domain_id = d1\nassign_role_allowed = reader\n",
        )
        .await;

        // Signed for a different plugin_name than the one attempting to use it.
        let handle = host.sign_handle("some-other-plugin", "u1", "d1");
        let err = host
            .assign_role(
                "acme",
                AssignRoleRequest {
                    resolved_identity: handle,
                    role: "reader".to_string(),
                    target: RoleAssignmentTarget::Domain {
                        domain_id: "d1".to_string(),
                    },
                },
            )
            .expect_err("a handle minted for a different plugin must be rejected");
        assert!(err.contains("InvalidHandle") || err.contains("invalid"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_http_fetch_rejects_host_outside_allowlist() {
        let (host, _receivers) = host_functions_with_provider(
            Provider::mocked_builder(),
            "allowed_hosts = risk.acme.example.com\n",
        )
        .await;

        let err = host
            .http_fetch(
                "acme",
                HttpFetchRequest {
                    method: "GET".to_string(),
                    url: "https://evil.example.com/".to_string(),
                    headers: HashMap::new(),
                    body: None,
                },
            )
            .expect_err("a host outside allowed_hosts must be rejected");
        assert!(err.contains("allowed_hosts") || err.contains("not in this plugin"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_http_fetch_rejects_cloud_metadata_address() {
        // A host that resolves to the AWS/GCP/Azure metadata IP must be
        // rejected at connect time even if somehow allowlisted by name -
        // simulate this directly against the IP-range check rather than
        // relying on DNS behavior in a test environment.
        assert!(is_disallowed_ip(&"169.254.169.254".parse().unwrap()));
        assert!(is_disallowed_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_disallowed_ip(&"10.0.0.5".parse().unwrap()));
        assert!(is_disallowed_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_disallowed_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_disallowed_ip(&"::1".parse().unwrap()));
        assert!(is_disallowed_ip(&"fe80::1".parse().unwrap()));
        assert!(is_disallowed_ip(&"fc00::1".parse().unwrap()));
        // Shared address space (CGNAT, 100.64.0.0/10), IETF protocol
        // assignments (192.0.0.0/24), benchmarking (198.18.0.0/15), and
        // reserved (240.0.0.0/4) - all routable-looking but never legitimate
        // http_fetch targets.
        assert!(is_disallowed_ip(&"100.64.0.1".parse().unwrap()));
        assert!(is_disallowed_ip(&"100.127.255.255".parse().unwrap()));
        assert!(is_disallowed_ip(&"192.0.0.1".parse().unwrap()));
        assert!(is_disallowed_ip(&"198.18.0.1".parse().unwrap()));
        assert!(is_disallowed_ip(&"198.19.255.255".parse().unwrap()));
        assert!(is_disallowed_ip(&"240.0.0.1".parse().unwrap()));
        // IPv4-in-IPv6 encodings that carry a private/loopback v4 the naive
        // `to_ipv4_mapped`-only check would miss: IPv4-compatible ::/96,
        // NAT64 64:ff9b::/96, and 6to4 2002::/16.
        assert!(is_disallowed_ip(&"::7f00:1".parse().unwrap())); // ::127.0.0.1
        assert!(is_disallowed_ip(&"64:ff9b::a00:5".parse().unwrap())); // NAT64 10.0.0.5
        assert!(is_disallowed_ip(&"2002:a00:1::".parse().unwrap())); // 6to4 10.0.0.1
        // Genuinely public addresses still pass, including a 6to4 wrapping a
        // public v4 and an ordinary public v6.
        assert!(!is_disallowed_ip(&"93.184.216.34".parse().unwrap()));
        assert!(!is_disallowed_ip(&"100.63.255.255".parse().unwrap())); // just below CGNAT
        assert!(!is_disallowed_ip(&"2606:2800:220:1::".parse().unwrap()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_http_fetch_rejects_unsupported_scheme() {
        let (host, _receivers) = host_functions_with_provider(
            Provider::mocked_builder(),
            "allowed_hosts = risk.acme.example.com\n",
        )
        .await;

        let err = host
            .http_fetch(
                "acme",
                HttpFetchRequest {
                    method: "GET".to_string(),
                    url: "ftp://risk.acme.example.com/".to_string(),
                    headers: HashMap::new(),
                    body: None,
                },
            )
            .expect_err("a non-http(s) scheme must be rejected");
        assert!(err.contains("not http"));
    }

    /// End-to-end proof of the connect-time IP re-validation (ADR §6.A):
    /// `localhost` is allowlisted *by name*, but resolves to a loopback
    /// address, which must still be rejected - this is exactly the
    /// hostname-allowlist bypass the connect-time check exists to close
    /// (an operator who allowlists a legitimate-looking hostname has no
    /// control over what it resolves to).
    #[tokio::test(flavor = "multi_thread")]
    async fn test_http_fetch_rejects_hostname_that_resolves_to_loopback() {
        let (host, _receivers) =
            host_functions_with_provider(Provider::mocked_builder(), "allowed_hosts = localhost\n")
                .await;

        let err = host
            .http_fetch(
                "acme",
                HttpFetchRequest {
                    method: "GET".to_string(),
                    url: "http://localhost:1/".to_string(),
                    headers: HashMap::new(),
                    body: None,
                },
            )
            .expect_err("localhost must be rejected even though it's allowlisted by name");
        assert!(err.contains("no allowed IP address"));
    }

    fn ok_response(
        status: u16,
        headers: Vec<(&str, &str)>,
        body: &str,
    ) -> crate::auth_plugin_http::FetchResponse {
        crate::auth_plugin_http::FetchResponse {
            status,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            content_length: Some(body.len() as u64),
            body: body.as_bytes().to_vec(),
        }
    }

    /// Proves the `DynamicPluginHttpFetcher` trait boundary itself: core
    /// resolves+validates the IP (an IP-literal host needs no real DNS),
    /// then hands the request to the fetcher, separating guest headers from
    /// the host-injected auth header (attach-order/anti-shadowing is the
    /// `reqwest`-impl's responsibility, exercised in `keystone`'s own unit
    /// tests) and returns exactly what the fetcher returned.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_http_fetch_round_trips_through_the_fetcher_trait() {
        let fetcher = Arc::new(ScriptedHttpFetcher::new(vec![ok_response(
            200,
            vec![("content-type", "text/plain")],
            "hello",
        )]));

        let (host, _receivers) = host_functions_with_provider_and_fetcher(
            Provider::mocked_builder(),
            "allowed_hosts = 93.184.216.34\nhttp_fetch_auth_header = X-Auth\nhttp_fetch_auth_secret_env = DYNAMIC_PLUGIN_TEST_SECRET_ROUNDTRIP\n",
            fetcher.clone() as Arc<dyn DynamicPluginHttpFetcher>,
        )
        .await;

        // SAFETY: test-only, single-threaded w.r.t. this specific env var name.
        unsafe { std::env::set_var("DYNAMIC_PLUGIN_TEST_SECRET_ROUNDTRIP", "s3cr3t") };
        let mut guest_headers = HashMap::new();
        guest_headers.insert("X-Guest".to_string(), "1".to_string());

        let response = host
            .http_fetch(
                "acme",
                HttpFetchRequest {
                    method: "GET".to_string(),
                    url: "http://93.184.216.34/data".to_string(),
                    headers: guest_headers,
                    body: None,
                },
            )
            .expect("fetch should succeed via the scripted fetcher");
        unsafe { std::env::remove_var("DYNAMIC_PLUGIN_TEST_SECRET_ROUNDTRIP") };

        assert_eq!(response.status, 200);
        assert_eq!(response.body, "hello");

        let calls = fetcher.calls();
        assert_eq!(calls.len(), 1);
        let (method, url, guest, auth) = &calls[0];
        assert_eq!(method, "GET");
        assert_eq!(url, "http://93.184.216.34/data");
        assert_eq!(guest.get("X-Guest").map(String::as_str), Some("1"));
        assert_eq!(
            auth.as_ref().map(|(n, v)| (n.as_str(), v.as_str())),
            Some(("X-Auth", "s3cr3t"))
        );
    }

    /// Proves the manual, bounded, re-validated redirect loop still works
    /// with the fetcher trait boundary: a 302 followed by a 200 must
    /// resolve to the final response, having called the fetcher twice.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_http_fetch_follows_redirect_via_the_fetcher_trait() {
        let fetcher = Arc::new(ScriptedHttpFetcher::new(vec![
            ok_response(302, vec![("location", "/new")], ""),
            ok_response(200, vec![], "final"),
        ]));

        let (host, _receivers) = host_functions_with_provider_and_fetcher(
            Provider::mocked_builder(),
            "allowed_hosts = 93.184.216.34\nhttp_fetch_follow_redirects = true\n",
            fetcher.clone() as Arc<dyn DynamicPluginHttpFetcher>,
        )
        .await;

        let response = host
            .http_fetch(
                "acme",
                HttpFetchRequest {
                    method: "GET".to_string(),
                    url: "http://93.184.216.34/data".to_string(),
                    headers: HashMap::new(),
                    body: None,
                },
            )
            .expect("redirect should be followed to the final response");

        assert_eq!(response.status, 200);
        assert_eq!(response.body, "final");
        assert_eq!(fetcher.calls().len(), 2, "both hops must call the fetcher");
    }

    /// `shrink_idle_sources` must not evict a source whose bucket hasn't
    /// actually recovered yet - it exists to reclaim memory from truly idle
    /// (fully-recovered) sources (ADR §7, unbounded-keyed-store concern), not
    /// to reset an in-flight rate-limit decision. With a 1-per-minute quota,
    /// a source that has just consumed its only token is nowhere near
    /// "indistinguishable from fresh"; if `shrink_idle_sources` wrongly
    /// dropped it, the immediately-following check would incorrectly
    /// succeed against a brand-new bucket instead of being rejected.
    #[test]
    fn test_shrink_idle_sources_does_not_reset_an_exhausted_bucket() {
        let ini = "[auth_plugin.p]\npath = /dev/null\nsha256 = 0\nmode = full_auth\ninvocation_rate_limit_per_source_per_minute = 1\n";
        let config: openstack_keystone_config::DynamicPluginConfig = {
            use config::{Config as RawConfig, File, FileFormat};
            #[derive(serde::Deserialize)]
            struct Wrapper {
                auth_plugin: HashMap<String, openstack_keystone_config::DynamicPluginConfig>,
            }
            let c = RawConfig::builder()
                .add_source(File::from_str(ini, FileFormat::Ini))
                .build()
                .unwrap();
            let wrapper: Wrapper = c.try_deserialize().unwrap();
            wrapper.auth_plugin.into_iter().next().unwrap().1
        };

        let limiter = PluginInvocationLimiter::new(&config);
        limiter
            .check_per_source(Some("203.0.113.1"))
            .expect("first call within quota should succeed");
        limiter.shrink_idle_sources();
        let result = limiter.check_per_source(Some("203.0.113.1"));
        assert!(
            result.is_err(),
            "an exhausted source's bucket must not be reset by a shrink pass"
        );
    }
}
