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
//! ADR 0025 Phase 1 (PR 1.2): dispatch a `POST /v3/auth/tokens` request
//! naming an unrecognized `identity.<method>` to a loaded `mode = full_auth`
//! dynamic auth plugin's `authenticate` entry point.
//!
//! This is the seam between the HTTP-shaped request in `crates/keystone`
//! (which owns header/remote-addr extraction and the `Identity` catch-all
//! field) and the plugin's wasm boundary - the actual invocation,
//! response-bounds enforcement, identity-binding verification, and audit
//! trail all live here so `crates/keystone`'s dispatch loop
//! (`api/v3/auth/token/common.rs::authenticate_request`) stays a thin,
//! HTTP-shaped caller.
use std::collections::HashMap;

use openstack_keystone_auth_plugin_runtime::{
    AuthPluginRequest, AuthPluginResponse, MappingResponse, RouteRequest, RouteResponse,
    WORKLOAD_ID_CLAIM_KEY,
};
use openstack_keystone_config::{HARD_DENYLISTED_HEADERS, PluginMode};
use openstack_keystone_core_types::auth::{
    AuthenticationContext, AuthenticationResult, AuthenticationResultBuilder, IdentityInfo,
    PrincipalInfo, UserIdentityInfoBuilder,
};
use openstack_keystone_core_types::mapping::auth::MappingAuthRequest;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;

use crate::auth::ExecutionContext;
use crate::auth_plugin::{emit_wasm_plugin_audit, emit_wasm_route_audit};
use crate::keystone::ServiceState;
use crate::net::resolve_client_ip;

/// What the HTTP layer hands to [`authenticate_via_wasm_plugin`] - already
/// extracted from the framework-specific request/header types.
pub struct WasmPluginAuthRequest {
    /// The raw `identity.<plugin_name>` JSON block from the client's
    /// request body.
    pub payload: serde_json::Value,
    /// Every inbound request header, unfiltered - filtered down to
    /// `exposed_headers` (and defensively re-checked against
    /// [`HARD_DENYLISTED_HEADERS`]) inside this function, never passed to
    /// the plugin as-is.
    pub raw_headers: HashMap<String, String>,
    /// Raw public-interface TCP peer address. Internal/admin callers pass
    /// `None` even when their listener records a peer for audit logging.
    pub peer_ip: Option<std::net::IpAddr>,
}

#[derive(Debug, thiserror::Error)]
pub enum WasmPluginAuthError {
    #[error("no such dynamic auth plugin is loaded")]
    NotFound,
    #[error("plugin is not mode=full_auth")]
    WrongMode,
    #[error("plugin invocation failed: {0}")]
    InvokeFailed(String),
    #[error("authenticate response was malformed or exceeded its bounds: {0}")]
    MalformedResponse(String),
    #[error("resolved_identity handle failed verification")]
    InvalidHandle,
    #[error("invocation rate/concurrency limit exceeded: {0}")]
    RateLimited(&'static str, std::time::Duration),
    #[error("denied by plugin")]
    Denied(String),
    #[error("fetching the resolved user failed: {0}")]
    Identity(String),
    #[error("mapping engine failed: {0}")]
    MappingEngineFailed(String),
}

/// Dispatch one `identity.<plugin_name>` login attempt to that plugin's
/// `authenticate` entry point. Fails closed on every error path (ADR §7):
/// the caller is expected to map every non-`Denied` `Err` to the same
/// generic unauthorized response a client sees for any other failed
/// authentication attempt - a plugin's internal denial `reason` is audited,
/// never returned to the caller.
pub async fn authenticate_via_wasm_plugin(
    state: &ServiceState,
    plugin_name: &str,
    request: WasmPluginAuthRequest,
) -> Result<AuthenticationResult, WasmPluginAuthError> {
    let registry = state.auth_plugin_registry.read().await.clone();
    let Some(loaded) = registry.get(plugin_name) else {
        return Err(WasmPluginAuthError::NotFound);
    };

    let config = {
        let cfg = state.config_manager.config.read().await;
        cfg.auth_plugin.get(plugin_name).cloned()
    };
    let Some(config) = config else {
        return Err(WasmPluginAuthError::NotFound);
    };
    if config.mode != PluginMode::FullAuth {
        return Err(WasmPluginAuthError::WrongMode);
    }

    let Some(limiter) = state
        .auth_plugin_limiters
        .read()
        .await
        .get(plugin_name)
        .cloned()
    else {
        // Registry and limiter map are always populated together by
        // `load_auth_plugins` - reaching here means the plugin isn't
        // actually loaded, same as an ordinary registry-lookup miss.
        return Err(WasmPluginAuthError::NotFound);
    };

    let (trusted_proxies, trusted_header) = {
        let cfg = state.config_manager.config.read().await;
        (
            cfg.auth_plugins.trusted_proxies.clone(),
            cfg.auth_plugins.trusted_header,
        )
    };
    let remote_addr = resolve_client_ip(
        request
            .raw_headers
            .get(trusted_header.as_str())
            .map(String::as_str),
        trusted_header,
        request.peer_ip,
        &trusted_proxies,
    )
    .map(|ip| ip.to_string());

    // Rate/concurrency bounds (ADR §7), checked in order, cheapest and
    // most-specific first, before the plugin is ever invoked - a single
    // hammering source is rejected without ever touching the shared
    // per-plugin budget or a concurrency slot.
    if let Err((bound, retry_after)) = limiter.check_per_source(remote_addr.as_deref()) {
        let _ = emit_wasm_plugin_audit(
            state,
            plugin_name,
            "authenticate",
            "rate_limited",
            Some(bound.as_str().to_string()),
        )
        .await;
        return Err(WasmPluginAuthError::RateLimited(
            bound.as_str(),
            retry_after,
        ));
    }
    if let Err((bound, retry_after)) = limiter.check_per_plugin() {
        let _ = emit_wasm_plugin_audit(
            state,
            plugin_name,
            "authenticate",
            "rate_limited",
            Some(bound.as_str().to_string()),
        )
        .await;
        return Err(WasmPluginAuthError::RateLimited(
            bound.as_str(),
            retry_after,
        ));
    }
    let _permit = match limiter.try_acquire_concurrency_permit() {
        Ok(permit) => permit,
        Err((bound, retry_after)) => {
            let _ = emit_wasm_plugin_audit(
                state,
                plugin_name,
                "authenticate",
                "rate_limited",
                Some(bound.as_str().to_string()),
            )
            .await;
            return Err(WasmPluginAuthError::RateLimited(
                bound.as_str(),
                retry_after,
            ));
        }
    };

    // Allowlist down to `exposed_headers`, then defensively re-check none
    // of `HARD_DENYLISTED_HEADERS` survived - config-load already rejects
    // a plugin config listing one (`crates/config/src/auth_plugins.rs`),
    // this is the request-time belt-and-suspenders layer.
    let headers: HashMap<String, String> = request
        .raw_headers
        .into_iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            config
                .exposed_headers
                .iter()
                .any(|h| h.eq_ignore_ascii_case(name))
                && !HARD_DENYLISTED_HEADERS.contains(&lower.as_str())
        })
        .collect();

    let auth_request = AuthPluginRequest {
        payload: request.payload,
        headers,
        remote_addr,
    };
    let input = serde_json::to_vec(&auth_request)
        .map_err(|e| WasmPluginAuthError::InvokeFailed(e.to_string()))?;

    // `LoadedPlugin::invoke` runs the guest module synchronously (up to
    // `timeout_ms` of wall-clock time) - `block_in_place` hands this worker
    // thread's other work to a different thread for the duration, so a slow
    // or spinning plugin invocation doesn't stall unrelated async tasks
    // sharing this runtime.
    let raw_response = match tokio::task::block_in_place(|| loaded.invoke("authenticate", &input)) {
        Ok(bytes) => bytes,
        Err(e) => {
            let _ = emit_wasm_plugin_audit(
                state,
                plugin_name,
                "authenticate",
                "failure",
                Some(e.to_string()),
            )
            .await;
            return Err(WasmPluginAuthError::InvokeFailed(e.to_string()));
        }
    };

    let response =
        match openstack_keystone_auth_plugin_runtime::decode_and_validate_response(&raw_response) {
            Ok(response) => response,
            Err(e) => {
                let _ = emit_wasm_plugin_audit(
                    state,
                    plugin_name,
                    "authenticate",
                    "failure",
                    Some(e.to_string()),
                )
                .await;
                return Err(WasmPluginAuthError::MalformedResponse(e.to_string()));
            }
        };

    let (resolved_identity, claims) = match response {
        AuthPluginResponse::Deny { reason } => {
            let _ = emit_wasm_plugin_audit(
                state,
                plugin_name,
                "authenticate",
                "failure",
                Some(reason.clone()),
            )
            .await;
            return Err(WasmPluginAuthError::Denied(reason));
        }
        AuthPluginResponse::Allow {
            resolved_identity,
            claims,
        } => (resolved_identity, claims),
    };

    let Some(core_host_functions) = state.core_host_functions.read().await.clone() else {
        return Err(WasmPluginAuthError::InvalidHandle);
    };
    let Some((user_id, _domain_id)) =
        core_host_functions.verify_handle(plugin_name, &resolved_identity)
    else {
        // A handle that fails verification here means either a forged/
        // tampered handle or one issued for a different plugin - audited
        // as a suspicious event, distinct from an ordinary plugin-side
        // denial (ADR §4 "Identity Binding" step 3).
        let _ = emit_wasm_plugin_audit(
            state,
            plugin_name,
            "authenticate",
            "suspicious",
            Some("resolved_identity handle failed verification".to_string()),
        )
        .await;
        return Err(WasmPluginAuthError::InvalidHandle);
    };

    let ctx = ExecutionContext::internal(state);
    let user = state
        .provider
        .get_identity_provider()
        .get_user(&ctx, &user_id)
        .await
        .map_err(|e| WasmPluginAuthError::Identity(e.to_string()))?
        .ok_or_else(|| {
            WasmPluginAuthError::Identity("resolved user no longer exists".to_string())
        })?;

    let _ = emit_wasm_plugin_audit(state, plugin_name, "authenticate", "success", None).await;

    let result = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::WasmPlugin {
            plugin_name: plugin_name.to_string(),
            claims,
            token: None,
        })
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user_id)
                    .user(user)
                    .build()
                    .map_err(|e| WasmPluginAuthError::Identity(e.to_string()))?,
            ),
        })
        .build()
        .map_err(|e| WasmPluginAuthError::Identity(e.to_string()))?;

    Ok(result)
}

/// Flattens a `mapping`-mode plugin's `Claims` map (top-level
/// `HashMap<String, serde_json::Value>`, per [`MappingResponse::Claims`])
/// into the dotted-key, multi-valued shape the Mapping Engine expects
/// (`HashMap<String, Vec<String>>`, [`MappingAuthRequest::claims`]) - the
/// same convention every other `IdentitySource` ingress adapter already
/// normalizes its claims into (e.g. federation's `flatten_federation_claims`
/// in `crates/keystone/src/federation/api/common.rs`, not reusable here
/// since `core` cannot depend on the `keystone` crate). Nested objects
/// become dotted paths (`"a.b"`); a scalar array is collected in place;
/// an array containing a nested object is flattened with indexed keys
/// (`"a.0"`, `"a.1"`).
fn flatten_plugin_claims(
    claims: &HashMap<String, serde_json::Value>,
) -> HashMap<String, Vec<String>> {
    fn is_scalar(v: &serde_json::Value) -> bool {
        !matches!(
            v,
            serde_json::Value::Array(_) | serde_json::Value::Object(_)
        )
    }

    fn scalar_as_string(v: &serde_json::Value) -> Option<String> {
        match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            serde_json::Value::Bool(b) => Some(b.to_string()),
            serde_json::Value::Null => None,
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => None,
        }
    }

    fn flatten_into(key: &str, value: &serde_json::Value, out: &mut HashMap<String, Vec<String>>) {
        match value {
            serde_json::Value::Object(map) => {
                for (sub_key, sub_val) in map {
                    flatten_into(&format!("{key}.{sub_key}"), sub_val, out);
                }
            }
            serde_json::Value::Array(items) if items.iter().all(is_scalar) => {
                let values: Vec<String> = items.iter().filter_map(scalar_as_string).collect();
                if !values.is_empty() {
                    out.entry(key.to_string()).or_default().extend(values);
                }
            }
            serde_json::Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    flatten_into(&format!("{key}.{i}"), item, out);
                }
            }
            other => {
                if let Some(s) = scalar_as_string(other) {
                    out.entry(key.to_string()).or_default().push(s);
                }
            }
        }
    }

    let mut out = HashMap::new();
    for (key, value) in claims {
        flatten_into(key, value, &mut out);
    }
    out
}

/// Dispatch one `identity.<plugin_name>` login attempt to that plugin's
/// `mapping` entry point (ADR 0025 §4 "mapping Mode"). Unlike
/// [`authenticate_via_wasm_plugin`], the plugin never names an identity -
/// its `Claims` response is handed to the existing, already-reviewed
/// Mapping Engine (ADR 0020) under `provider_id = "wasm:<plugin_name>"`,
/// exactly as if it came from an OIDC/K8s/SPIFFE ingress adapter. The
/// Mapping Engine, not this function, produces the eventual
/// `AuthenticationContext::Mapping(...)` and is fail-closed by construction:
/// no `MappingRuleSet` authored under that `provider_id` means no login
/// succeeds (`MappingProviderError::NotFound`/`NoMatchingRule`).
pub async fn authenticate_via_wasm_mapping_plugin(
    state: &ServiceState,
    plugin_name: &str,
    request: WasmPluginAuthRequest,
) -> Result<AuthenticationResult, WasmPluginAuthError> {
    let registry = state.auth_plugin_registry.read().await.clone();
    let Some(loaded) = registry.get(plugin_name) else {
        return Err(WasmPluginAuthError::NotFound);
    };

    let config = {
        let cfg = state.config_manager.config.read().await;
        cfg.auth_plugin.get(plugin_name).cloned()
    };
    let Some(config) = config else {
        return Err(WasmPluginAuthError::NotFound);
    };
    if config.mode != PluginMode::Mapping {
        return Err(WasmPluginAuthError::WrongMode);
    }

    let Some(limiter) = state
        .auth_plugin_limiters
        .read()
        .await
        .get(plugin_name)
        .cloned()
    else {
        return Err(WasmPluginAuthError::NotFound);
    };

    let (trusted_proxies, trusted_header) = {
        let cfg = state.config_manager.config.read().await;
        (
            cfg.auth_plugins.trusted_proxies.clone(),
            cfg.auth_plugins.trusted_header,
        )
    };
    let remote_addr = resolve_client_ip(
        request
            .raw_headers
            .get(trusted_header.as_str())
            .map(String::as_str),
        trusted_header,
        request.peer_ip,
        &trusted_proxies,
    )
    .map(|ip| ip.to_string());

    if let Err((bound, retry_after)) = limiter.check_per_source(remote_addr.as_deref()) {
        let _ = emit_wasm_plugin_audit(
            state,
            plugin_name,
            "mapping",
            "rate_limited",
            Some(bound.as_str().to_string()),
        )
        .await;
        return Err(WasmPluginAuthError::RateLimited(
            bound.as_str(),
            retry_after,
        ));
    }
    if let Err((bound, retry_after)) = limiter.check_per_plugin() {
        let _ = emit_wasm_plugin_audit(
            state,
            plugin_name,
            "mapping",
            "rate_limited",
            Some(bound.as_str().to_string()),
        )
        .await;
        return Err(WasmPluginAuthError::RateLimited(
            bound.as_str(),
            retry_after,
        ));
    }
    let _permit = match limiter.try_acquire_concurrency_permit() {
        Ok(permit) => permit,
        Err((bound, retry_after)) => {
            let _ = emit_wasm_plugin_audit(
                state,
                plugin_name,
                "mapping",
                "rate_limited",
                Some(bound.as_str().to_string()),
            )
            .await;
            return Err(WasmPluginAuthError::RateLimited(
                bound.as_str(),
                retry_after,
            ));
        }
    };

    let headers: HashMap<String, String> = request
        .raw_headers
        .into_iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            config
                .exposed_headers
                .iter()
                .any(|h| h.eq_ignore_ascii_case(name))
                && !HARD_DENYLISTED_HEADERS.contains(&lower.as_str())
        })
        .collect();

    let auth_request = AuthPluginRequest {
        payload: request.payload,
        headers,
        remote_addr,
    };
    let input = serde_json::to_vec(&auth_request)
        .map_err(|e| WasmPluginAuthError::InvokeFailed(e.to_string()))?;

    // See the `authenticate` dispatch's identical comment above -
    // `block_in_place` keeps a slow/spinning guest invocation from stalling
    // unrelated async work on this runtime.
    let raw_response = match tokio::task::block_in_place(|| loaded.invoke("mapping", &input)) {
        Ok(bytes) => bytes,
        Err(e) => {
            let _ = emit_wasm_plugin_audit(
                state,
                plugin_name,
                "mapping",
                "failure",
                Some(e.to_string()),
            )
            .await;
            return Err(WasmPluginAuthError::InvokeFailed(e.to_string()));
        }
    };

    let response =
        match openstack_keystone_auth_plugin_runtime::decode_and_validate_mapping_response(
            &raw_response,
        ) {
            Ok(response) => response,
            Err(e) => {
                let _ = emit_wasm_plugin_audit(
                    state,
                    plugin_name,
                    "mapping",
                    "failure",
                    Some(e.to_string()),
                )
                .await;
                return Err(WasmPluginAuthError::MalformedResponse(e.to_string()));
            }
        };

    let claims = match response {
        MappingResponse::Deny { reason } => {
            let _ = emit_wasm_plugin_audit(
                state,
                plugin_name,
                "mapping",
                "failure",
                Some(reason.clone()),
            )
            .await;
            return Err(WasmPluginAuthError::Denied(reason));
        }
        MappingResponse::Claims { claims } => claims,
    };

    // Guaranteed present and a string by `decode_and_validate_mapping_response`.
    let unique_workload_id = claims
        .get(WORKLOAD_ID_CLAIM_KEY)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let ctx = ExecutionContext::internal(state);
    let mapping_req = MappingAuthRequest {
        domain_id: None,
        source: IdentitySource::WasmPlugin {
            plugin_name: plugin_name.to_string(),
        },
        unique_workload_id,
        claims: flatten_plugin_claims(&claims),
        rule_name: None,
    };

    let result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&ctx, &mapping_req)
        .await
        .map_err(|e| WasmPluginAuthError::MappingEngineFailed(e.to_string()));

    match &result {
        Ok(_) => {
            let _ = emit_wasm_plugin_audit(state, plugin_name, "mapping", "success", None).await;
        }
        Err(e) => {
            let _ = emit_wasm_plugin_audit(
                state,
                plugin_name,
                "mapping",
                "failure",
                Some(e.to_string()),
            )
            .await;
        }
    }

    result
}

/// What a `route`-mode plugin's `route` entry point decided (ADR 0025 §4
/// "Guest Contract - `route` Mode"). `target_method: None` means
/// `Passthrough` - the caller dispatches the request exactly as received,
/// as if no router plugin were installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    pub target_method: Option<String>,
    pub payload: Option<serde_json::Value>,
}

/// Dispatch a pre-dispatch routing decision to a `mode = route` plugin's
/// `route` entry point (ADR 0025 §4 "Guest Contract - `route` Mode"). Unlike
/// [`authenticate_via_wasm_plugin`]/[`authenticate_via_wasm_mapping_plugin`],
/// this runs *before* the caller's per-method dispatch loop, on the client's
/// full, raw `identity.methods` list, and never authenticates anyone - it
/// only ever relabels which already-registered method should handle the
/// request. `methods`/`payloads` are already filtered by the caller to
/// exactly this plugin's `inspect_methods` (a router never sees a block it
/// wasn't configured to inspect). A `Route { target_method, .. }` naming a
/// method outside the plugin's configured `route_targets` is rejected as
/// malformed (§7 posture: reject, never redirect to an unintended handler),
/// since the guest contract's own bounds-checker
/// (`decode_and_validate_route_response`) has no visibility into `core`/
/// config state.
pub async fn route_via_wasm_plugin(
    state: &ServiceState,
    plugin_name: &str,
    methods: &[String],
    payloads: HashMap<String, serde_json::Value>,
    raw_headers: HashMap<String, String>,
    peer_ip: Option<std::net::IpAddr>,
) -> Result<RouteDecision, WasmPluginAuthError> {
    let registry = state.auth_plugin_registry.read().await.clone();
    let Some(loaded) = registry.get(plugin_name) else {
        return Err(WasmPluginAuthError::NotFound);
    };

    let config = {
        let cfg = state.config_manager.config.read().await;
        cfg.auth_plugin.get(plugin_name).cloned()
    };
    let Some(config) = config else {
        return Err(WasmPluginAuthError::NotFound);
    };
    if config.mode != PluginMode::Route {
        return Err(WasmPluginAuthError::WrongMode);
    }

    let Some(limiter) = state
        .auth_plugin_limiters
        .read()
        .await
        .get(plugin_name)
        .cloned()
    else {
        return Err(WasmPluginAuthError::NotFound);
    };

    let (trusted_proxies, trusted_header) = {
        let cfg = state.config_manager.config.read().await;
        (
            cfg.auth_plugins.trusted_proxies.clone(),
            cfg.auth_plugins.trusted_header,
        )
    };
    let remote_addr = resolve_client_ip(
        raw_headers.get(trusted_header.as_str()).map(String::as_str),
        trusted_header,
        peer_ip,
        &trusted_proxies,
    )
    .map(|ip| ip.to_string());

    // Independent budget from the target method's own (ADR §7 "Fail-closed,
    // independent budget") - falls out for free since `limiter` is looked
    // up by this router's own `plugin_name`, a separate
    // `PluginInvocationLimiter` instance from any target method's.
    if let Err((bound, retry_after)) = limiter.check_per_source(remote_addr.as_deref()) {
        let _ = emit_wasm_route_audit(
            state,
            plugin_name,
            methods,
            "rate_limited",
            None,
            Some(bound.as_str().to_string()),
        )
        .await;
        return Err(WasmPluginAuthError::RateLimited(
            bound.as_str(),
            retry_after,
        ));
    }
    if let Err((bound, retry_after)) = limiter.check_per_plugin() {
        let _ = emit_wasm_route_audit(
            state,
            plugin_name,
            methods,
            "rate_limited",
            None,
            Some(bound.as_str().to_string()),
        )
        .await;
        return Err(WasmPluginAuthError::RateLimited(
            bound.as_str(),
            retry_after,
        ));
    }
    let _permit = match limiter.try_acquire_concurrency_permit() {
        Ok(permit) => permit,
        Err((bound, retry_after)) => {
            let _ = emit_wasm_route_audit(
                state,
                plugin_name,
                methods,
                "rate_limited",
                None,
                Some(bound.as_str().to_string()),
            )
            .await;
            return Err(WasmPluginAuthError::RateLimited(
                bound.as_str(),
                retry_after,
            ));
        }
    };

    let headers: HashMap<String, String> = raw_headers
        .into_iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            config
                .exposed_headers
                .iter()
                .any(|h| h.eq_ignore_ascii_case(name))
                && !HARD_DENYLISTED_HEADERS.contains(&lower.as_str())
        })
        .collect();

    let route_request = RouteRequest {
        methods: methods.to_vec(),
        headers,
        payloads,
        remote_addr,
    };
    let input = serde_json::to_vec(&route_request)
        .map_err(|e| WasmPluginAuthError::InvokeFailed(e.to_string()))?;

    // See the `authenticate` dispatch's identical comment above -
    // `block_in_place` keeps a slow/spinning guest invocation from stalling
    // unrelated async work on this runtime.
    let raw_response = match tokio::task::block_in_place(|| loaded.invoke("route", &input)) {
        Ok(bytes) => bytes,
        Err(e) => {
            let _ = emit_wasm_route_audit(
                state,
                plugin_name,
                methods,
                "failure",
                None,
                Some(e.to_string()),
            )
            .await;
            return Err(WasmPluginAuthError::InvokeFailed(e.to_string()));
        }
    };

    let response = match openstack_keystone_auth_plugin_runtime::decode_and_validate_route_response(
        &raw_response,
    ) {
        Ok(response) => response,
        Err(e) => {
            let _ = emit_wasm_route_audit(
                state,
                plugin_name,
                methods,
                "failure",
                None,
                Some(e.to_string()),
            )
            .await;
            return Err(WasmPluginAuthError::MalformedResponse(e.to_string()));
        }
    };

    match response {
        RouteResponse::Passthrough => {
            let _ =
                emit_wasm_route_audit(state, plugin_name, methods, "passthrough", None, None).await;
            Ok(RouteDecision {
                target_method: None,
                payload: None,
            })
        }
        RouteResponse::Route {
            target_method,
            payload,
        } => {
            if !config.route_targets.iter().any(|t| t == &target_method) {
                let _ = emit_wasm_route_audit(
                    state,
                    plugin_name,
                    methods,
                    "failure",
                    Some(&target_method),
                    Some("target_method outside configured route_targets".to_string()),
                )
                .await;
                return Err(WasmPluginAuthError::MalformedResponse(format!(
                    "target_method `{target_method}` is not in this plugin's route_targets"
                )));
            }
            let _ = emit_wasm_route_audit(
                state,
                plugin_name,
                methods,
                "route",
                Some(&target_method),
                None,
            )
            .await;
            Ok(RouteDecision {
                target_method: Some(target_method),
                payload: Some(payload),
            })
        }
        RouteResponse::Deny { reason } => {
            let _ = emit_wasm_route_audit(
                state,
                plugin_name,
                methods,
                "deny",
                None,
                Some(reason.clone()),
            )
            .await;
            Err(WasmPluginAuthError::Denied(reason))
        }
    }
}

/// End-to-end acceptance tests against the real, compiled reference plugin
/// (`crates/auth-plugin-runtime/tests/fixtures/reference-plugin`) - not
/// a mock of the wasm boundary, proving `authenticate_via_wasm_plugin`'s
/// full path (registry lookup, real `extism` invocation, response-bounds
/// decoding, identity-binding verification, `AuthenticationContext`
/// construction) actually works together, matching the plan's acceptance
/// criteria: provision on first login, idempotent second login, bad-handle
/// denial, claims land under `plugin_claims.<plugin_name>.*` only.
#[cfg(test)]
mod acceptance_tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{Arc, Mutex};

    use openstack_keystone_audit::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager, DynamicPluginsSection};
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use sha2::{Digest, Sha256};

    use crate::auth_plugin_http::{DynamicPluginHttpFetcher, FetchResponse};
    use crate::auth_plugin_identity::MockDynamicPluginIdentityProvider;
    use crate::auth_plugin_startup::load_auth_plugins;
    use crate::identity::MockIdentityProvider;
    use crate::keystone::Service;
    use crate::policy::MockPolicy;
    use crate::provider::Provider;

    use super::*;

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
        ) -> Result<FetchResponse, String> {
            panic!("this test's plugin doesn't grant http_fetch")
        }
    }

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../auth-plugin-runtime/tests/fixtures/reference-plugin")
    }

    /// Builds the reference plugin fixture for `wasm32-unknown-unknown` -
    /// cargo no-ops if nothing changed, so this is cheap across the three
    /// tests in this module.
    fn build_reference_plugin() -> (PathBuf, String) {
        let dir = fixture_dir();
        let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()))
            .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
            .current_dir(&dir)
            .status()
            .expect("failed to spawn cargo to build the reference plugin fixture");
        assert!(
            status.success(),
            "building the reference plugin fixture failed"
        );

        let wasm_path = dir.join("target/wasm32-unknown-unknown/release/reference_plugin.wasm");
        assert!(
            wasm_path.is_file(),
            "expected build artifact at {}",
            wasm_path.display()
        );
        let bytes = std::fs::read(&wasm_path).unwrap();
        let sha256 = {
            use std::fmt::Write;
            Sha256::digest(&bytes)
                .iter()
                .fold(String::new(), |mut acc, b| {
                    let _ = write!(acc, "{b:02x}");
                    acc
                })
        };
        (wasm_path, sha256)
    }

    async fn build_state(
        identity_mock: MockIdentityProvider,
        dpi_mock: MockDynamicPluginIdentityProvider,
    ) -> ServiceState {
        build_state_with_plugins(identity_mock, dpi_mock, &["p"], "").await
    }

    /// Like [`build_state`], but loads one `DynamicPluginConfig` per name in
    /// `plugin_names` (all pointing at the same compiled reference plugin
    /// binary) and appends `extra_ini` to every plugin's `[auth_plugin.*]`
    /// section - used by the rate-limit/concurrency tests to override the
    /// default (generous) bounds down to something a handful of calls can
    /// trip.
    async fn build_state_with_plugins(
        identity_mock: MockIdentityProvider,
        dpi_mock: MockDynamicPluginIdentityProvider,
        plugin_names: &[&str],
        extra_ini: &str,
    ) -> ServiceState {
        let (path, sha256) = build_reference_plugin();

        let mut cfg = Config {
            auth_plugins: DynamicPluginsSection {
                plugins: plugin_names.iter().map(|n| n.to_string()).collect(),
                ..Default::default()
            },
            ..Default::default()
        };

        for name in plugin_names {
            let plugin_config = {
                use config::{Config as RawConfig, File, FileFormat};
                use std::collections::HashMap as StdHashMap;

                #[derive(serde::Deserialize)]
                struct Wrapper {
                    auth_plugin: StdHashMap<String, openstack_keystone_config::DynamicPluginConfig>,
                }

                let ini = format!(
                    "[auth_plugin.{name}]\npath = {}\nsha256 = {}\nmode = full_auth\ncapabilities = provision_user\nprovision_domain_id = d\n{extra_ini}\n",
                    path.display(),
                    sha256,
                );
                let c = RawConfig::builder()
                    .add_source(File::from_str(&ini, FileFormat::Ini))
                    .build()
                    .unwrap();
                let wrapper: Wrapper = c.try_deserialize().unwrap();
                wrapper.auth_plugin.into_iter().next().unwrap().1
            };
            cfg.auth_plugin.insert(name.to_string(), plugin_config);
        }

        let (audit_dispatcher, receivers) = AuditDispatcher::new(
            "test-node",
            uuid::Uuid::new_v4().to_string(),
            Arc::from(b"test-hmac-key-32-bytes-long!!!!".as_slice()),
            0,
        );
        // Keep the channel open for the lifetime of the process - dropping
        // the receivers would close the channel and make every
        // `dispatch_critical` call (including the ones `provision_user`'s
        // own audit trail depends on, PR 1.1) fail with `AuditChannelDead`.
        std::mem::forget(receivers);

        let provider = Provider::mocked_builder()
            .mock_identity(identity_mock)
            .mock_auth_plugin_identity(dpi_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(cfg),
                sea_orm::DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                audit_dispatcher,
                None,
            )
            .await
            .unwrap(),
        );

        load_auth_plugins(&state, Arc::new(UnreachableHttpFetcher)).await;
        for name in plugin_names {
            assert!(
                state.auth_plugin_registry.read().await.contains(name),
                "reference plugin {name} should have loaded"
            );
        }
        state
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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_provision_on_first_login_then_idempotent_second_login() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_create_user()
            .times(1)
            .returning(|_, _| Ok(user_response("u1", "d")));
        identity_mock
            .expect_get_user()
            .returning(|_, _| Ok(Some(user_response("u1", "d"))));
        identity_mock
            .expect_get_user_domain_id()
            .returning(|_, _| Ok("d".to_string()));

        let resolved = Arc::new(Mutex::new(None::<String>));
        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        let resolved_for_find = resolved.clone();
        dpi_mock
            .expect_find()
            .returning(move |_, _, _| Ok(resolved_for_find.lock().unwrap().clone()));
        let resolved_for_create = resolved.clone();
        dpi_mock
            .expect_create_or_resolve()
            .times(1)
            .returning(move |_, _, _, user_id| {
                *resolved_for_create.lock().unwrap() = Some(user_id.to_string());
                Ok(user_id.to_string())
            });

        let state = build_state(identity_mock, dpi_mock).await;

        let request = |external_id: &str| WasmPluginAuthRequest {
            payload: serde_json::json!({"external_id": external_id}),
            raw_headers: HashMap::new(),
            peer_ip: None,
        };

        let first = authenticate_via_wasm_plugin(&state, "p", request("alice"))
            .await
            .expect("first login should provision a new user");
        let AuthenticationContext::WasmPlugin {
            claims,
            plugin_name,
            ..
        } = &first.context
        else {
            panic!("expected WasmPlugin context");
        };
        assert_eq!(plugin_name, "p");
        assert_eq!(
            claims.get("source"),
            Some(&serde_json::json!("reference-plugin"))
        );

        // Second login for the same external_id must resolve to not-found
        // in `find` still (the mock's shared `resolved` cell is never
        // populated by this test - `create_or_resolve` alone proves the
        // dispatch path round-trips the winning user_id back into the
        // issued `AuthenticationContext`, mirroring PR 1.1's own idempotency
        // coverage of `provision_user_inner` itself).
        let second = authenticate_via_wasm_plugin(&state, "p", request("alice"))
            .await
            .expect("second login should still succeed");
        assert_eq!(first.principal.identity, second.principal.identity);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bad_handle_is_rejected() {
        let identity_mock = MockIdentityProvider::default();
        let dpi_mock = MockDynamicPluginIdentityProvider::default();
        let state = build_state(identity_mock, dpi_mock).await;

        let err = authenticate_via_wasm_plugin(
            &state,
            "p",
            WasmPluginAuthRequest {
                payload: serde_json::json!({"external_id": "mallory", "bad_handle": true}),
                raw_headers: HashMap::new(),
                peer_ip: None,
            },
        )
        .await
        .expect_err("a self-fabricated resolved_identity must fail verification");
        assert!(matches!(err, WasmPluginAuthError::InvalidHandle));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_deny_response_is_rejected_without_leaking_reason() {
        let identity_mock = MockIdentityProvider::default();
        let dpi_mock = MockDynamicPluginIdentityProvider::default();
        let state = build_state(identity_mock, dpi_mock).await;

        let err = authenticate_via_wasm_plugin(
            &state,
            "p",
            WasmPluginAuthRequest {
                payload: serde_json::json!({"external_id": "denied-user", "deny": true}),
                raw_headers: HashMap::new(),
                peer_ip: None,
            },
        )
        .await
        .expect_err("a plugin Deny response must be rejected");
        assert!(matches!(err, WasmPluginAuthError::Denied(_)));
    }

    /// Permissive identity mocks that tolerate an arbitrary number of
    /// provisioning calls - the rate-limit tests below care only about
    /// `authenticate_via_wasm_plugin`'s `Ok`/`Err` outcome, not identity
    /// content or provisioning idempotency (already covered by
    /// `test_provision_on_first_login_then_idempotent_second_login`).
    fn permissive_mocks() -> (MockIdentityProvider, MockDynamicPluginIdentityProvider) {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_create_user()
            .returning(|_, _| Ok(user_response("u1", "d")));
        identity_mock
            .expect_get_user()
            .returning(|_, _| Ok(Some(user_response("u1", "d"))));
        identity_mock
            .expect_get_user_domain_id()
            .returning(|_, _| Ok("d".to_string()));

        let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
        dpi_mock.expect_find().returning(|_, _, _| Ok(None));
        dpi_mock
            .expect_create_or_resolve()
            .returning(|_, _, _, user_id| Ok(user_id.to_string()));

        (identity_mock, dpi_mock)
    }

    fn request(external_id: &str, peer_ip: Option<std::net::IpAddr>) -> WasmPluginAuthRequest {
        WasmPluginAuthRequest {
            payload: serde_json::json!({"external_id": external_id}),
            raw_headers: HashMap::new(),
            peer_ip,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_per_source_rate_limit_rejects() {
        let (identity_mock, dpi_mock) = permissive_mocks();
        let state = build_state_with_plugins(
            identity_mock,
            dpi_mock,
            &["p"],
            "invocation_rate_limit_per_source_per_minute = 1\n\
             invocation_rate_limit_per_minute = 1000\n\
             max_concurrent_invocations = 1000",
        )
        .await;

        let addr = Some("203.0.113.9".parse().unwrap());
        authenticate_via_wasm_plugin(&state, "p", request("alice", addr))
            .await
            .expect("first call within the per-source bucket should succeed");
        let err = authenticate_via_wasm_plugin(&state, "p", request("bob", addr))
            .await
            .expect_err("second call from the same source should exceed the per-source bucket");
        assert!(matches!(
            err,
            WasmPluginAuthError::RateLimited("per_source", _)
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_missing_public_peer_bypasses_per_source_limit() {
        let (identity_mock, dpi_mock) = permissive_mocks();
        let state = build_state_with_plugins(
            identity_mock,
            dpi_mock,
            &["p"],
            "invocation_rate_limit_per_source_per_minute = 1\n\
             invocation_rate_limit_per_minute = 1000\n\
             max_concurrent_invocations = 1000",
        )
        .await;

        authenticate_via_wasm_plugin(&state, "p", request("internal-a", None))
            .await
            .expect("first internal call should bypass the public-source bucket");
        authenticate_via_wasm_plugin(&state, "p", request("internal-b", None))
            .await
            .expect("second internal call should not share a mesh-peer bucket");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_per_plugin_rate_limit_rejects() {
        let (identity_mock, dpi_mock) = permissive_mocks();
        let state = build_state_with_plugins(
            identity_mock,
            dpi_mock,
            &["p"],
            "invocation_rate_limit_per_source_per_minute = 1000\n\
             invocation_rate_limit_per_minute = 1\n\
             max_concurrent_invocations = 1000",
        )
        .await;

        // Different source per call defeats bound 1, isolating bound 2.
        authenticate_via_wasm_plugin(
            &state,
            "p",
            request("alice", Some("203.0.113.1".parse().unwrap())),
        )
        .await
        .expect("first call within the per-plugin bucket should succeed");
        let err = authenticate_via_wasm_plugin(
            &state,
            "p",
            request("bob", Some("203.0.113.2".parse().unwrap())),
        )
        .await
        .expect_err("second call should exceed the shared per-plugin bucket");
        assert!(matches!(
            err,
            WasmPluginAuthError::RateLimited("per_plugin", _)
        ));
    }

    #[tokio::test]
    async fn test_concurrency_limit_rejects() {
        use openstack_keystone_config::DynamicPluginConfig;

        let ini = format!(
            "[auth_plugin.p]\npath = /dev/null\nsha256 = {}\nmode = full_auth\nmax_concurrent_invocations = 1\n",
            "0".repeat(64),
        );
        let config: DynamicPluginConfig = {
            use config::{Config as RawConfig, File, FileFormat};
            use std::collections::HashMap as StdHashMap;
            #[derive(serde::Deserialize)]
            struct Wrapper {
                auth_plugin: StdHashMap<String, DynamicPluginConfig>,
            }
            let c = RawConfig::builder()
                .add_source(File::from_str(&ini, FileFormat::Ini))
                .build()
                .unwrap();
            let wrapper: Wrapper = c.try_deserialize().unwrap();
            wrapper.auth_plugin.into_iter().next().unwrap().1
        };

        let limiter = crate::auth_plugin::PluginInvocationLimiter::new(&config);
        let permit = limiter
            .try_acquire_concurrency_permit()
            .expect("first acquire should succeed");
        let err = limiter
            .try_acquire_concurrency_permit()
            .expect_err("second acquire should be rejected while the slot is held");
        assert_eq!(err.0, crate::auth_plugin::RateLimitBound::Concurrency);
        drop(permit);
        let _permit = limiter
            .try_acquire_concurrency_permit()
            .expect("acquire should succeed again once the permit is released");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_two_plugins_independent_budgets() {
        let (identity_mock, dpi_mock) = permissive_mocks();
        let state = build_state_with_plugins(
            identity_mock,
            dpi_mock,
            &["p1", "p2"],
            "invocation_rate_limit_per_source_per_minute = 1000\n\
             invocation_rate_limit_per_minute = 1\n\
             max_concurrent_invocations = 1000",
        )
        .await;

        authenticate_via_wasm_plugin(&state, "p1", request("alice", None))
            .await
            .expect("p1's first call should succeed");
        let err = authenticate_via_wasm_plugin(&state, "p1", request("bob", None))
            .await
            .expect_err("p1's second call should exceed its own per-plugin bucket");
        assert!(matches!(
            err,
            WasmPluginAuthError::RateLimited("per_plugin", _)
        ));

        authenticate_via_wasm_plugin(&state, "p2", request("carol", None))
            .await
            .expect("p2's budget is independent of p1's exhausted budget");
    }
}

#[cfg(test)]
mod flatten_plugin_claims_tests {
    use super::*;

    #[test]
    fn test_flattens_scalars_and_nested_objects() {
        let mut claims = HashMap::new();
        claims.insert("risk".to_string(), serde_json::json!(3));
        claims.insert(
            "profile".to_string(),
            serde_json::json!({"email": "a@example.com"}),
        );
        let out = flatten_plugin_claims(&claims);
        assert_eq!(out.get("risk"), Some(&vec!["3".to_string()]));
        assert_eq!(
            out.get("profile.email"),
            Some(&vec!["a@example.com".to_string()])
        );
    }

    #[test]
    fn test_flattens_scalar_array_in_place() {
        let mut claims = HashMap::new();
        claims.insert("groups".to_string(), serde_json::json!(["a", "b"]));
        let out = flatten_plugin_claims(&claims);
        assert_eq!(
            out.get("groups"),
            Some(&vec!["a".to_string(), "b".to_string()])
        );
    }

    #[test]
    fn test_flattens_array_of_objects_with_indexed_keys() {
        let mut claims = HashMap::new();
        claims.insert(
            "roles".to_string(),
            serde_json::json!([{"name": "admin"}, {"name": "member"}]),
        );
        let out = flatten_plugin_claims(&claims);
        assert_eq!(out.get("roles.0.name"), Some(&vec!["admin".to_string()]));
        assert_eq!(out.get("roles.1.name"), Some(&vec!["member".to_string()]));
    }

    #[test]
    fn test_null_is_dropped() {
        let mut claims = HashMap::new();
        claims.insert("gone".to_string(), serde_json::Value::Null);
        let out = flatten_plugin_claims(&claims);
        assert!(!out.contains_key("gone"));
    }
}

/// End-to-end acceptance tests against the real, compiled reference plugin's
/// `mapping` export (ADR 0025 §4 "mapping Mode") - `authenticate_by_mapping`
/// itself is mocked (its own correctness is ADR 0020's concern, already
/// covered by the Mapping Engine's own test suite); what these tests prove
/// is that [`authenticate_via_wasm_mapping_plugin`] gets the wasm boundary
/// right end to end: real registry lookup, real `extism` invocation of the
/// `mapping` entry point, response-bounds decoding, `__keystone_workload_id`
/// extraction, and building the exact `MappingAuthRequest` the engine
/// expects (`IdentitySource::WasmPlugin`, flattened claims, `domain_id:
/// None`).
#[cfg(test)]
mod mapping_acceptance_tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;

    use openstack_keystone_audit::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager, DynamicPluginsSection};
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthenticationResultBuilder, IdentityInfo, PrincipalInfo,
        UserIdentityInfoBuilder,
    };
    use sha2::{Digest, Sha256};

    use crate::auth_plugin_http::{DynamicPluginHttpFetcher, FetchResponse};
    use crate::auth_plugin_identity::MockDynamicPluginIdentityProvider;
    use crate::auth_plugin_startup::load_auth_plugins;
    use crate::identity::MockIdentityProvider;
    use crate::keystone::Service;
    use crate::mocks::MockMappingProvider;
    use crate::policy::MockPolicy;
    use crate::provider::Provider;

    use super::*;

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
        ) -> Result<FetchResponse, String> {
            panic!("this test's plugin doesn't grant http_fetch")
        }
    }

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../auth-plugin-runtime/tests/fixtures/reference-plugin")
    }

    fn build_reference_plugin() -> (PathBuf, String) {
        let dir = fixture_dir();
        let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()))
            .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
            .current_dir(&dir)
            .status()
            .expect("failed to spawn cargo to build the reference plugin fixture");
        assert!(
            status.success(),
            "building the reference plugin fixture failed"
        );

        let wasm_path = dir.join("target/wasm32-unknown-unknown/release/reference_plugin.wasm");
        assert!(
            wasm_path.is_file(),
            "expected build artifact at {}",
            wasm_path.display()
        );
        let bytes = std::fs::read(&wasm_path).unwrap();
        let sha256 = {
            use std::fmt::Write;
            Sha256::digest(&bytes)
                .iter()
                .fold(String::new(), |mut acc, b| {
                    let _ = write!(acc, "{b:02x}");
                    acc
                })
        };
        (wasm_path, sha256)
    }

    /// Loads the reference plugin fixture as `mode = mapping` under the
    /// given `plugin_name`, wired to `mapping_mock`'s `MappingApi`
    /// expectations - `mapping`-mode plugins grant none of
    /// `provision_user`/`find_user`/`assign_role` (config-load-time
    /// forbidden per PR 0.1), so the identity/auth-plugin-identity mocks
    /// carry no expectations here, unlike the `full_auth` acceptance tests.
    async fn build_mapping_state(
        plugin_name: &str,
        mapping_mock: MockMappingProvider,
    ) -> ServiceState {
        let (path, sha256) = build_reference_plugin();

        let cfg = Config {
            auth_plugins: DynamicPluginsSection {
                plugins: vec![plugin_name.to_string()],
                ..Default::default()
            },
            auth_plugin: {
                use config::{Config as RawConfig, File, FileFormat};
                use std::collections::HashMap as StdHashMap;

                #[derive(serde::Deserialize)]
                struct Wrapper {
                    auth_plugin: StdHashMap<String, openstack_keystone_config::DynamicPluginConfig>,
                }

                let ini = format!(
                    "[auth_plugin.{plugin_name}]\npath = {}\nsha256 = {}\nmode = mapping\n",
                    path.display(),
                    sha256,
                );
                let c = RawConfig::builder()
                    .add_source(File::from_str(&ini, FileFormat::Ini))
                    .build()
                    .unwrap();
                let wrapper: Wrapper = c.try_deserialize().unwrap();
                wrapper.auth_plugin.into_iter().collect()
            },
            ..Default::default()
        };

        let (audit_dispatcher, receivers) = AuditDispatcher::new(
            "test-node",
            uuid::Uuid::new_v4().to_string(),
            Arc::from(b"test-hmac-key-32-bytes-long!!!!".as_slice()),
            0,
        );
        std::mem::forget(receivers);

        let provider = Provider::mocked_builder()
            .mock_identity(MockIdentityProvider::default())
            .mock_auth_plugin_identity(MockDynamicPluginIdentityProvider::default())
            .mock_mapping(mapping_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(cfg),
                sea_orm::DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                audit_dispatcher,
                None,
            )
            .await
            .unwrap(),
        );

        load_auth_plugins(&state, Arc::new(UnreachableHttpFetcher)).await;
        assert!(
            state
                .auth_plugin_registry
                .read()
                .await
                .contains(plugin_name),
            "reference plugin {plugin_name} should have loaded"
        );
        state
    }

    fn fixed_auth_result() -> AuthenticationResult {
        AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Mapping(
                openstack_keystone_core_types::mapping::auth::MappingContext {
                    mapping_id: "m1".to_string(),
                    matched_rule_name: "r1".to_string(),
                    virtual_user_id: "vu1".to_string(),
                    is_system: false,
                },
            ))
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("vu1")
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap()
    }

    fn mapping_request(external_id: &str, deny: bool) -> WasmPluginAuthRequest {
        WasmPluginAuthRequest {
            payload: serde_json::json!({"external_id": external_id, "deny": deny}),
            raw_headers: HashMap::new(),
            peer_ip: None,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_mapping_dispatch_resolves_via_mapping_engine() {
        let mut mapping_mock = MockMappingProvider::default();
        mapping_mock
            .expect_authenticate_by_mapping()
            .withf(|_, req| {
                matches!(
                    &req.source,
                    IdentitySource::WasmPlugin { plugin_name } if plugin_name == "p"
                ) && req.domain_id.is_none()
                    && req.unique_workload_id == "alice"
                    && req.claims.get("external_id") == Some(&vec!["alice".to_string()])
                    // The reserved workload-id claim stays in the claims map
                    // too (per the confirmed convention), just flattened.
                    && req.claims.get("__keystone_workload_id")
                        == Some(&vec!["alice".to_string()])
            })
            .times(1)
            .returning(|_, _| Ok(fixed_auth_result()));

        let state = build_mapping_state("p", mapping_mock).await;

        let result =
            authenticate_via_wasm_mapping_plugin(&state, "p", mapping_request("alice", false))
                .await
                .expect("mapping dispatch should succeed");
        assert!(matches!(result.context, AuthenticationContext::Mapping(_)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_mapping_deny_is_rejected_without_calling_engine() {
        let mut mapping_mock = MockMappingProvider::default();
        mapping_mock.expect_authenticate_by_mapping().times(0);

        let state = build_mapping_state("p", mapping_mock).await;

        let err =
            authenticate_via_wasm_mapping_plugin(&state, "p", mapping_request("mallory", true))
                .await
                .expect_err("a plugin Deny response must be rejected");
        assert!(matches!(err, WasmPluginAuthError::Denied(_)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_full_auth_dispatch_rejects_mapping_mode_plugin() {
        let mapping_mock = MockMappingProvider::default();
        let state = build_mapping_state("p", mapping_mock).await;

        let err = authenticate_via_wasm_plugin(&state, "p", mapping_request("alice", false))
            .await
            .expect_err("a mode=mapping plugin must be rejected by the full_auth dispatcher");
        assert!(matches!(err, WasmPluginAuthError::WrongMode));
    }
}

/// End-to-end acceptance tests against the real, compiled reference plugin's
/// `route` export (ADR 0025 §4 "Guest Contract - `route` Mode"). Proves
/// [`route_via_wasm_plugin`] gets the wasm boundary right end to end: real
/// registry lookup, real `extism` invocation of the `route` entry point,
/// response-bounds decoding, and the host-side `route_targets` allowlist
/// check that the guest contract's own decoder can't perform (it has no
/// visibility into config state).
#[cfg(test)]
mod route_acceptance_tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;

    use openstack_keystone_audit::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager, DynamicPluginsSection};
    use sha2::{Digest, Sha256};

    use crate::auth_plugin_http::{DynamicPluginHttpFetcher, FetchResponse};
    use crate::auth_plugin_identity::MockDynamicPluginIdentityProvider;
    use crate::auth_plugin_startup::load_auth_plugins;
    use crate::identity::MockIdentityProvider;
    use crate::keystone::Service;
    use crate::policy::MockPolicy;
    use crate::provider::Provider;

    use super::*;

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
        ) -> Result<FetchResponse, String> {
            panic!("this test's plugin doesn't grant http_fetch")
        }
    }

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../auth-plugin-runtime/tests/fixtures/reference-plugin")
    }

    fn build_reference_plugin() -> (PathBuf, String) {
        let dir = fixture_dir();
        let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()))
            .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
            .current_dir(&dir)
            .status()
            .expect("failed to spawn cargo to build the reference plugin fixture");
        assert!(
            status.success(),
            "building the reference plugin fixture failed"
        );

        let wasm_path = dir.join("target/wasm32-unknown-unknown/release/reference_plugin.wasm");
        assert!(
            wasm_path.is_file(),
            "expected build artifact at {}",
            wasm_path.display()
        );
        let bytes = std::fs::read(&wasm_path).unwrap();
        let sha256 = {
            use std::fmt::Write;
            Sha256::digest(&bytes)
                .iter()
                .fold(String::new(), |mut acc, b| {
                    let _ = write!(acc, "{b:02x}");
                    acc
                })
        };
        (wasm_path, sha256)
    }

    /// Loads the reference plugin fixture as `mode = route`, `inspect_methods
    /// = application_credential`, with `route_targets` set to
    /// `allowed_target` - a single caller-chosen allowlist entry, letting
    /// each test independently prove both the allowlisted and
    /// non-allowlisted paths.
    async fn build_route_state(plugin_name: &str, allowed_target: &str) -> ServiceState {
        let (path, sha256) = build_reference_plugin();

        let cfg = Config {
            auth_plugins: DynamicPluginsSection {
                plugins: vec![plugin_name.to_string()],
                ..Default::default()
            },
            auth_plugin: {
                use config::{Config as RawConfig, File, FileFormat};
                use std::collections::HashMap as StdHashMap;

                #[derive(serde::Deserialize)]
                struct Wrapper {
                    auth_plugin: StdHashMap<String, openstack_keystone_config::DynamicPluginConfig>,
                }

                let ini = format!(
                    "[auth_plugin.{plugin_name}]\npath = {}\nsha256 = {}\nmode = route\ninspect_methods = application_credential\nroute_targets = {allowed_target}\n",
                    path.display(),
                    sha256,
                );
                let c = RawConfig::builder()
                    .add_source(File::from_str(&ini, FileFormat::Ini))
                    .build()
                    .unwrap();
                let wrapper: Wrapper = c.try_deserialize().unwrap();
                wrapper.auth_plugin.into_iter().collect()
            },
            ..Default::default()
        };

        let (audit_dispatcher, receivers) = AuditDispatcher::new(
            "test-node",
            uuid::Uuid::new_v4().to_string(),
            Arc::from(b"test-hmac-key-32-bytes-long!!!!".as_slice()),
            0,
        );
        std::mem::forget(receivers);

        let provider = Provider::mocked_builder()
            .mock_identity(MockIdentityProvider::default())
            .mock_auth_plugin_identity(MockDynamicPluginIdentityProvider::default())
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(cfg),
                sea_orm::DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                audit_dispatcher,
                None,
            )
            .await
            .unwrap(),
        );

        load_auth_plugins(&state, Arc::new(UnreachableHttpFetcher)).await;
        assert!(
            state
                .auth_plugin_registry
                .read()
                .await
                .contains(plugin_name),
            "reference plugin {plugin_name} should have loaded"
        );
        state
    }

    /// Loads the reference plugin fixture as `mode = full_auth` - used only
    /// by [`test_route_dispatch_rejects_non_route_mode_plugin`] to prove the
    /// route dispatcher's own mode gate, mirroring `acceptance_tests::
    /// build_state` (duplicated rather than shared, since that helper is
    /// private to its own module).
    async fn build_full_auth_state(plugin_name: &str) -> ServiceState {
        let (path, sha256) = build_reference_plugin();

        let cfg = Config {
            auth_plugins: DynamicPluginsSection {
                plugins: vec![plugin_name.to_string()],
                ..Default::default()
            },
            auth_plugin: {
                use config::{Config as RawConfig, File, FileFormat};
                use std::collections::HashMap as StdHashMap;

                #[derive(serde::Deserialize)]
                struct Wrapper {
                    auth_plugin: StdHashMap<String, openstack_keystone_config::DynamicPluginConfig>,
                }

                let ini = format!(
                    "[auth_plugin.{plugin_name}]\npath = {}\nsha256 = {}\nmode = full_auth\ncapabilities = provision_user\nprovision_domain_id = d\n",
                    path.display(),
                    sha256,
                );
                let c = RawConfig::builder()
                    .add_source(File::from_str(&ini, FileFormat::Ini))
                    .build()
                    .unwrap();
                let wrapper: Wrapper = c.try_deserialize().unwrap();
                wrapper.auth_plugin.into_iter().collect()
            },
            ..Default::default()
        };

        let (audit_dispatcher, receivers) = AuditDispatcher::new(
            "test-node",
            uuid::Uuid::new_v4().to_string(),
            Arc::from(b"test-hmac-key-32-bytes-long!!!!".as_slice()),
            0,
        );
        std::mem::forget(receivers);

        let provider = Provider::mocked_builder()
            .mock_identity(MockIdentityProvider::default())
            .mock_auth_plugin_identity(MockDynamicPluginIdentityProvider::default())
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(cfg),
                sea_orm::DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                audit_dispatcher,
                None,
            )
            .await
            .unwrap(),
        );

        load_auth_plugins(&state, Arc::new(UnreachableHttpFetcher)).await;
        assert!(
            state
                .auth_plugin_registry
                .read()
                .await
                .contains(plugin_name),
            "reference plugin {plugin_name} should have loaded"
        );
        state
    }

    fn appcred_payloads(cred_id: &str) -> HashMap<String, serde_json::Value> {
        let mut payloads = HashMap::new();
        payloads.insert(
            "application_credential".to_string(),
            serde_json::json!({"application_credential_id": cred_id}),
        );
        payloads
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_passthrough_when_no_matching_credential_shape() {
        let state = build_route_state("p", "hacked_appcred_handler").await;
        let decision = route_via_wasm_plugin(
            &state,
            "p",
            &["application_credential".to_string()],
            appcred_payloads("some-other-shape"),
            HashMap::new(),
            None,
        )
        .await
        .expect("passthrough should not error");
        assert_eq!(decision.target_method, None);
        assert_eq!(decision.payload, None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_route_to_allowlisted_target_succeeds() {
        let state = build_route_state("p", "hacked_appcred_handler").await;
        let decision = route_via_wasm_plugin(
            &state,
            "p",
            &["application_credential".to_string()],
            appcred_payloads("tf-abc123"),
            HashMap::new(),
            None,
        )
        .await
        .expect("route to an allowlisted target should succeed");
        assert_eq!(
            decision.target_method.as_deref(),
            Some("hacked_appcred_handler")
        );
        assert_eq!(
            decision.payload,
            Some(serde_json::json!({"external_id": "abc123"}))
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_route_to_non_allowlisted_target_is_rejected() {
        // route_targets allowlists a *different* method than the plugin
        // actually reroutes to (`hacked_appcred_handler`), so the host's own
        // allowlist check must reject it - the plugin cannot direct traffic
        // to a target the operator never authorized, even though the wire
        // response itself is well-formed.
        let state = build_route_state("p", "some_other_target").await;
        let err = route_via_wasm_plugin(
            &state,
            "p",
            &["application_credential".to_string()],
            appcred_payloads("tf-abc123"),
            HashMap::new(),
            None,
        )
        .await
        .expect_err("an off-allowlist target must be rejected, not redirected");
        assert!(matches!(err, WasmPluginAuthError::MalformedResponse(_)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_deny_fails_closed() {
        let state = build_route_state("p", "hacked_appcred_handler").await;
        let err = route_via_wasm_plugin(
            &state,
            "p",
            &["application_credential".to_string()],
            appcred_payloads("deny-me"),
            HashMap::new(),
            None,
        )
        .await
        .expect_err("a plugin Deny response must be rejected");
        assert!(matches!(err, WasmPluginAuthError::Denied(_)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_full_auth_dispatch_rejects_route_mode_plugin() {
        let state = build_route_state("p", "hacked_appcred_handler").await;
        let err = authenticate_via_wasm_plugin(
            &state,
            "p",
            WasmPluginAuthRequest {
                payload: serde_json::json!({"external_id": "alice"}),
                raw_headers: HashMap::new(),
                peer_ip: None,
            },
        )
        .await
        .expect_err("a mode=route plugin must be rejected by the full_auth dispatcher");
        assert!(matches!(err, WasmPluginAuthError::WrongMode));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_route_dispatch_rejects_non_route_mode_plugin() {
        let state = build_full_auth_state("p").await;

        let err = route_via_wasm_plugin(
            &state,
            "p",
            &["password".to_string()],
            HashMap::new(),
            HashMap::new(),
            None,
        )
        .await
        .expect_err("a mode=full_auth plugin must be rejected by the route dispatcher");
        assert!(matches!(err, WasmPluginAuthError::WrongMode));
    }
}
