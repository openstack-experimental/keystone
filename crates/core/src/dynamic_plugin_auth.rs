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

use openstack_keystone_config::{HARD_DENYLISTED_HEADERS, PluginMode};
use openstack_keystone_core_types::auth::{
    AuthenticationContext, AuthenticationResult, AuthenticationResultBuilder, IdentityInfo,
    PrincipalInfo, UserIdentityInfoBuilder,
};
use openstack_keystone_dynamic_plugin_runtime::{AuthPluginRequest, AuthPluginResponse};

use crate::auth::ExecutionContext;
use crate::dynamic_plugin::emit_wasm_plugin_audit;
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
    /// `X-Forwarded-For` header value, if present - resolved into a
    /// trusted client address using `[dynamic_plugins].trusted_proxies`.
    pub xff_header: Option<String>,
    /// Raw TCP peer address.
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
    RateLimited(&'static str),
    #[error("denied by plugin")]
    Denied(String),
    #[error("fetching the resolved user failed: {0}")]
    Identity(String),
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
    let registry = state.dynamic_plugin_registry.read().await.clone();
    let Some(loaded) = registry.get(plugin_name) else {
        return Err(WasmPluginAuthError::NotFound);
    };

    let config = {
        let cfg = state.config_manager.config.read().await;
        cfg.dynamic_plugin.get(plugin_name).cloned()
    };
    let Some(config) = config else {
        return Err(WasmPluginAuthError::NotFound);
    };
    if config.mode != PluginMode::FullAuth {
        return Err(WasmPluginAuthError::WrongMode);
    }

    let Some(limiter) = state
        .dynamic_plugin_limiters
        .read()
        .await
        .get(plugin_name)
        .cloned()
    else {
        // Registry and limiter map are always populated together by
        // `load_dynamic_plugins` - reaching here means the plugin isn't
        // actually loaded, same as an ordinary registry-lookup miss.
        return Err(WasmPluginAuthError::NotFound);
    };

    let trusted_proxies = {
        let cfg = state.config_manager.config.read().await;
        cfg.dynamic_plugins.trusted_proxies.clone()
    };
    let remote_addr = resolve_client_ip(
        request.xff_header.as_deref(),
        request.peer_ip,
        &trusted_proxies,
    )
    .map(|ip| ip.to_string());

    // Rate/concurrency bounds (ADR §7), checked in order, cheapest and
    // most-specific first, before the plugin is ever invoked - a single
    // hammering source is rejected without ever touching the shared
    // per-plugin budget or a concurrency slot.
    if let Err(bound) = limiter.check_per_source(remote_addr.as_deref()) {
        let _ = emit_wasm_plugin_audit(
            state,
            plugin_name,
            "authenticate",
            "rate_limited",
            Some(bound.as_str().to_string()),
        )
        .await;
        return Err(WasmPluginAuthError::RateLimited(bound.as_str()));
    }
    if let Err(bound) = limiter.check_per_plugin() {
        let _ = emit_wasm_plugin_audit(
            state,
            plugin_name,
            "authenticate",
            "rate_limited",
            Some(bound.as_str().to_string()),
        )
        .await;
        return Err(WasmPluginAuthError::RateLimited(bound.as_str()));
    }
    let _permit = match limiter.try_acquire_concurrency_permit() {
        Ok(permit) => permit,
        Err(bound) => {
            let _ = emit_wasm_plugin_audit(
                state,
                plugin_name,
                "authenticate",
                "rate_limited",
                Some(bound.as_str().to_string()),
            )
            .await;
            return Err(WasmPluginAuthError::RateLimited(bound.as_str()));
        }
    };

    // Allowlist down to `exposed_headers`, then defensively re-check none
    // of `HARD_DENYLISTED_HEADERS` survived - config-load already rejects
    // a plugin config listing one (`crates/config/src/dynamic_plugins.rs`),
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

    let raw_response = match loaded.invoke("authenticate", &input) {
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

    let response = match openstack_keystone_dynamic_plugin_runtime::decode_and_validate_response(
        &raw_response,
    ) {
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
            plugin_sha256: loaded.sha256,
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

/// End-to-end acceptance tests against the real, compiled reference plugin
/// (`crates/dynamic-plugin-runtime/tests/fixtures/reference-plugin`) - not
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

    use crate::dynamic_plugin_http::{DynamicPluginHttpFetcher, FetchResponse};
    use crate::dynamic_plugin_identity::MockDynamicPluginIdentityProvider;
    use crate::dynamic_plugin_startup::load_dynamic_plugins;
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
            .join("../dynamic-plugin-runtime/tests/fixtures/reference-plugin")
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
    /// binary) and appends `extra_ini` to every plugin's `[dynamic_plugin.*]`
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
            dynamic_plugins: DynamicPluginsSection {
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
                    dynamic_plugin:
                        StdHashMap<String, openstack_keystone_config::DynamicPluginConfig>,
                }

                let ini = format!(
                    "[dynamic_plugin.{name}]\npath = {}\nsha256 = {}\nmode = full_auth\ncapabilities = provision_user\nprovision_domain_id = d\n{extra_ini}\n",
                    path.display(),
                    sha256,
                );
                let c = RawConfig::builder()
                    .add_source(File::from_str(&ini, FileFormat::Ini))
                    .build()
                    .unwrap();
                let wrapper: Wrapper = c.try_deserialize().unwrap();
                wrapper.dynamic_plugin.into_iter().next().unwrap().1
            };
            cfg.dynamic_plugin.insert(name.to_string(), plugin_config);
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
            .mock_dynamic_plugin_identity(dpi_mock)
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

        load_dynamic_plugins(&state, Arc::new(UnreachableHttpFetcher)).await;
        for name in plugin_names {
            assert!(
                state.dynamic_plugin_registry.read().await.contains(name),
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
            xff_header: None,
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
                xff_header: None,
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
                xff_header: None,
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
            xff_header: None,
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
            WasmPluginAuthError::RateLimited("per_source")
        ));
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
            WasmPluginAuthError::RateLimited("per_plugin")
        ));
    }

    #[tokio::test]
    async fn test_concurrency_limit_rejects() {
        use openstack_keystone_config::DynamicPluginConfig;

        let ini = format!(
            "[dynamic_plugin.p]\npath = /dev/null\nsha256 = {}\nmode = full_auth\nmax_concurrent_invocations = 1\n",
            "0".repeat(64),
        );
        let config: DynamicPluginConfig = {
            use config::{Config as RawConfig, File, FileFormat};
            use std::collections::HashMap as StdHashMap;
            #[derive(serde::Deserialize)]
            struct Wrapper {
                dynamic_plugin: StdHashMap<String, DynamicPluginConfig>,
            }
            let c = RawConfig::builder()
                .add_source(File::from_str(&ini, FileFormat::Ini))
                .build()
                .unwrap();
            let wrapper: Wrapper = c.try_deserialize().unwrap();
            wrapper.dynamic_plugin.into_iter().next().unwrap().1
        };

        let limiter = crate::dynamic_plugin::PluginInvocationLimiter::new(&config);
        let permit = limiter
            .try_acquire_concurrency_permit()
            .expect("first acquire should succeed");
        let err = limiter
            .try_acquire_concurrency_permit()
            .expect_err("second acquire should be rejected while the slot is held");
        assert_eq!(err, crate::dynamic_plugin::RateLimitBound::Concurrency);
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
            WasmPluginAuthError::RateLimited("per_plugin")
        ));

        authenticate_via_wasm_plugin(&state, "p2", request("carol", None))
            .await
            .expect("p2's budget is independent of p1's exhausted budget");
    }
}
