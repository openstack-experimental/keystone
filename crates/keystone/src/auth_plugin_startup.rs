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
//! Post-construction dynamic auth plugin loading (ADR 0025), mirroring
//! `subscribe_event_hooks`'s wiring pattern in
//! `crates/keystone/src/bin/keystone.rs`: [`CoreHostFunctions`] needs an
//! already-built `ServiceState`, so plugins can only be loaded *after*
//! `Service::new` returns and the result is `Arc`-wrapped - not from inside
//! `Service::new` itself.
//!
//! Lives here (not in `openstack-keystone-core`) so `core` never depends on
//! the extism-backed `openstack-keystone-auth-plugin-runtime` crate in
//! production code - only this top-level service crate, which actually
//! constructs the real `WasmPluginRegistry`, does.
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use openstack_keystone_auth_plugin_runtime::WasmPluginRegistry;
use openstack_keystone_core::auth_plugin::{
    CoreHostFunctions, PluginInvocationLimiter, as_host_functions,
};
use openstack_keystone_core::auth_plugin_http::DynamicPluginHttpFetcher;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_telemetry::metrics::{self, CounterVec, Label, Meter};

/// Load every configured dynamic auth plugin against `state`, populating
/// `state.auth_plugin_registry`/`state.core_host_functions`. Never fails
/// the caller - a per-plugin load failure (missing file, checksum
/// mismatch, compile error) disables only that plugin; every other plugin
/// and every builtin auth method still start normally (ADR 0025 §5).
pub async fn load_auth_plugins(
    state: &ServiceState,
    http_fetcher: Arc<dyn DynamicPluginHttpFetcher>,
) {
    let (section, configs) = {
        let cfg = state.config_manager.config.read().await;
        (cfg.auth_plugins.clone(), cfg.auth_plugin.clone())
    };

    let core_host_functions = Arc::new(CoreHostFunctions::new(state.clone(), http_fetcher));
    let host_functions = as_host_functions(core_host_functions.clone());

    let (registry, errors) = WasmPluginRegistry::load(&section, &configs, Some(&host_functions));
    if !errors.is_empty() {
        for (name, err) in &errors {
            tracing::error!(
                target: "keystone_auth_plugin_load_failure",
                plugin_name = %name,
                error = %err,
                "dynamic auth plugin failed to load at startup; this plugin is disabled, \
                 all other auth methods start normally"
            );
            // A counter, so a future reload path accumulates rather than
            // silently resetting the metric an operator may be alerting on.
            LOAD_FAILURE_METRICS.record(name);
        }
    }

    let limiters: HashMap<String, Arc<PluginInvocationLimiter>> = configs
        .iter()
        .filter(|(name, _)| registry.contains(name))
        .map(|(name, cfg)| (name.clone(), Arc::new(PluginInvocationLimiter::new(cfg))))
        .collect();

    *state.auth_plugin_registry.write().await = Arc::new(registry);
    *state.core_host_functions.write().await = Some(core_host_functions);
    *state.auth_plugin_limiters.write().await = limiters;
}

/// `keystone_auth_plugin_load_failure{plugin_name}` (ADR 0025 §5): the
/// cumulative count of dynamic auth plugin load failures. `plugin_name` is the
/// operator-chosen `[auth_plugin.<name>]` section name, a bounded label.
pub struct LoadFailureMetrics {
    failures: CounterVec<1>,
}

impl LoadFailureMetrics {
    /// Create the counter on `meter`.
    pub fn new(meter: &Meter) -> Self {
        Self {
            failures: CounterVec::new(
                meter,
                "keystone_auth_plugin_load_failure",
                "Cumulative count of dynamic auth plugin load failures (missing file, checksum \
                 mismatch, compile error), labeled by plugin_name - ADR 0025 section 5. A load \
                 failure disables only that plugin; every other auth method still starts normally.",
                ["plugin_name"],
            ),
        }
    }

    /// Count one failure to load `plugin_name`.
    pub fn record(&self, plugin_name: &str) {
        self.failures.inc([Label::bounded(plugin_name)]);
    }
}

/// Process-wide load-failure counter.
pub static LOAD_FAILURE_METRICS: LazyLock<LoadFailureMetrics> =
    LazyLock::new(|| LoadFailureMetrics::new(&metrics::meter()));

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use cadf::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager};
    use openstack_keystone_core::auth_plugin_http::FetchResponse;
    use openstack_keystone_telemetry::metrics::MetricsPipeline;
    use std::net::SocketAddr;

    use crate::keystone::Service;
    use crate::policy::MockPolicy;
    use crate::provider::Provider;

    /// Pins the rendered exposition text against
    /// `tests/golden/auth_plugin_load_failure.prom` (ADR 0040).
    #[test]
    fn golden_load_failure_exposition() {
        let pipeline = MetricsPipeline::new();
        let metrics = LoadFailureMetrics::new(&pipeline.meter());
        metrics.record("geoip");
        metrics.record("geoip");
        metrics.record("a\"b\\c");
        openstack_keystone_telemetry::assert_golden!("auth_plugin_load_failure", pipeline.render());
    }

    struct UnreachableHttpFetcher;

    #[async_trait]
    impl DynamicPluginHttpFetcher for UnreachableHttpFetcher {
        async fn fetch(
            &self,
            _method: &str,
            _url: &str,
            _resolved_addr: SocketAddr,
            _headers: &HashMap<String, String>,
            _body: Option<&str>,
            _timeout_ms: u64,
            _auth_header: Option<(&str, &str)>,
            _max_body_bytes: usize,
        ) -> Result<FetchResponse, String> {
            panic!("not exercised by this test")
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_load_auth_plugins_with_no_configured_plugins_leaves_registry_empty() {
        let cfg = Config::default();
        let (audit_dispatcher, _receivers) = AuditDispatcher::new(
            "test-node",
            uuid::Uuid::new_v4().to_string(),
            Arc::from(b"test-hmac-key-32-bytes-long!!!!".as_slice()),
            0,
        );
        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(cfg),
                sea_orm::DatabaseConnection::default(),
                Provider::mocked_builder().build().unwrap(),
                Arc::new(MockPolicy::default()),
                audit_dispatcher,
                None,
            )
            .await
            .unwrap(),
        );

        load_auth_plugins(&state, Arc::new(UnreachableHttpFetcher)).await;

        assert!(state.auth_plugin_registry.read().await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_load_auth_plugins_records_load_failure_metric() {
        use openstack_keystone_config::DynamicPluginConfig;
        use std::path::PathBuf;

        let mut cfg = Config::default();
        cfg.auth_plugins.plugins = vec!["bad".to_string()];
        cfg.auth_plugin.insert(
            "bad".to_string(),
            DynamicPluginConfig {
                path: PathBuf::from("/nonexistent/plugin.wasm"),
                sha256: "0".repeat(64),
                mode: openstack_keystone_config::PluginMode::FullAuth,
                capabilities: vec!["provision_user".to_string()],
                exposed_headers: Vec::new(),
                allowed_hosts: Vec::new(),
                http_fetch_follow_redirects: false,
                http_fetch_auth_header: None,
                http_fetch_auth_secret_env: None,
                provision_domain_id: Some("d".to_string()),
                allowed_provision_domains: Vec::new(),
                assign_role_allowed: Vec::new(),
                inspect_methods: Vec::new(),
                route_targets: Vec::new(),
                timeout_ms: 1_000,
                fuel_limit: 10_000_000,
                memory_limit_mb: 16,
                invocation_rate_limit_per_source_per_minute: 20,
                invocation_rate_limit_per_minute: 300,
                max_concurrent_invocations: 16,
                valid_since: None,
            },
        );

        let (audit_dispatcher, _receivers) = AuditDispatcher::new(
            "test-node",
            uuid::Uuid::new_v4().to_string(),
            Arc::from(b"test-hmac-key-32-bytes-long!!!!".as_slice()),
            0,
        );
        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(cfg),
                sea_orm::DatabaseConnection::default(),
                Provider::mocked_builder().build().unwrap(),
                Arc::new(MockPolicy::default()),
                audit_dispatcher,
                None,
            )
            .await
            .unwrap(),
        );

        load_auth_plugins(&state, Arc::new(UnreachableHttpFetcher)).await;

        assert!(state.auth_plugin_registry.read().await.is_empty());

        let text = openstack_keystone_telemetry::metrics::render_prometheus();
        assert!(
            text.contains("keystone_auth_plugin_load_failure{plugin_name=\"bad\"} 1"),
            "{text}"
        );
    }

    #[test]
    fn load_failure_label_value_is_escaped() {
        let pipeline = MetricsPipeline::new();
        LoadFailureMetrics::new(&pipeline.meter()).record("weird\"name\\");
        assert!(
            pipeline
                .render()
                .contains("plugin_name=\"weird\\\"name\\\\\"")
        );
    }
}
