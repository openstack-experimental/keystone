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
//! already-built [`ServiceState`], so plugins can only be loaded *after*
//! `Service::new` returns and the result is `Arc`-wrapped - not from inside
//! `Service::new` itself.
use std::collections::HashMap;
use std::sync::Arc;

use openstack_keystone_auth_plugin_runtime::WasmPluginRegistry;

use crate::auth_plugin::{CoreHostFunctions, PluginInvocationLimiter, as_host_functions};
use crate::auth_plugin_http::DynamicPluginHttpFetcher;
use crate::keystone::ServiceState;

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
        let mut failures = state.auth_plugin_load_failures.write().await;
        for (name, err) in &errors {
            tracing::error!(
                target: "keystone_auth_plugin_load_failure",
                plugin_name = %name,
                error = %err,
                "dynamic auth plugin failed to load at startup; this plugin is disabled, \
                 all other auth methods start normally"
            );
            // Additive, not overwritten: `load_auth_plugins` only runs once
            // at startup today (ADR §5 - no hot reload), but the counter is
            // written this way so a future reload path accumulates rather
            // than silently resetting the metric an operator may be
            // alerting on.
            *failures.entry(name.clone()).or_insert(0) += 1;
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

/// Serialise `keystone_auth_plugin_load_failure{plugin_name}` (ADR 0025 §5)
/// as Prometheus text exposition format (v0.0.4), one sample per plugin that
/// has ever failed to load. Empty (no samples, just the `# HELP`/`# TYPE`
/// header) when every configured plugin has always loaded successfully -
/// matches `openstack_keystone_audit::metrics::format_prometheus_text`'s
/// style so both can be concatenated into one `/metrics` response body.
pub fn format_load_failure_metrics(failures: &HashMap<String, u64>) -> String {
    let mut out = String::from(
        "# HELP keystone_auth_plugin_load_failure \
Cumulative count of dynamic auth plugin load failures (missing file, checksum \
mismatch, compile error), labeled by plugin_name - ADR 0025 section 5. A \
load failure disables only that plugin; every other auth method still \
starts normally.\n\
# TYPE keystone_auth_plugin_load_failure counter\n",
    );
    let mut names: Vec<&String> = failures.keys().collect();
    names.sort();
    for name in names {
        let count = failures[name];
        // Prometheus label-value escaping: a plugin name is an operator-
        // chosen config-section identifier, not attacker-influenced, but
        // escaping is cheap and correct regardless.
        let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
        out.push_str(&format!(
            "keystone_auth_plugin_load_failure{{plugin_name=\"{escaped}\"}} {count}\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_plugin_http::FetchResponse;
    use crate::keystone::Service;
    use crate::provider::Provider;
    use async_trait::async_trait;
    use openstack_keystone_audit::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager};
    use std::collections::HashMap;
    use std::net::SocketAddr;

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
                Arc::new(crate::policy::MockPolicy::default()),
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
                Arc::new(crate::policy::MockPolicy::default()),
                audit_dispatcher,
                None,
            )
            .await
            .unwrap(),
        );

        load_auth_plugins(&state, Arc::new(UnreachableHttpFetcher)).await;

        assert!(state.auth_plugin_registry.read().await.is_empty());
        let failures = state.auth_plugin_load_failures.read().await;
        assert_eq!(failures.get("bad"), Some(&1));

        let text = format_load_failure_metrics(&failures);
        assert!(text.contains("keystone_auth_plugin_load_failure{plugin_name=\"bad\"} 1"));
    }

    #[test]
    fn test_format_load_failure_metrics_empty() {
        let text = format_load_failure_metrics(&HashMap::new());
        assert!(text.contains("# HELP keystone_auth_plugin_load_failure"));
        assert!(text.contains("# TYPE keystone_auth_plugin_load_failure counter"));
        assert!(!text.contains("plugin_name="));
    }

    #[test]
    fn test_format_load_failure_metrics_escapes_label_value() {
        let mut failures = HashMap::new();
        failures.insert("weird\"name\\".to_string(), 3u64);
        let text = format_load_failure_metrics(&failures);
        assert!(text.contains("plugin_name=\"weird\\\"name\\\\\""));
    }
}
