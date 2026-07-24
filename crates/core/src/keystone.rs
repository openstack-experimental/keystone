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
//! # Keystone state
use std::collections::HashMap;
use std::sync::Arc;

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use sea_orm::DatabaseConnection;
use tokio::sync::RwLock;
use tracing::info;

use openstack_keystone_audit::AuditDispatcher;
use openstack_keystone_auth_plugin_runtime::WasmPluginRegistry;
use openstack_keystone_config::ConfigManager;
use openstack_keystone_local_emergency_store::{LeaderlessTracker, LocalEmergencyStore};
use openstack_keystone_storage_api::StorageApi;

use crate::auth_plugin::{CoreHostFunctions, PluginInvocationLimiter};
use crate::error::KeystoneError;
use crate::events::EventDispatcher;
use crate::policy::PolicyEnforcer;
use crate::provider::Provider;
use crate::rate_limit::RateLimitState;

// Placing ServiceState behind Arc is necessary to address DatabaseConnection
// not implementing Clone.
//#[derive(Clone)]
pub struct Service {
    /// Config file.
    pub config_manager: Arc<ConfigManager>,

    /// Database connection.
    pub db: DatabaseConnection,

    /// Policy enforcer.
    pub policy_enforcer: Arc<dyn PolicyEnforcer>,

    /// Service/resource Provider.
    pub provider: Provider,

    /// Event dispatcher for inter-provider notifications.
    pub event_dispatcher: Arc<EventDispatcher>,

    /// Audit dispatcher for fail-closed audit records.
    pub audit_dispatcher: Arc<AuditDispatcher>,

    /// Distributed storage instance (when configured).
    pub storage: Option<Arc<dyn StorageApi>>,

    /// Node-local, quorum-bypass emergency write path (ADR 0028).
    ///
    /// `None` unless a distributed storage backend was configured and
    /// `[local_emergency]` is available on this node. Populated
    /// post-construction (like `core_host_functions` below) since the real
    /// Fjall-backed store needs the same database handle
    /// `StateMachineStore` uses, which isn't available until distributed
    /// storage itself finishes initializing in
    /// `crates/keystone/src/bin/keystone.rs`.
    pub local_emergency_store: RwLock<Option<Arc<dyn LocalEmergencyStore>>>,

    /// Tracks how long this node's Raft leader has been unknown, feeding
    /// the `[local_emergency]` quorum-bypass guardrail (ADR 0028 §1).
    /// Always present (harmless/unused if `local_emergency_store` is
    /// `None`) since it carries no state until observations are recorded.
    pub local_emergency_leaderless_tracker: LeaderlessTracker,

    /// Sliding-window rate limiter for the API Key (SCIM ingress)
    /// authentication path, keyed on `lookup_hash` (or source IP when the
    /// presented token fails the format check) (ADR 0021 §6.A).
    pub api_key_rate_limiter: Arc<DefaultKeyedRateLimiter<String>>,

    /// Sliding-window rate limiter for `POST /v4/oauth2/{domain_id}/token`,
    /// keyed on the raw, unverified `client_id` string presented in the
    /// request (ADR 0026 §7.A "Pre-Hash Enforcement") - checked before any
    /// storage lookup or Argon2id verification. A separate pool from
    /// `api_key_rate_limiter` above, own tunable blast radius.
    pub oauth2_token_rate_limiter: Arc<DefaultKeyedRateLimiter<String>>,

    /// Loaded dynamic auth plugins (ADR 0025). Empty until
    /// `crate::auth_plugin_startup::load_auth_plugins` runs
    /// post-construction - `CoreHostFunctions` needs a `ServiceState`,
    /// which doesn't exist until `Service::new` returns, so this can't be
    /// populated inline here (mirrors how `subscribe_event_hooks` wires
    /// provider hooks onto an already-`Arc`-wrapped `Service` at process
    /// startup, in `crates/keystone/src/bin/keystone.rs`).
    pub auth_plugin_registry: RwLock<Arc<WasmPluginRegistry>>,

    /// The [`CoreHostFunctions`] instance the dynamic plugin registry above
    /// was loaded with - kept alongside the registry so dispatch code can
    /// call [`CoreHostFunctions::verify_handle`] using the *same*
    /// process-lifetime HMAC key the registry's plugins were loaded with.
    /// `None` until `load_auth_plugins` runs, same as the registry.
    pub core_host_functions: RwLock<Option<Arc<CoreHostFunctions>>>,

    /// Rate-limiting state (ADR-0022).
    ///
    /// Holds one `governor` keyed limiter per active bucket. `None` fields
    /// mean the corresponding bucket is disabled in `keystone.conf` and
    /// requests bypass that check entirely.
    pub rate_limiters: RateLimitState,

    /// Per-plugin invocation rate/concurrency limiters (ADR 0025 §7), keyed
    /// by plugin name - populated alongside `auth_plugin_registry` by
    /// `crate::auth_plugin_startup::load_auth_plugins`, one entry per
    /// successfully loaded plugin.
    pub auth_plugin_limiters: RwLock<HashMap<String, Arc<PluginInvocationLimiter>>>,

    /// Cumulative dynamic auth plugin load failure count, keyed by plugin
    /// name (ADR 0025 §5: a checksum mismatch, missing file, or compile
    /// error at load time is never fatal to the process - this is the
    /// backing counter for the `keystone_auth_plugin_load_failure{plugin_name}`
    /// metric §5 calls for, incremented by
    /// `crate::auth_plugin_startup::load_auth_plugins` alongside its
    /// `CRITICAL` log line).
    pub auth_plugin_load_failures: RwLock<HashMap<String, u64>>,

    /// Shutdown flag.
    pub shutdown: bool,
}

pub type ServiceState = Arc<Service>;

impl Service {
    /// Creates a new Keystone service instance.
    ///
    /// # Parameters
    /// - `cfg`: The configuration manager for the service.
    /// - `db`: The database connection.
    /// - `provider`: The provider for services/resources.
    /// - `policy_enforcer`: The policy enforcer instance.
    /// - `audit_dispatcher`: The audit dispatcher for fail-closed audit
    ///   records.
    /// - `storage`: Optional distributed storage instance.
    ///
    /// # Returns
    /// - `Ok(Self)` if the service was initialized successfully.
    /// - `Err(KeystoneError)` if there was an error during initialization.
    pub async fn new(
        cfg: Arc<ConfigManager>,
        db: DatabaseConnection,
        provider: Provider,
        policy_enforcer: Arc<dyn PolicyEnforcer>,
        audit_dispatcher: Arc<AuditDispatcher>,
        storage: Option<Arc<dyn StorageApi>>,
    ) -> Result<Self, KeystoneError> {
        let api_key_cfg = cfg.config.read().await.api_key.clone();
        let quota = Quota::per_minute(
            api_key_cfg
                .rate_limit_replenish_per_minute
                .try_into()
                .unwrap_or(std::num::NonZeroU32::MAX),
        )
        .allow_burst(
            api_key_cfg
                .rate_limit_burst_size
                .try_into()
                .unwrap_or(std::num::NonZeroU32::MAX),
        );
        let api_key_rate_limiter = Arc::new(RateLimiter::keyed(quota));

        let oauth2_cfg = cfg.config.read().await.oauth2.clone();
        let oauth2_token_quota = Quota::per_minute(
            oauth2_cfg
                .token_rate_limit_replenish_per_minute
                .try_into()
                .unwrap_or(std::num::NonZeroU32::MAX),
        )
        .allow_burst(
            oauth2_cfg
                .token_rate_limit_burst_size
                .try_into()
                .unwrap_or(std::num::NonZeroU32::MAX),
        );
        let oauth2_token_rate_limiter = Arc::new(RateLimiter::keyed(oauth2_token_quota));

        // Build rate-limiting state from config. Fails fast (Invariant 2) if
        // any enabled bucket has zero burst or replenish rate.
        let rate_limiters = {
            let config = cfg.config.read().await;
            RateLimitState::from_config(&config)?
        };

        Ok(Self {
            config_manager: cfg,
            provider,
            event_dispatcher: EventDispatcher::production(),
            audit_dispatcher,
            db,
            policy_enforcer,
            storage,
            local_emergency_store: RwLock::new(None),
            local_emergency_leaderless_tracker: LeaderlessTracker::new(),
            api_key_rate_limiter,
            oauth2_token_rate_limiter,
            auth_plugin_registry: RwLock::new(Arc::new(WasmPluginRegistry::default())),
            core_host_functions: RwLock::new(None),
            rate_limiters,
            auth_plugin_limiters: RwLock::new(HashMap::new()),
            auth_plugin_load_failures: RwLock::new(HashMap::new()),
            shutdown: false,
        })
    }

    /// Install the node-local emergency store, once distributed storage has
    /// finished initializing (ADR 0028). A no-op path (`local_emergency_store`
    /// stays `None`) if this is never called, e.g. on a node with no
    /// distributed storage configured.
    pub async fn set_local_emergency_store(&self, store: Arc<dyn LocalEmergencyStore>) {
        *self.local_emergency_store.write().await = Some(store);
    }

    /// Terminates the Keystone service.
    ///
    /// # Returns
    /// - `Ok(())` upon successful termination.
    /// - `Err(KeystoneError)` if an error occurred during termination.
    pub async fn terminate(&self) -> Result<(), KeystoneError> {
        info!("Terminating Keystone");
        // Stop the config watcher and, for a Vault-backed configuration,
        // revoke the Vault token before the process exits.
        self.config_manager.shutdown().await;
        Ok(())
    }
}
