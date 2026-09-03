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

//! Long-lived background tasks spawned at startup: the periodic cleanup
//! loop, the config-reload reactors (dummy-hash cache, rate limiters,
//! database connection), the provider event-hook subscriptions, and the
//! dynamic auth-plugin load.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sea_orm::ConnectOptions;
use secrecy::ExposeSecret;
use tokio::spawn;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use super::{Startup, debug_elapsed};
use crate::application_credential::ApplicationCredentialHook;
use crate::assignment::AssignmentHook;
use crate::auth_plugin_http_client::KeystoneDynamicPluginHttpFetcher;
use crate::auth_plugin_identity::DynamicPluginIdentityHook;
use crate::auth_plugin_startup::load_auth_plugins;
use crate::catalog::CatalogHook;
use crate::db_reload;
use crate::federation::FederationHook;
use crate::identity::IdentityHook;
use crate::idmapping::IdMappingHook;
use crate::k8s_auth::K8sAuthHook;
use crate::oauth2_key::Oauth2KeyHook;
use crate::resource::ResourceHook;
use crate::revoke::RevokeHook;
use crate::role::RoleHook;
use crate::token::TokenHook;
use crate::trust::TrustHook;
use openstack_keystone_core::api_key::janitor as api_key_janitor;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::cadf_hook::CadfAuditHook;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::oauth2_key::janitor as oauth2_key_janitor;
use openstack_keystone_core::scim_resource::janitor as scim_resource_janitor;

/// Spawn every background task and perform the post-construction hook/plugin
/// wiring. `phase_start` is only used for the phase-timing traces (measured
/// from the start of the listen phase, as the original `main` did).
pub async fn spawn_all(startup: &Startup, phase_start: Instant) {
    let token = &startup.token;
    let state = &startup.state;

    // Periodic cleanup: federation cleanup, auth-plugin limiter shrink
    // (ADR 0025 §7), stale rate-limit key eviction (ADR 0022), all on one
    // 60s tick.
    spawn(cleanup(token.clone(), state.clone()));

    // Leader-gated janitors (each runs on every node, only does work on the
    // current Raft leader):
    //  - API Key (SCIM ingress) inactivity disablement + tombstone purge
    //    (ADR 0021 §6.F)
    //  - SCIM resource permanent purge past retention (ADR 0024 §6.C)
    //  - OAuth2 signing-key `Previous` retirement + JTI list pruning
    //    (ADR 0026 §3)
    api_key_janitor::spawn(state.clone());
    scim_resource_janitor::spawn(state.clone());
    oauth2_key_janitor::spawn(state.clone());

    // Config-reload reactors.
    spawn(reset_dummy_hash_on_reload(token.clone(), state.clone()));
    spawn(reload_rate_limits_on_config_change(
        token.clone(),
        state.clone(),
    ));
    spawn(reconnect_db_on_config_change(token.clone(), state.clone()));

    subscribe_event_hooks(state).await;
    debug_elapsed(phase_start, "subscribe_event_hooks");

    // Dynamic auth plugins (ADR 0025): loaded post-construction since
    // `CoreHostFunctions` needs a fully-built `ServiceState`. A per-plugin
    // load failure disables only that plugin.
    load_auth_plugins(state, Arc::new(KeystoneDynamicPluginHttpFetcher::new())).await;
    debug_elapsed(phase_start, "load_auth_plugins");
    warn_on_unresolvable_auth_methods(state).await;
}

/// Subscribe every provider event hook, plus the CADF audit hook, to
/// `state`'s event dispatcher.
async fn subscribe_event_hooks(state: &ServiceState) {
    macro_rules! subscribe {
        ($($hook:ty),+ $(,)?) => {$(
            state
                .event_dispatcher
                .subscribe(Arc::new(<$hook>::new(state.clone())))
                .await;
        )+};
    }
    subscribe!(
        ApplicationCredentialHook,
        AssignmentHook,
        CatalogHook,
        DynamicPluginIdentityHook,
        FederationHook,
        IdentityHook,
        IdMappingHook,
        K8sAuthHook,
        Oauth2KeyHook,
        ResourceHook,
        RevokeHook,
        RoleHook,
        TokenHook,
        TrustHook,
    );

    // Phase 3: the CADF audit hook (fail-closed provider auditing) — a
    // separate `subscribe_audit` channel, not the generic one above.
    state
        .event_dispatcher
        .subscribe_audit(Arc::new(CadfAuditHook::new(Arc::clone(
            &state.audit_dispatcher,
        ))))
        .await;
}

/// Log a `WARN` for every `[auth] methods` entry that is neither a builtin
/// auth method nor a successfully-loaded dynamic plugin name (ADR 0025 §5:
/// a misconfiguration here degrades one method, not the node).
async fn warn_on_unresolvable_auth_methods(state: &ServiceState) {
    const BUILTIN_AUTH_METHODS: &[&str] = &[
        "password",
        "token",
        "totp",
        "openid",
        "application_credential",
        "trust",
        "webauthn",
        "mapped",
        "k8s",
        "admin",
    ];
    let methods = state
        .config_manager
        .config
        .read()
        .await
        .auth
        .methods
        .clone();
    let registry = state.auth_plugin_registry.read().await;
    for method in &methods {
        if !BUILTIN_AUTH_METHODS.contains(&method.as_str()) && !registry.contains(method) {
            warn!(
                method = %method,
                "[auth] methods names a method that is neither a builtin nor a loaded dynamic \
                 auth plugin - this method will never authenticate anyone"
            );
        }
    }
}

/// Periodic best-effort housekeeping on a 60s tick: federation provider
/// cleanup, per-plugin rate-limit keyed-store shrink (ADR 0025 §7), and
/// global rate-limit stale-entry eviction (ADR 0022).
async fn cleanup(cancel: CancellationToken, state: ServiceState) {
    let mut interval = time::interval(Duration::from_secs(60));
    interval.tick().await;
    info!("Start the periodic cleanup thread");
    loop {
        tokio::select! {
            _ = interval.tick() => {
                trace!("cleanup job tick");
                if let Err(e) = state
                    .provider
                    .get_federation_provider()
                    .cleanup(&ExecutionContext::internal(&state))
                    .await
                {
                    error!("Error during cleanup job: {}", e);
                }
                for limiter in state.auth_plugin_limiters.read().await.values() {
                    limiter.shrink_idle_sources();
                }
                state.rate_limiters.retain_recent();
            },
            () = cancel.cancelled() => {
                info!("Cancellation requested. Stopping cleanup task.");
                break;
            }
        }
    }
}

/// Clear the dummy-password-hash cache on every configuration reload.
///
/// Subscribes to `ConfigManager::notify_tx`. On every notification (or a
/// lagged receiver) we drop all cached `(algorithm, rounds)` dummy hashes so
/// the next authentication of a non-existent user recomputes one matching
/// the new configuration — always safe.
async fn reset_dummy_hash_on_reload(cancel: CancellationToken, state: ServiceState) {
    let mut reload_rx = state.config_manager.notify_tx.subscribe();
    loop {
        tokio::select! {
            recv = reload_rx.recv() => {
                match recv {
                    Ok(()) => {
                        debug!("Configuration reloaded; clearing dummy-hash cache");
                        openstack_keystone_password_hashing::reset_dummy_hash_cache().await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(skipped, "Lagged behind config reloads; clearing dummy-hash cache");
                        openstack_keystone_password_hashing::reset_dummy_hash_cache().await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            () = cancel.cancelled() => {
                info!("Cancellation requested. Stopping dummy-hash reset task.");
                break;
            }
        }
    }
}

/// Atomically rebuild rate limiters when their configuration changes.
///
/// Invalid runtime replacements are logged and ignored, preserving the
/// previous validated limiter and its counters. Initial configuration
/// remains fail-hard in `KeystoneServiceState::new`.
async fn reload_rate_limits_on_config_change(cancel: CancellationToken, state: ServiceState) {
    let mut reload_rx = state.config_manager.notify_tx.subscribe();
    loop {
        tokio::select! {
            recv = reload_rx.recv() => {
                match recv {
                    Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        let config = state.config_manager.config.read().await;
                        match state.rate_limiters.reload(&config) {
                            Ok(true) => info!("Rate-limit configuration reloaded"),
                            Ok(false) => {}
                            Err(error) => error!(
                                %error,
                                "Invalid rate-limit configuration reload; retaining last-known-good state"
                            ),
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            () = cancel.cancelled() => {
                info!("Cancellation requested. Stopping rate-limit reload task.");
                break;
            }
        }
    }
}

/// Rebuild the database connection when its resolved connection string, or
/// any of its configured `[database]` TLS files, change across a
/// configuration reload — including a Vault-backed `[database] connection`
/// re-resolving to rotated credentials, or a `tls_*_file` rotating on disk
/// without the DSN string itself changing.
///
/// Triggered only by `ConfigManager::notify_tx`; there is deliberately no
/// periodic timer fallback. An unreachable host or invalid/stale rotated
/// credential is logged and the existing connection is left in service
/// (last-known-good).
async fn reconnect_db_on_config_change(cancel: CancellationToken, state: ServiceState) {
    let mut reload_rx = state.config_manager.notify_tx.subscribe();
    let mut current_dsn = state
        .config_manager
        .config
        .read()
        .await
        .database
        .get_connection();
    let mut current_tls_mtimes =
        db_reload::db_tls_mtimes(&*state.config_manager.config.read().await);
    loop {
        tokio::select! {
            recv = reload_rx.recv() => {
                match recv {
                    Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        let config = state.config_manager.config.read().await;
                        let new_dsn = config.database.get_connection();
                        let new_tls_mtimes = db_reload::db_tls_mtimes(&config);
                        if new_dsn.expose_secret() == current_dsn.expose_secret()
                            && new_tls_mtimes == current_tls_mtimes
                        {
                            continue;
                        }
                        let mut opt = ConnectOptions::new(new_dsn.expose_secret())
                            .sqlx_logging(config.database.sqlx_logging_enabled())
                            .sqlx_logging_level(config.database.sqlx_logging_level())
                            .to_owned();
                        db_reload::apply_db_tls(&mut opt, &config.database.tls);
                        drop(config);
                        match state.db.reconnect(opt).await {
                            Ok(()) => {
                                info!("Database connection reloaded");
                                current_dsn = new_dsn;
                                current_tls_mtimes = new_tls_mtimes;
                            }
                            Err(error) => error!(
                                %error,
                                "Failed to reconnect to database with reloaded configuration; \
                                 retaining last-known-good connection"
                            ),
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            () = cancel.cancelled() => {
                info!("Cancellation requested. Stopping database reconnect task.");
                break;
            }
        }
    }
}
