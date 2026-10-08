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

//! # Keystone process startup
//!
//! Everything the `keystone` binary does between `main()` and the point where
//! the listener tasks are awaited: CLI parsing, tracing/audit initialization,
//! service-state construction, background task supervision, router assembly,
//! and the per-interface listeners.
//!
//! `main()` in `src/bin/keystone.rs` is a thin shell that calls [`run`].

use std::sync::Arc;
use std::time::Instant;

use clap::Parser;
use color_eyre::eyre::{Report, Result};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_distributed_storage::app::Storage;
use openstack_keystone_distributed_storage::config::DistributedStorageConfiguration;

pub mod args;
pub mod audit;
pub mod background;
pub mod bootstrap;
pub mod listeners;
pub mod opa;
pub mod raft;
pub mod router;
pub mod shutdown;
pub mod tracing_init;

pub use args::{Args, OpenApiFormat};

/// Everything the post-bootstrap startup steps need in one bundle, so each
/// step takes `&Startup` instead of a growing parameter list.
pub struct Startup {
    /// The fully resolved configuration snapshot taken at startup. Live
    /// reloads are observed through `state.config_manager`, not this copy.
    pub cfg: Config,
    /// The `[distributed_storage]` section of the startup snapshot, when
    /// distributed storage is configured.
    pub distributed_storage: Option<DistributedStorageConfiguration>,
    /// Process-wide shutdown signal. Cancelled by the signal watcher or by
    /// any listener task that exits/fails.
    pub token: CancellationToken,
    /// The shared service state handed to every API handler.
    pub state: ServiceState,
    /// The concrete distributed-storage handle, when `[distributed_storage]`
    /// is configured. Needed by the Raft listener and the node-local
    /// emergency store wiring.
    pub concrete_storage: Option<Arc<Storage>>,
    /// The audit spool writer task. Awaited (bounded) after `token` is
    /// cancelled so queued audit events are flushed before the process exits.
    pub audit_writer: Option<JoinHandle<()>>,
}

/// Report the effective `[otel]` / `[oslo_middleware_tracing]` configuration
/// (ADR 0040) now that the subscriber is installed: alias notes, conflicts
/// between the two sections, and whether anything is being exported.
fn log_telemetry_config(guards: &tracing_init::Guards) {
    if let Some(err) = &guards.telemetry_error {
        warn!("telemetry: not exporting: {err}");
    }
    let Some(resolved) = &guards.resolved else {
        return;
    };
    for warning in &resolved.warnings {
        warn!("telemetry: {warning}");
    }
    let Some(settings) = &resolved.settings else {
        return;
    };
    if guards.exporting() {
        info!(
            traces = settings.traces_enabled,
            metrics = settings.metrics_enabled,
            endpoint = %settings.endpoint,
            protocol = ?settings.protocol,
            service_name = %settings.service_name,
            "telemetry: exporting over OTLP"
        );
    } else if !openstack_keystone_telemetry::OTLP_COMPILED {
        warn!(
            "telemetry is enabled in the configuration but this build has no OTLP support \
             (build with the `otel` feature); nothing will be exported"
        );
    }
}

/// Parse CLI arguments, initialize logging, build the service, spawn the
/// background tasks and listeners, then block until one listener task exits
/// and tear the rest down.
///
/// `#[allow(clippy::print_stdout)]` covers the `--dump-openapi` path, which
/// deliberately writes the schema to stdout.
#[allow(clippy::print_stdout)]
pub async fn run() -> Result<(), Report> {
    let args = Args::parse();

    // When only dumping the OpenAPI spec we must not touch the config file,
    // so logging is not initialized yet either.
    let (main_router, openapi) = args::build_api();
    if let Some(dump_format) = &args.dump_openapi {
        return args::dump_openapi(dump_format, &openapi);
    }

    // Catch a driver section whose registration the linker dropped (ADR 0018,
    // ADR 0039) before the configuration is loaded without it.
    oslo_config::assert_registered(&[
        "jws_tokens",
        "distributed_storage",
        "otel",
        "oslo_middleware_tracing",
    ])?;
    #[cfg(feature = "openfga")]
    oslo_config::assert_registered(&["openfga"])?;

    let cfg_mgr = crate::config::ConfigManager::watched(args.config.clone()).await?;
    let cfg = cfg_mgr.config.read().await.clone();

    // The guard must stay alive for the rest of `run` to flush buffered
    // file-appender logs.
    let guards = tracing_init::init(args.verbose, &cfg)?;
    color_eyre::install()?;
    log_telemetry_config(&guards);

    check_oauth2_public_endpoint(&cfg);
    crate::api::v4::oauth2::init_ui(&cfg.oauth2).map_err(|e| eyre::eyre!(e))?;

    info!("Starting Keystone...");
    let startup_timer = Instant::now();

    let mut startup = bootstrap::run(cfg_mgr, cfg, startup_timer).await?;

    // Phase timings from here on are measured relative to the start of the
    // listen phase (matching the original `main`), not process start.
    let listen_phase_start = Instant::now();
    debug!("Spawning background tasks...");
    background::spawn_all(&startup, listen_phase_start).await;
    debug_elapsed(listen_phase_start, "spawn_background_tasks");

    let (app, http_metrics) = router::build(&startup, main_router, openapi).await?;
    debug_elapsed(listen_phase_start, "build_router");

    shutdown::spawn_watcher(&startup);

    let mut handles: JoinSet<()> = JoinSet::new();
    debug!("Starting Raft gRPC listener and cluster join...");
    raft::start(&startup, &mut handles).await?;
    debug_elapsed(listen_phase_start, "raft_start");
    debug!("Starting embedded OPA...");
    opa::spawn(&startup, &mut handles).await?;
    debug_elapsed(listen_phase_start, "opa_spawn");
    debug!("Starting public listener...");
    listeners::spawn_public(&startup, app.clone(), &mut handles).await?;
    debug!("Starting internal listener...");
    listeners::spawn_internal(&startup, app.clone(), &mut handles)?;
    debug!("Starting metrics listener...");
    listeners::spawn_metrics(&startup, http_metrics.as_ref(), &mut handles).await?;
    debug!("Starting admin listener...");
    listeners::spawn_admin(&startup, app, &mut handles);

    info!(
        "Keystone is now running (startup took {:.3}s)",
        startup_timer.elapsed().as_secs_f32()
    );

    shutdown::await_listeners(handles).await;
    startup.token.cancel();
    shutdown::await_audit_writer(startup.audit_writer.take(), &startup.cfg).await;
    guards.shutdown().await;
    Ok(())
}

/// Log an error when the OAuth2 OP would have to derive its issuer from the
/// request `Host` header.
///
/// Without `[DEFAULT] public_endpoint` the OP endpoints (`/authorize`,
/// `/device_authorization`, `/token`, discovery) answer `503` unless the
/// development-only `[oauth2] allow_host_header_issuer` override is on.
pub(crate) fn check_oauth2_public_endpoint(cfg: &Config) {
    if cfg.default.public_endpoint.is_some() {
        return;
    }
    if cfg.oauth2.allow_host_header_issuer {
        warn!(
            "[oauth2] allow_host_header_issuer is enabled and [DEFAULT] public_endpoint is \
             not set: the OAuth2 issuer follows the request Host header. Use for \
             development only."
        );
    } else {
        error!(
            "[DEFAULT] public_endpoint is not set: the OAuth2 provider endpoints will \
             answer 503 server_error because the issuer cannot be pinned. Set \
             public_endpoint to the externally visible https URL."
        );
    }
}

/// Emit a `DEBUG` line with the wall-clock time since `since` for a named
/// startup phase. Shared by the phase-timing traces that used to be inline in
/// `main`.
pub(crate) fn debug_elapsed(since: Instant, phase: &str) {
    tracing::debug!("{phase} took {:.3}s", since.elapsed().as_secs_f32());
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared fixtures for the `startup` submodule tests: a mocked
    //! `ServiceState` and a `Startup` bundle wrapping it. Mirrors
    //! `openstack_keystone_core::tests::get_mocked_state`, which is
    //! `#[cfg(test)]`-gated inside `core` and not visible here.

    use std::path::PathBuf;

    use sea_orm::DatabaseConnection;

    use super::*;
    use crate::config::ConfigManager;
    use cadf::AuditDispatcher;
    use openstack_keystone_core::keystone::Service;
    use openstack_keystone_core::policy::MockPolicy;
    use openstack_keystone_core::provider::Provider;

    pub(crate) fn test_config(spool_dir: PathBuf) -> Config {
        let mut cfg = Config::default();
        cfg.audit.spool_dir = Some(spool_dir);
        cfg.audit.node_id = "test-node".into();
        cfg
    }

    pub(crate) async fn test_state(cfg: Config) -> ServiceState {
        Arc::new(
            Service::new(
                ConfigManager::not_watched(cfg),
                DatabaseConnection::default(),
                Provider::mocked_builder().build().unwrap(),
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        )
    }

    pub(crate) async fn test_startup(cfg: Config) -> Startup {
        let state = test_state(cfg.clone()).await;
        Startup {
            cfg,
            distributed_storage: None,
            token: CancellationToken::new(),
            state,
            concrete_storage: None,
            audit_writer: None,
        }
    }
}
