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
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::Config;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_distributed_storage::app::Storage;

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
    /// Process-wide shutdown signal. Cancelled by the signal watcher or by
    /// any listener task that exits/fails.
    pub token: CancellationToken,
    /// The shared service state handed to every API handler.
    pub state: ServiceState,
    /// The concrete distributed-storage handle, when `[distributed_storage]`
    /// is configured. Needed by the Raft listener and the node-local
    /// emergency store wiring.
    pub concrete_storage: Option<Arc<Storage>>,
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

    let cfg_mgr = crate::config::ConfigManager::watched(args.config.clone()).await?;
    let cfg = cfg_mgr.config.read().await.clone();

    // The guard must stay alive for the rest of `run` to flush buffered
    // file-appender logs.
    let _guard = tracing_init::init(args.verbose, &cfg)?;
    color_eyre::install()?;

    info!("Starting Keystone...");
    let startup_timer = Instant::now();

    let startup = bootstrap::run(cfg_mgr, cfg, startup_timer).await?;

    // Phase timings from here on are measured relative to the start of the
    // listen phase (matching the original `main`), not process start.
    let listen_phase_start = Instant::now();
    background::spawn_all(&startup, listen_phase_start).await;

    let (app, http_metrics) = router::build(&startup, main_router, openapi).await?;
    debug_elapsed(listen_phase_start, "build_router");

    shutdown::spawn_watcher(&startup);

    let mut handles: JoinSet<()> = JoinSet::new();
    raft::start(&startup, &mut handles).await?;
    opa::spawn(&startup, &mut handles).await?;
    listeners::spawn_public(&startup, app.clone(), &mut handles).await?;
    listeners::spawn_internal(&startup, app.clone(), &mut handles)?;
    listeners::spawn_metrics(&startup, http_metrics.as_ref(), &mut handles).await?;
    listeners::spawn_admin(&startup, app, &mut handles);

    info!(
        "Keystone is now running (startup took {:.3}s)",
        startup_timer.elapsed().as_secs_f32()
    );

    shutdown::await_listeners(handles).await;
    startup.token.cancel();
    Ok(())
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
    use openstack_keystone_audit::AuditDispatcher;
    use openstack_keystone_core::keystone::Service;
    use openstack_keystone_core::policy::MockPolicy;
    use openstack_keystone_core::provider::Provider;

    pub(crate) fn test_config(spool_dir: PathBuf) -> Config {
        let mut cfg = Config::default();
        cfg.audit.spool_dir = spool_dir;
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
            token: CancellationToken::new(),
            state,
            concrete_storage: None,
        }
    }
}
