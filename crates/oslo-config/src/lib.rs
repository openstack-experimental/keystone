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
//! # OpenStack oslo.config style configuration engine
//!
//! A service-agnostic configuration engine modelled after Python's
//! `oslo.config`, where every module registers its own option group while the
//! deployment keeps a single file that is reloaded live.
//!
//! ## What the engine does
//!
//! - The file is parsed as INI (full compatibility with the legacy OpenStack
//!   format).
//! - An optional additional file, named by an environment variable chosen by
//!   the service ([`SourceSpec::site_vars_env`]), overlays the main file.
//! - Environment variables take final precedence. With the prefix `OS` and the
//!   separator `__` they look like `OS_API_POLICY__OPA_BASE_URL` for setting
//!   `[api_policy].opa_base_url`.
//! - Vault references (`vault://mount/path#key`) are resolved on the raw
//!   configuration before it is deserialized. They need a `[vault]` section
//!   (`VaultSection`). This is the `vault` cargo feature, enabled by default;
//!   without it the Vault client dependencies are not built and references
//!   are left untouched.
//! - [`ConfigManager`] watches the files and reloads the configuration on
//!   change, keeping the last-known-good configuration when a reload fails.
//!
//! The engine knows nothing about the sections of a particular service.
//!
//! ## Concepts
//!
//! - **Core schema** ([`CoreSchema`]): the top-level configuration type of the
//!   service. It owns the sections that the core of the service reads or that
//!   more than one crate needs. It describes where the raw configuration comes
//!   from ([`CoreSchema::source`]) and which section names it uses
//!   ([`CoreSchema::reserved_sections`]).
//! - **Registered section** ([`ConfigSection`]): a section owned by any other
//!   crate (a driver, a library). The INI section name is bound to the Rust
//!   type, so a typed lookup can never mismatch the name. The crate registers
//!   the type at link time with [`register_section!`]; no central schema needs
//!   to change. A type implementing [`Default`] is optional (materialized from
//!   `Default` when absent, registered as `register_section!(S, default)`), a
//!   type without it is required (absent from the [`SectionBag`] when the file
//!   does not contain it, [`ConfigView::require`] reports it).
//! - **Block** ([`register_block!`], [`parse_block`], [`ParsedSection`]): a
//!   driver specific configuration block whose type is chosen by a
//!   discriminator in the file (e.g. `driver = openfga` in
//!   `[assignment.backends.<name>]`) instead of by the section name. The
//!   schema keeps the parsed block type erased as a [`ParsedSection`] and the
//!   driver recovers its type with [`ParsedSection::downcast_ref`].
//!
//! ### Section or block?
//!
//! | | Registered section | Block |
//! |---|---|---|
//! | Selected by | INI section name ([`ConfigSection::NAME`]) | `driver` discriminator inside a namespace owned by the schema |
//! | Registered with | [`register_section!`] | [`register_block!`] |
//! | Lives in | [`SectionBag`] of the snapshot | a field of the core schema |
//! | Read with | [`ConfigView::section`] / [`ConfigView::require`] | [`ParsedSection::downcast_ref`] |
//! | Absent | `None` / error naming the section (or `Default`) | the schema decides |
//!
//! One type can serve both. OpenFGA registers `[openfga]` as a section for the
//! global driver (`view.require::<OpenFga>()`) and the same type as the block
//! of `[assignment.backends.<name>]` for per-domain drivers
//! (`block.downcast_ref::<OpenFga>()`).
//! - **Snapshot** ([`Loaded`]): the core schema value together with the
//!   registered sections. A reload swaps both atomically. Read it through a
//!   [`ConfigView`].
//!
//! ## Loading pipeline
//!
//! raw configuration (file, site-vars file, environment) -> Vault resolution
//! -> registered sections ([`ConfigSection::finish`], then the validation pass
//! [`ConfigSection::validate_with`]) -> core schema
//! ([`CoreSchema::finish_load`]). Env override, site-vars and Vault therefore
//! apply to registered sections exactly like to the core ones. Sections that
//! are neither reserved by the core schema nor registered are reported with a
//! warning (a misspelled name or a driver that is not linked).
//!
//! ## Linking
//!
//! Registration happens through the [`inventory`] crate: it only works when
//! the crate that registers a section is actually linked into the binary. A
//! crate that is merely a dependency without any referenced symbol can be
//! dropped by the linker, silently turning a required section into a missing
//! one. The usual remedy is to expose a no-op `anchor()` function that the
//! binary calls, and to verify at startup with [`assert_registered`].
//! [`check_registry`] rejects duplicate names and names that collide with the
//! core schema.
//!
//! ## Example
//!
//! ```no_run
//! use std::path::PathBuf;
//!
//! use oslo_config::{
//!     ConfigManager, ConfigSection, CoreSchema, SourceSpec, register_section,
//! };
//! use serde::Deserialize;
//!
//! /// The core schema of the service: only what the core itself reads.
//! #[derive(Deserialize)]
//! struct Config {
//!     #[serde(default)]
//!     database: Database,
//! }
//!
//! #[derive(Default, Deserialize)]
//! struct Database {
//!     connection: Option<String>,
//! }
//!
//! impl CoreSchema for Config {
//!     fn source() -> SourceSpec {
//!         SourceSpec {
//!             env_prefix: "OS",
//!             env_prefix_separator: "_",
//!             env_separator: "__",
//!             site_vars_env: "MYSERVICE_SITE_VARS_FILE",
//!         }
//!     }
//!
//!     // Names of the fields of `Config`, so that registered sections
//!     // cannot reuse them.
//!     fn reserved_sections() -> &'static [&'static str] {
//!         &["database"]
//!     }
//! }
//!
//! /// A section owned by a driver crate: `[cache]`.
//! #[derive(Default, Deserialize)]
//! struct CacheSection {
//!     #[serde(default)]
//!     ttl_seconds: u64,
//! }
//!
//! impl ConfigSection for CacheSection {
//!     const NAME: &'static str = "cache";
//! }
//!
//! // Optional section: `CacheSection::default()` when `[cache]` is absent.
//! register_section!(CacheSection, default);
//!
//! // The same type can also be the block of a namespace owned by the schema,
//! // e.g. `[caches.<name>] driver = local`. The schema stores the parsed block
//! // as a `ParsedSection` (see `oslo_config::parse_block`) and the driver
//! // reads it back with `downcast_ref`:
//! //
//! //     register_block!("caches", "local", CacheSection);
//! //     let cfg = block.downcast_ref::<CacheSection>();
//!
//! # async fn run() -> Result<(), eyre::Report> {
//! // Load, start the file watcher and keep the configuration live.
//! let manager = ConfigManager::<Config>::watched(PathBuf::from("/etc/myservice.conf")).await?;
//!
//! // Take a snapshot and read the core schema and a registered section.
//! let snapshot = manager.config.read().await;
//! let view = snapshot.view();
//! let _connection = &view.database.connection;
//! let _ttl = view.require::<CacheSection>()?.ttl_seconds;
//!
//! // React to reloads.
//! let mut changes = manager.notify_tx.subscribe();
//! let _ = changes.recv().await;
//!
//! manager.shutdown().await;
//! # Ok(())
//! # }
//! ```
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use config::{File, FileFormat};
use eyre::{Report, WrapErr};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde::de::DeserializeOwned;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::error;

mod primitives;
mod section;
/// Resolution of `vault://` references and the live Vault state.
#[cfg(feature = "vault")]
pub mod vault;
/// Stand-in for the [`vault`] module when the `vault` feature is disabled:
/// no reference is ever resolved, so there is never a Vault runtime.
#[cfg(not(feature = "vault"))]
mod vault {
    use tokio::time::Instant;

    /// Error raised for a configuration that is invalid after resolution.
    /// Never constructed without the `vault` feature.
    #[derive(Debug)]
    pub(crate) enum VaultConfigError {
        /// See the `vault` feature.
        ResolvedConfigurationInvalid,
    }

    impl std::fmt::Display for VaultConfigError {
        /// Format the error.
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("configuration is invalid after resolving Vault references")
        }
    }

    impl std::error::Error for VaultConfigError {}

    /// Uninhabited: without the `vault` feature there is no Vault state.
    pub(crate) enum VaultRuntime {}

    impl VaultRuntime {
        /// Never called, there is no value of this type.
        pub(crate) async fn has_new_version(&mut self) -> Result<bool, VaultConfigError> {
            match *self {}
        }

        /// Never called, there is no value of this type.
        pub(crate) fn next_deadline(&self) -> Instant {
            match *self {}
        }

        /// Never called, there is no value of this type.
        pub(crate) async fn renew_if_due(&mut self) -> Result<(), VaultConfigError> {
            match *self {}
        }

        /// Never called, there is no value of this type.
        pub(crate) async fn revoke(&self) -> Result<(), VaultConfigError> {
            match *self {}
        }
    }
}

pub use inventory;
pub use primitives::*;
pub use section::{
    BlockDescriptor, ConfigError, ConfigSection, ConfigView, LoadCtx, Loaded, ParsedSection,
    SectionBag, SectionDescriptor, assert_registered, check_registry, parse_block,
    unclaimed_sections,
};
#[cfg(feature = "vault")]
pub use vault::VaultSection;

/// Where a service reads its raw configuration from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSpec {
    /// Prefix of the environment variables overriding configuration values
    /// (without the separator), e.g. `OS`.
    pub env_prefix: &'static str,
    /// Separator between the prefix and the section name, e.g. `_`.
    pub env_prefix_separator: &'static str,
    /// Separator between the section and the option, e.g. `__`.
    pub env_separator: &'static str,
    /// Name of the environment variable holding the path of an additional
    /// ("site vars") file that overlays the main file, e.g.
    /// `KEYSTONE_SITE_VARS_FILE`.
    pub site_vars_env: &'static str,
}

/// The top-level configuration type of a service.
pub trait CoreSchema: DeserializeOwned + Send + Sync + 'static {
    /// Post-process a freshly parsed configuration: read the files it refers
    /// to and validate it. Used by the full loading pipeline
    /// ([`load_all`], [`ConfigManager`]) and not by [`load`].
    fn finish_load(self, _ctx: &LoadCtx) -> Result<Self, Report> {
        Ok(self)
    }

    /// Names of the sections of the core schema. Registered sections must not
    /// reuse them.
    fn reserved_sections() -> &'static [&'static str] {
        &[]
    }

    /// Describe where the raw configuration comes from.
    fn source() -> SourceSpec;

    /// Files (or directories) whose change must trigger a reload, in addition
    /// to the main configuration file.
    fn watch_files(&self) -> HashSet<PathBuf> {
        HashSet::new()
    }
}

/// Build the raw (not yet deserialized) configuration: main file, site-vars
/// file and environment overrides, in increasing precedence.
pub fn build_raw<C: CoreSchema>(path: PathBuf) -> Result<config::Config, Report> {
    let spec = C::source();
    let mut builder = config::Config::builder();

    if std::path::Path::new(&path).is_file() {
        builder = builder.add_source(File::from(path).format(FileFormat::Ini));
    }

    if let Ok(site_vars_file) = std::env::var(spec.site_vars_env) {
        builder = builder.add_source(File::with_name(&site_vars_file));
    }

    builder
        .add_source(
            config::Environment::with_prefix(spec.env_prefix)
                .prefix_separator(spec.env_prefix_separator)
                .separator(spec.env_separator),
        )
        .build()
        .wrap_err("Failed to read configuration file")
}

/// Deserialize the raw configuration into the service schema.
pub fn from_raw<C: CoreSchema>(raw: config::Config) -> Result<C, Report> {
    raw.try_deserialize()
        .wrap_err("Failed to parse configuration file")
}

/// Load and parse the config file, resolving any Vault references.
pub async fn load<C: CoreSchema>(path: PathBuf) -> Result<C, Report> {
    let mut raw = build_raw::<C>(path)?;
    resolve_vault_references(&mut raw).await?;
    from_raw::<C>(raw)
}

/// Load the config file, resolve Vault references and everything the schema
/// refers to ([`CoreSchema::finish_load`]).
pub async fn load_all<C: CoreSchema>(path: PathBuf) -> Result<C, Report> {
    Ok(load_all_with_vault_state::<C>(&path).await?.config.core)
}

/// Like [`load_all`] but also materializes the registered sections.
pub async fn load_snapshot_from<C: CoreSchema>(path: PathBuf) -> Result<Loaded<C>, Report> {
    Ok(load_all_with_vault_state::<C>(&path).await?.config)
}

/// Resolve any Vault references in `raw` in place.
///
/// Returns `Ok(None)` when the configuration contains no Vault references
/// (so a plain configuration pays no Vault cost), or `Ok(Some(runtime))`
/// with the live [`vault::VaultRuntime`] used to keep the resolved secrets
/// current.
#[cfg(feature = "vault")]
async fn resolve_vault_references(
    raw: &mut config::Config,
) -> Result<Option<vault::VaultRuntime>, Report> {
    if !vault::contains_vault_references(&raw.cache)? {
        return Ok(None);
    }
    raw.get_table("vault")
        .map_err(|_| vault::VaultConfigError::MissingConfiguration)?;
    let vault_config: VaultSection = raw
        .get("vault")
        .map_err(|_| vault::VaultConfigError::InvalidConfiguration)?;
    let resolved = vault::resolve(raw, &vault_config).await?;
    Ok(Some(resolved.runtime))
}

/// Without the `vault` feature references are not resolved.
#[cfg(not(feature = "vault"))]
async fn resolve_vault_references(
    _raw: &mut config::Config,
) -> Result<Option<vault::VaultRuntime>, Report> {
    Ok(None)
}

/// Load the complete snapshot together with the Vault runtime that keeps the
/// resolved secrets current.
async fn load_all_with_vault_state<C: CoreSchema>(path: &Path) -> Result<LoadedConfig<C>, Report> {
    let mut raw = build_raw::<C>(path.to_path_buf())?;
    let vault = resolve_vault_references(&mut raw).await?;
    let parsed = load_snapshot::<C>(raw, path);
    let config = match vault {
        // A configuration that resolved Vault references but then failed to
        // build is surfaced distinctly from a plain configuration error.
        Some(_) => parsed.map_err(|_| vault::VaultConfigError::ResolvedConfigurationInvalid)?,
        None => parsed?,
    };
    Ok(LoadedConfig { config, vault })
}

/// Parse the core schema and the registered sections out of `raw`.
fn load_snapshot<C: CoreSchema>(raw: config::Config, path: &Path) -> Result<Loaded<C>, Report> {
    check_registry(C::reserved_sections())?;
    for name in unclaimed_sections(&raw, C::reserved_sections()) {
        tracing::warn!(
            section = %name,
            "configuration section [{name}] is not claimed by the core schema or any \
             registered section and is ignored (misspelled name or driver not linked?)"
        );
    }
    let ctx = LoadCtx {
        config_path: path.to_path_buf(),
    };
    let sections = section::load_sections(&raw, &ctx)?;
    let core = from_raw::<C>(raw).and_then(|c| c.finish_load(&ctx))?;
    Ok(Loaded {
        core,
        sections: Arc::new(sections),
    })
}

/// Result of a full load: the snapshot and the Vault runtime (when the
/// configuration references Vault).
struct LoadedConfig<C> {
    /// The loaded snapshot.
    config: Loaded<C>,
    /// Live Vault state, `None` for a configuration without Vault references.
    vault: Option<vault::VaultRuntime>,
}

/// Config Manager supporting config file watch and reload.
pub struct ConfigManager<C> {
    /// The current config.
    pub config: Arc<RwLock<Loaded<C>>>,
    /// Notify listeners that something changed.
    pub notify_tx: tokio::sync::broadcast::Sender<()>,
    /// Signals the background watcher to stop and run its teardown (e.g.
    /// revoking the Vault token) on graceful shutdown.
    shutdown: CancellationToken,
    /// Handle to the spawned watcher task, awaited by [`Self::shutdown`] so
    /// teardown completes before the process exits.
    watcher_handle: Mutex<Option<JoinHandle<()>>>,
}

impl<C: CoreSchema> ConfigManager<C> {
    /// Swap in a freshly loaded snapshot, register watches for newly
    /// referenced files, replace the Vault runtime and notify listeners.
    async fn apply_loaded(
        manager: &Arc<Self>,
        loaded: LoadedConfig<C>,
        vault_runtime: &mut Option<vault::VaultRuntime>,
        watcher: &mut RecommendedWatcher,
        watched_paths: &mut HashSet<PathBuf>,
    ) {
        let mut candidates = loaded.config.core.watch_files();
        candidates.extend(loaded.config.section_watch_files());
        for watch_candidate in candidates {
            if !watched_paths.contains(&watch_candidate) {
                let _ = watcher.watch(watch_candidate.as_path(), RecursiveMode::NonRecursive);
                watched_paths.insert(watch_candidate);
            }
        }

        *manager.config.write().await = loaded.config;
        *vault_runtime = loaded.vault;
        let _ = manager.notify_tx.send(());
    }

    /// Initialize the Manager with no watcher.
    pub fn not_watched(config: C) -> Arc<Self> {
        let (notify_tx, _) = tokio::sync::broadcast::channel(16);
        Arc::new(Self {
            config: Arc::new(RwLock::new(Loaded::new(config))),
            notify_tx,
            shutdown: CancellationToken::new(),
            watcher_handle: Mutex::new(None),
        })
    }

    /// Initialize the Manager with no watcher from a ready made snapshot.
    pub fn not_watched_loaded(config: Loaded<C>) -> Arc<Self> {
        let (notify_tx, _) = tokio::sync::broadcast::channel(16);
        Arc::new(Self {
            config: Arc::new(RwLock::new(config)),
            notify_tx,
            shutdown: CancellationToken::new(),
            watcher_handle: Mutex::new(None),
        })
    }

    /// Gracefully stop the background watcher.
    ///
    /// Cancels the watch loop and awaits its completion. When the
    /// configuration is Vault-backed, the loop revokes the Vault token as
    /// part of its teardown before this returns. Safe to call on an
    /// unwatched manager (no-op) and idempotent across repeated calls.
    pub async fn shutdown(&self) {
        self.shutdown.cancel();
        if let Some(handle) = self.watcher_handle.lock().await.take() {
            let _ = handle.await;
        }
    }

    /// Watch loop for constant watching for the configuration changes and
    /// corresponding notifications.
    #[allow(clippy::expect_used)]
    async fn watch_loop(
        manager: Arc<Self>,
        config_path: PathBuf,
        mut vault_runtime: Option<vault::VaultRuntime>,
        shutdown: CancellationToken,
    ) {
        let (sync_tx, mut sync_rx) = tokio::sync::mpsc::channel(1);

        let mut watcher: RecommendedWatcher =
            notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                if let Ok(event) = res {
                    // Data modifications, name changes (renames/symlink swaps),
                    // creations, and removals. Removal matters for the
                    // per-domain config directory (ADR 0034
                    // §9): deleting a `keystone.<name>.
                    // conf` must re-scan so the domain's binding
                    // drops. A spurious removal event on another watched file
                    // costs one reload that lands on last-known-good.
                    if event.kind.is_modify() || event.kind.is_create() || event.kind.is_remove() {
                        // `try_send`, not `blocking_send`: this callback runs
                        // on notify's single background
                        // event-loop thread, which also
                        // services `watch()`/`unwatch()` control requests.
                        // Blocking here until `sync_rx` is drained can deadlock
                        // that thread against a concurrent `watcher.watch()`
                        // call (e.g. while registering the initial watch set)
                        // that can only be serviced once this send completes.
                        // A dropped event is harmless: the consumer already
                        // coalesces any backlog via the `try_recv` drain below.
                        let _ = sync_tx.try_send(event);
                    }
                }
            })
            .expect("Failed to create watcher");
        // A global set of watches to prevent deadlock while re-registering the
        // same file.
        let mut watched_paths = {
            let current = manager.config.read().await;
            let mut paths = current.core.watch_files();
            paths.extend(current.section_watch_files());
            paths
        };

        // Watch the main config
        watched_paths.insert(config_path.clone());
        if let Some(parent) = config_path.parent() {
            // For K8 it is practical to add a directory watch since the CM is
            // replaced as a whole without touching the individual
            // file.
            watched_paths.insert(parent.to_path_buf());
        }

        // Register file watches
        for watch in watched_paths.iter() {
            let _ = watcher.watch(watch.as_path(), RecursiveMode::NonRecursive);
        }

        loop {
            // Only arm the Vault maintenance timer when a Vault runtime is
            // active; otherwise this branch never fires (rather than parking on
            // a far-future sentinel deadline).
            let vault_deadline = vault_runtime
                .as_ref()
                .map(vault::VaultRuntime::next_deadline);
            let vault_tick = async {
                match vault_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                () = shutdown.cancelled() => {
                    break;
                }
                event = sync_rx.recv() => {
                    if event.is_none() {
                        break;
                    }
                    while sync_rx.try_recv().is_ok() {}
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    match load_all_with_vault_state::<C>(&config_path).await {
                        Ok(loaded) => {
                            Self::apply_loaded(
                                &manager,
                                loaded,
                                &mut vault_runtime,
                                &mut watcher,
                                &mut watched_paths,
                            ).await;
                        }
                        Err(_) => {
                            error!("configuration reload failed; retaining last-known-good configuration");
                        }
                    }
                }
                () = vault_tick => {
                    let Some(runtime) = &mut vault_runtime else {
                        continue;
                    };
                    if runtime.renew_if_due().await.is_err() {
                        error!("Vault token renewal failed; retrying while retaining current configuration");
                    }
                    match runtime.has_new_version().await {
                        Ok(true) => match load_all_with_vault_state::<C>(&config_path).await {
                            Ok(loaded) => {
                                Self::apply_loaded(
                                    &manager,
                                    loaded,
                                    &mut vault_runtime,
                                    &mut watcher,
                                    &mut watched_paths,
                                ).await;
                            }
                            Err(_) => {
                                error!("Vault configuration refresh failed; retaining last-known-good configuration");
                            }
                        },
                        Ok(false) => {}
                        Err(_) => {
                            error!("Vault metadata poll failed; retaining last-known-good configuration");
                        }
                    }
                }
            }
        }

        // The loop exited (graceful shutdown or the watcher channel closing).
        // For a Vault-backed configuration, revoke the token so it is
        // invalidated immediately instead of lingering valid until its TTL
        // expires.
        if let Some(runtime) = &vault_runtime
            && runtime.revoke().await.is_err()
        {
            error!("Vault token revocation on shutdown failed");
        }
    }

    /// Initializes the config, starts the background watcher,
    /// and returns the manager for the live state.
    pub async fn watched(config_path: impl Into<PathBuf>) -> Result<Arc<Self>, Report> {
        let config_path = config_path.into();
        let (notify_tx, _) = tokio::sync::broadcast::channel(16);

        // Initial Load
        let initial = load_all_with_vault_state::<C>(&config_path).await?;

        let shutdown = CancellationToken::new();
        let manager = Arc::new(Self {
            config: Arc::new(RwLock::new(initial.config)),
            notify_tx,
            shutdown: shutdown.clone(),
            watcher_handle: Mutex::new(None),
        });

        // Spawn Background Watcher
        let manager_clone = Arc::clone(&manager);
        let handle = tokio::spawn(async move {
            Self::watch_loop(manager_clone, config_path, initial.vault, shutdown).await;
        });
        *manager.watcher_handle.lock().await = Some(handle);

        Ok(manager)
    }
}
