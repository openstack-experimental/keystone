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
//! # Keystone configuration
//!
//! Parse of the Keystone configuration file with the following features:
//!
//! - File is parsed as the INI file keeping full compatibility with the legacy
//!   OpenStack config format
//! - Additional file is loaded overloading the initial config with the file
//!   name coming from the `KEYSTONE_SITE_VARS_FILE` environment variable. When
//!   it is not set no additional file is loaded.
//! - Environment variables take final precedence. They use the traditional
//!   OpenStack style and look like `OS_API_POLICY__OPA_BASE_URL` for setting
//!   `[api_policy].opa_base_url` variable.
//!
//! # Example
//!
//! ```no_run
//! use openstack_keystone_config::Config;
//!
//! # #[tokio::main]
//! # async fn main() {
//! let cfg = Config::new("/etc/keystone/keystone.conf".into())
//!     .await
//!     .unwrap();
//! # }
//! ```
//!
//! ```no_run
//! use openstack_keystone_config::ConfigManager;
//!
//! #[tokio::main]
//! async fn main() {
//!     let cfg_mgr = ConfigManager::watched("/etc/keystone/keystone.conf")
//!         .await
//!         .unwrap();
//!     let cfg = cfg_mgr.config.read().await;
//! }
//! ```
use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use config::{File, FileFormat};
use eyre::{Report, WrapErr};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::error;
use validator::Validate;

mod api_key;
mod application_credentials;
mod assignment;
mod audit;
mod auth;
mod auth_plugin_identity;
mod auth_plugins;
mod catalog;
mod common;
mod credential;
mod database;
mod default;
mod distributed_storage;
mod ec2;
mod federation;
mod fernet_token;
mod identity;
mod idmapping;
mod interface;
mod jws_token;
mod k8s_auth;
mod ldap;
mod listener;
mod local_emergency;
mod mapping;
mod oauth2;
mod oslo_middleware;
mod pagination;
mod policy;
mod rate_limit;
mod resource;
mod revoke;
mod role;
mod scim_realm;
mod scim_resource;
mod security_compliance;
mod token;
mod token_restriction;
mod trust;
mod vault;
mod webauthn;

pub use api_key::*;
pub use application_credentials::*;
pub use assignment::*;
pub use audit::*;
pub use auth::*;
pub use auth_plugin_identity::*;
pub use auth_plugins::*;
pub use catalog::*;
pub use common::*;
pub use credential::*;
pub use database::*;
pub use default::*;
pub use distributed_storage::*;
pub use ec2::*;
pub use federation::*;
pub use fernet_token::*;
pub use identity::*;
pub use idmapping::*;
pub use interface::*;
pub use jws_token::*;
pub use k8s_auth::*;
pub use ldap::*;
pub use listener::*;
pub use local_emergency::*;
pub use mapping::*;
pub use oauth2::*;
pub use oslo_middleware::*;
pub use pagination::*;
pub use policy::*;
pub use rate_limit::*;
pub use resource::*;
pub use revoke::*;
pub use role::*;
pub use scim_realm::*;
pub use scim_resource::*;
pub use security_compliance::*;
pub use token::*;
pub use token_restriction::*;
pub use trust::*;
pub use vault::VaultSection;
pub use webauthn::*;

/// Keystone configuration.
#[derive(Debug, Default, Deserialize, Clone, Validate)]
pub struct Config {
    /// API Key (SCIM ingress) provider configuration.
    #[serde(default)]
    #[validate(nested)]
    pub api_key: ApiKeyProvider,

    /// Application credentials provider configuration.
    #[serde(default)]
    pub application_credential: ApplicationCredentialProvider,

    /// Audit framework configuration.
    #[serde(default)]
    pub audit: AuditConfig,

    /// Auth plugin identity-binding index provider configuration.
    #[serde(default)]
    pub auth_plugin_identity: AuthPluginIdentityProvider,

    /// API policy enforcement.
    #[serde(default)]
    pub api_policy: PolicyProvider,

    /// Assignments (roles) provider configuration.
    #[serde(default)]
    pub assignment: AssignmentProvider,

    /// Authentication configuration.
    pub auth: AuthProvider,

    /// Catalog provider configuration.
    #[serde(default)]
    pub catalog: CatalogProvider,

    /// Credential provider configuration.
    #[serde(default)]
    pub credential: CredentialProvider,

    /// Database configuration.
    //#[serde(default)]
    pub database: DatabaseSection,

    /// Global configuration options.
    #[serde(rename = "DEFAULT", default)]
    pub default: DefaultSection,

    /// Distributed storage configuration.
    #[serde(default)]
    #[validate(nested)]
    pub distributed_storage: Option<DistributedStorageConfiguration>,

    /// Dynamic (WebAssembly) auth plugins configuration - ADR 0025.
    #[serde(default)]
    pub auth_plugins: DynamicPluginsSection,

    /// Per-plugin `[auth_plugin.<name>]` sections - ADR 0025.
    #[serde(default)]
    pub auth_plugin: HashMap<String, DynamicPluginConfig>,

    /// `POST /v3/ec2tokens` configuration.
    #[serde(default)]
    pub ec2: Ec2Provider,

    /// Federation provider configuration.
    #[serde(default)]
    pub federation: FederationProvider,

    /// Fernet tokens provider configuration.
    #[serde(default)]
    pub fernet_tokens: FernetTokenProvider,

    /// JWS tokens provider configuration (ADR 0026 §10, Phase 0).
    #[serde(default)]
    pub jws_tokens: JwsTokenProvider,

    /// Identity provider configuration.
    #[serde(default)]
    pub identity: IdentityProvider,

    /// IdMapping provider configuration.
    #[serde(default)]
    pub idmapping: IdMappingProvider,

    /// K8s Auth provider configuration.
    #[serde(default)]
    pub k8s_auth: K8sAuthProvider,

    /// LDAP identity backend configuration (ADR-0027).
    #[serde(default)]
    pub ldap: LdapProvider,

    /// Node-local, quorum-bypass emergency write path configuration
    /// (ADR 0028).
    #[serde(default)]
    pub local_emergency: LocalEmergencyProvider,

    /// Mapping provider configuration.
    #[serde(default)]
    pub mapping: MappingProvider,

    /// OAuth2/OIDC provider configuration (ADR 0026).
    #[serde(default)]
    #[validate(nested)]
    pub oauth2: Oauth2Provider,

    /// `[oslo_middleware]` configuration (proxy header parsing).
    #[serde(default)]
    pub oslo_middleware: OsloMiddleware,

    /// Server listener configuration for the internal interface.
    #[serde(rename = "interface_internal", default)]
    pub interface_internal: Option<InternalInterface>,

    /// Server listener configuration for the public interface.
    #[serde(rename = "interface_public", default)]
    pub interface_public: PublicInterface,

    /// Server listener configuration for the admin interface.
    #[serde(rename = "interface_admin", default)]
    pub interface_admin: Option<AdminInterface>,

    /// Global per-IP rate limiting (ADR-0022, §1).
    ///
    /// Maps to the `[rate_limit_global_ip]` INI section. When `enabled =
    /// false` (the default) the governor is not instantiated and all requests
    /// bypass the check. Set `enabled = true` together with valid
    /// `burst_size` and `replenish_rate_per_second` to activate.
    #[serde(rename = "rate_limit_global_ip", default)]
    pub rate_limit_global_ip: RateLimitSection,

    /// Reverse proxies trusted by the global per-IP rate limiter.
    #[serde(rename = "rate_limit_trusted_proxies", default)]
    pub rate_limit_trusted_proxies: RateLimitTrustedProxiesSection,

    /// Server listener configuration for the health/metrics interface.
    #[serde(rename = "interface_metrics", default)]
    pub interface_metrics: MetricsInterface,

    /// Per-user authentication rate limiting (ADR-0022, §1).
    ///
    /// Maps to the `[rate_limit_user_auth]` INI section. When `enabled =
    /// false` (the default) the governor is not instantiated and
    /// authentication requests bypass the check. The limiter is keyed on the
    /// canonical user ID and is only consulted after the user is confirmed
    /// to exist (ADR-0022, Invariant 8).
    #[serde(rename = "rate_limit_user_auth", default)]
    pub rate_limit_user_auth: RateLimitSection,

    /// Resource provider configuration.
    #[serde(default)]
    pub resource: ResourceProvider,

    /// Revoke provider configuration.
    #[serde(default)]
    pub revoke: RevokeProvider,

    /// Role provider configuration.
    #[serde(default)]
    pub role: RoleProvider,

    /// SCIM realm provider configuration (ADR 0024).
    #[serde(default)]
    pub scim_realm: ScimRealmProvider,

    /// SCIM resource ownership index provider configuration (ADR 0024 §3.A).
    #[serde(default)]
    pub scim_resource: ScimResourceProvider,

    /// Security compliance configuration.
    #[serde(default)]
    #[validate(nested)]
    pub security_compliance: SecurityComplianceProvider,

    /// Token provider configuration.
    #[serde(default)]
    pub token: TokenProvider,

    /// Token restriction provider configuration.
    #[serde(default)]
    pub token_restriction: TokenRestrictionProvider,

    /// Trust provider configuration.
    #[serde(default)]
    pub trust: TrustProvider,

    /// Direct Vault bootstrap configuration.
    #[serde(default)]
    pub vault: Option<VaultSection>,

    /// Webauthn configuration.
    #[serde(default)]
    pub webauthn: WebauthnSection,
}

impl Config {
    fn build_raw(path: PathBuf) -> Result<config::Config, Report> {
        let mut builder = config::Config::builder();

        if std::path::Path::new(&path).is_file() {
            builder = builder.add_source(File::from(path).format(FileFormat::Ini));
        }

        if let Ok(site_vars_file) = env::var("KEYSTONE_SITE_VARS_FILE") {
            builder = builder.add_source(File::with_name(&site_vars_file));
        }

        builder
            .add_source(
                config::Environment::with_prefix("OS")
                    .prefix_separator("_")
                    .separator("__"),
            )
            .build()
            .wrap_err("Failed to read configuration file")
    }

    fn from_raw(raw: config::Config) -> Result<Self, Report> {
        raw.try_deserialize()
            .wrap_err("Failed to parse configuration file")
    }

    /// Load and parse the config file, resolving any Vault references.
    ///
    /// # Parameters
    /// - `path`: Path to the config file
    ///
    /// # Returns
    /// - `Ok(Self)` if the config was parsed successfully
    pub async fn new(path: PathBuf) -> Result<Self, Report> {
        let mut raw = Self::build_raw(path)?;
        Self::resolve_vault_references(&mut raw).await?;
        Self::from_raw(raw)
    }

    /// Load the config file, resolve Vault references and all certificates
    /// referred, and validate the complete configuration.
    ///
    /// # Parameters
    /// - `path`: Path to the config file
    ///
    /// # Returns
    /// - `Ok(Self)` if the config was parsed successfully
    pub async fn load_all(path: PathBuf) -> Result<Self, Report> {
        Ok(Self::load_all_with_vault_state(&path).await?.config)
    }

    /// Resolve any Vault references in `raw` in place.
    ///
    /// Returns `Ok(None)` when the configuration contains no Vault references
    /// (so a plain configuration pays no Vault cost), or `Ok(Some(runtime))`
    /// with the live [`vault::VaultRuntime`] used to keep the resolved secrets
    /// current.
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

    async fn load_all_with_vault_state(path: &Path) -> Result<LoadedConfig, Report> {
        let mut raw = Self::build_raw(path.to_path_buf())?;
        let vault = Self::resolve_vault_references(&mut raw).await?;
        let parsed = Self::from_raw(raw).and_then(Self::finish_load);
        let config = match vault {
            // A configuration that resolved Vault references but then failed to
            // build is surfaced distinctly from a plain configuration error.
            Some(_) => parsed.map_err(|_| vault::VaultConfigError::ResolvedConfigurationInvalid)?,
            None => parsed?,
        };
        Ok(LoadedConfig { config, vault })
    }

    fn finish_load(mut cfg: Self) -> Result<Self, Report> {
        if let Some(ref mut ds) = cfg.distributed_storage {
            if let RaftTlsConfiguration::Tls(ref mut tls) = ds.tls_configuration {
                tls.read_certs()
                    .wrap_err("reading distributed storage TLS configuration")?;
            }
            if let Some(ref mut pkcs11) = ds.pkcs11 {
                pkcs11
                    .load_secrets()
                    .wrap_err("reading distributed storage PKCS#11 configuration")?;
            }
            if let Some(ref mut tpm) = ds.tpm {
                tpm.load_secrets()
                    .wrap_err("reading distributed storage TPM configuration")?;
            }
        }
        // Compile password regex at load time.
        cfg.security_compliance
            .compile_regex()
            .wrap_err("compiling password_regex")?;
        // Validate the config after loading all the referred files.
        cfg.validate().wrap_err("Configuration validation failed")?;
        // Cross-field validation for [auth_plugins]/[auth_plugin.*]
        // (ADR 0025 §4/§5 fail-loud invariants) - not expressible via
        // `#[validate(...)]` derive since it needs both sections at once.
        cfg.auth_plugins
            .validate_semantics(&cfg.auth_plugin)
            .wrap_err("validating [auth_plugins] configuration")?;
        Ok(cfg)
    }

    /// Get the list of all files that should be watched.
    fn get_watch_files(&self) -> HashSet<PathBuf> {
        let mut watched_paths = HashSet::new();
        if let Some(ds) = &self.distributed_storage
            && let RaftTlsConfiguration::Tls(tls) = &ds.tls_configuration
        {
            if let Some(crt) = &tls.tls_cert_file {
                watched_paths.insert(crt.clone());
            }
            if let Some(key) = &tls.tls_key_file {
                watched_paths.insert(key.clone());
            }
            if let Some(ca) = &tls.tls_client_ca_file {
                watched_paths.insert(ca.clone());
            }
        }
        watched_paths
    }

    /// Resolve the effective page limit for a list request, following
    /// python-keystone's `Hints.get_limit_with_default` precedence:
    /// client-supplied `limit` → provider's `list_limit` → global
    /// `[DEFAULT] list_limit` → provider's `max_list_limit` → global
    /// `[DEFAULT] max_db_limit`. The client-supplied `limit` (if present) is
    /// always clamped to whichever max applies.
    pub fn resolve_list_limit(
        &self,
        provider_limit: &ListLimitConfig,
        requested: Option<u64>,
    ) -> Option<u64> {
        let max = provider_limit.max_list_limit.or(self.default.max_db_limit);
        let effective = requested
            .or(provider_limit.list_limit)
            .or(self.default.list_limit);
        match (effective, max) {
            (Some(effective), Some(max)) => Some(effective.min(max)),
            (Some(effective), None) => Some(effective),
            (None, max) => max,
        }
    }
}

impl TryFrom<config::ConfigBuilder<config::builder::DefaultState>> for Config {
    type Error = Report;

    /// Build a [`Config`] directly from a prepared [`config::ConfigBuilder`].
    ///
    /// This is the synchronous construction path used by downstream crates
    /// (and their tests) that assemble configuration in memory rather than
    /// loading it from a file. It does not resolve Vault references, load
    /// referred certificates, or run validation; use [`Config::load_all`] for
    /// the full loading pipeline.
    fn try_from(
        builder: config::ConfigBuilder<config::builder::DefaultState>,
    ) -> Result<Self, Self::Error> {
        let raw = builder
            .build()
            .wrap_err("Failed to read configuration file")?;
        Self::from_raw(raw)
    }
}

struct LoadedConfig {
    config: Config,
    vault: Option<vault::VaultRuntime>,
}

/// Config Manager supporting config file watch and reload.
pub struct ConfigManager {
    /// The current config.
    pub config: Arc<RwLock<Config>>,
    /// Notify listeners that something changed.
    pub notify_tx: tokio::sync::broadcast::Sender<()>,
}

impl ConfigManager {
    /// Initialize the Manager with no watcher.
    pub fn not_watched(config: Config) -> Arc<Self> {
        let (notify_tx, _) = tokio::sync::broadcast::channel(16);
        Arc::new(Self {
            config: Arc::new(RwLock::new(config)),
            notify_tx,
        })
    }

    /// Initializes the config, starts the background watcher,
    /// and returns the manager for the live state.
    pub async fn watched(config_path: impl Into<PathBuf>) -> Result<Arc<Self>, Report> {
        let config_path = config_path.into();
        let (notify_tx, _) = tokio::sync::broadcast::channel(16);

        // Initial Load
        let initial = Config::load_all_with_vault_state(&config_path).await?;

        let manager = Arc::new(Self {
            config: Arc::new(RwLock::new(initial.config)),
            notify_tx,
        });

        // Spawn Background Watcher
        let manager_clone = Arc::clone(&manager);
        tokio::spawn(async move {
            Self::watch_loop(manager_clone, config_path, initial.vault).await;
        });

        Ok(manager)
    }

    /// Watch loop for constant watching for the configuration changes and
    /// corresponding notifications.
    #[allow(clippy::expect_used)]
    async fn watch_loop(
        manager: Arc<Self>,
        config_path: PathBuf,
        mut vault_runtime: Option<vault::VaultRuntime>,
    ) {
        let (sync_tx, mut sync_rx) = tokio::sync::mpsc::channel(1);

        let mut watcher: RecommendedWatcher =
            notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                if let Ok(event) = res {
                    // Only trigger for data modifications or name changes (renames/symlink swaps)
                    if event.kind.is_modify() || event.kind.is_create() {
                        let _ = sync_tx.blocking_send(event);
                    }
                }
            })
            .expect("Failed to create watcher");
        // A global set of watches to prevent deadlock while re-registering the same
        // file.
        let mut watched_paths = manager.config.read().await.get_watch_files();

        // Watch the main config
        watched_paths.insert(config_path.clone());
        if let Some(parent) = config_path.parent() {
            // For K8 it is practical to add a directory watch since the CM is replaced as a
            // whole without touching the individual file.
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
                event = sync_rx.recv() => {
                    if event.is_none() {
                        break;
                    }
                    while sync_rx.try_recv().is_ok() {}
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    match Config::load_all_with_vault_state(&config_path).await {
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
                        Ok(true) => match Config::load_all_with_vault_state(&config_path).await {
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
    }

    async fn apply_loaded(
        manager: &Arc<Self>,
        loaded: LoadedConfig,
        vault_runtime: &mut Option<vault::VaultRuntime>,
        watcher: &mut RecommendedWatcher,
        watched_paths: &mut HashSet<PathBuf>,
    ) {
        for watch_candidate in loaded.config.get_watch_files() {
            if !watched_paths.contains(&watch_candidate) {
                let _ = watcher.watch(watch_candidate.as_path(), RecursiveMode::NonRecursive);
                watched_paths.insert(watch_candidate);
            }
        }

        *manager.config.write().await = loaded.config;
        *vault_runtime = loaded.vault;
        let _ = manager.notify_tx.send(());
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;

    use httpmock::MockServer;
    use secrecy::ExposeSecret;
    use serde_json::json;
    use serial_test::{parallel, serial};
    use tempfile::{NamedTempFile, tempdir};
    use tokio::time::{Duration, sleep, timeout};

    use super::*;
    use crate::vault::tests::{mock_lookup, mock_metadata, mock_renew, mock_secret};

    // `Config::new` is async, but these tests drive it from the synchronous
    // `temp_env::with_var` closure API, so run it to completion on a local
    // current-thread runtime.
    fn block_on_config_new(path: PathBuf) -> Result<Config, Report> {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(Config::new(path))
    }

    // `build_raw` reads process-global environment (`OS_*` overrides and
    // `KEYSTONE_SITE_VARS_FILE`). Tests that mutate that environment are marked
    // `#[serial]` and every test that loads a config through `build_raw` is
    // marked `#[parallel]`, so a mutated variable (e.g. a `KEYSTONE_SITE_VARS_FILE`
    // pointing at a temp file that is about to be dropped) can never leak into a
    // concurrently loading test.
    #[test]
    #[serial]
    fn test_env() {
        temp_env::with_var("OS_API_POLICY__OPA_BASE_URL", Some("http://test/"), || {
            let mut cfg_file = NamedTempFile::new().unwrap();
            write!(
                cfg_file,
                r#"
    [auth]
    methods = []
    [database]
    connection = "foo"
                "#
            )
            .unwrap();

            let cfg = block_on_config_new(cfg_file.path().to_path_buf()).unwrap();
            assert_eq!("http://test/", cfg.api_policy.opa_base_url.to_string());
        });
    }

    #[test]
    #[serial]
    fn test_site_vars() {
        let mut site_vars_file = NamedTempFile::with_suffix(".toml").unwrap();
        write!(
            site_vars_file,
            r#"
    [distributed_storage]
    node_id = 1
    node_cluster_addr = "http://foo:8300"
    path = "/tmp"
    type = "tls"
    tls_key_file = "/foo"
    tls_cert_file = "/bar"
    tls_client_ca_file = "/baz"
            "#
        )
        .unwrap();
        temp_env::with_var(
            "KEYSTONE_SITE_VARS_FILE",
            Some(site_vars_file.path()),
            || {
                let mut cfg_file = NamedTempFile::new().unwrap();
                write!(
                    cfg_file,
                    r#"
    [auth]
    methods = []
    [database]
    connection = "foo"
                "#
                )
                .unwrap();

                let cfg = block_on_config_new(cfg_file.path().to_path_buf()).unwrap();
                let ds = cfg.distributed_storage.unwrap();
                assert_eq!(1, ds.node_id);
                assert_eq!("http://foo:8300/", ds.node_cluster_addr.to_string());
            },
        );
    }

    #[test]
    fn test_listener_internal() {
        let c = config::Config::builder()
            .add_source(File::from_str(
                r#"
            [auth]
            methods = []
            [database]
            connection = "foo"
            [interface_internal]
            tcp_addr = "1.2.3.4:5678"
            type = "spiffe"
            trust_domains = "example.org"
            "#,
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let cfg: Config = c.try_deserialize().unwrap();
        if let Some(internal_if) = &cfg.interface_internal {
            if let ListenerConfig::Spiffe(spiffe) = &internal_if.listener {
                assert!(spiffe.trust_domains.contains(&String::from("example.org")));
            } else {
                panic!("should be regular tls");
            }
        } else {
            panic!("internal interface should be there");
        }
    }

    // Helper to setup a dummy config and cert file
    fn setup_files(dir: &std::path::Path) -> std::path::PathBuf {
        let config_path = dir.join("keystone.conf");

        let mut f = fs::File::create(&config_path).unwrap();
        f.write_all(
            r#"
    [auth]
    methods = []
    [database]
    connection = "foo"
                "#
            .as_bytes(),
        )
        .unwrap();
        f.sync_all().unwrap();
        //if let

        config_path
    }

    fn write_vault_config(
        file: &mut NamedTempFile,
        server: &MockServer,
        refresh_interval_seconds: u64,
    ) {
        write!(
            file,
            r#"
    [vault]
    address = {}
    token = test-token
    refresh_interval_seconds = {}

    [auth]
    methods = []

    [database]
    connection = "vault://secret/keystone/database#password"
            "#,
            server.base_url(),
            refresh_interval_seconds
        )
        .unwrap();
        file.flush().unwrap();
    }

    #[tokio::test]
    #[parallel]
    async fn test_async_loader_resolves_vault_reference() {
        let server = MockServer::start();
        let lookup = mock_lookup(&server, false, 60);
        let metadata = mock_metadata(&server, 4);
        let secret = mock_secret(
            &server,
            4,
            json!({
                "password": "environment-value"
            }),
        );
        let mut config_file = NamedTempFile::with_suffix(".conf").unwrap();
        write!(
            config_file,
            r#"
    [vault]
    address = {}
    token = test-token

    [auth]
    methods = []

    [database]
    connection = "vault://secret/keystone/database#password"
            "#,
            server.base_url()
        )
        .unwrap();

        let config = Config::load_all(config_file.path().to_path_buf())
            .await
            .unwrap();

        assert_eq!(
            config.database.connection.expose_secret(),
            "environment-value"
        );
        let vault = config.vault.unwrap();
        assert_eq!(vault.token.expose_secret(), "test-token");
        assert_eq!(vault.refresh_interval_seconds, 60);
        lookup.assert_calls(1);
        metadata.assert_calls(1);
        secret.assert_calls(1);
    }

    #[tokio::test]
    #[parallel]
    async fn test_resolved_configuration_error_is_redacted() {
        let server = MockServer::start();
        let _lookup = mock_lookup(&server, false, 60);
        let _metadata = mock_metadata(&server, 1);
        let _secret = mock_secret(&server, 1, json!({"password": "SUPERSECRET"}));
        let mut config_file = NamedTempFile::with_suffix(".conf").unwrap();
        write!(
            config_file,
            r#"
    [vault]
    address = {}
    token = test-token

    [DEFAULT]
    debug = "vault://secret/keystone/database#password"

    [auth]
    methods = []

    [database]
    connection = ordinary
            "#,
            server.base_url()
        )
        .unwrap();

        let error = Config::load_all(config_file.path().to_path_buf())
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "configuration is invalid after resolving Vault references"
        );
        assert!(!error.contains("SUPERSECRET"));
        assert!(!error.contains("test-token"));
    }

    #[tokio::test]
    #[parallel]
    async fn test_async_loader_fails_closed_without_vault_configuration() {
        let mut config_file = NamedTempFile::with_suffix(".conf").unwrap();
        write!(
            config_file,
            r#"
    [auth]
    methods = []
    [database]
    connection = "vault://secret/keystone/database#password"
            "#
        )
        .unwrap();

        let error = Config::load_all(config_file.path().to_path_buf())
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "Vault references require a [vault] configuration section"
        );
    }

    #[tokio::test]
    #[parallel]
    async fn test_vault_version_reload_and_last_known_good_retention() {
        let server = MockServer::start();
        let _lookup = mock_lookup(&server, false, 60);
        let mut metadata = mock_metadata(&server, 1);
        let mut secret = mock_secret(&server, 1, json!({"password": "version-one"}));
        let mut config_file = NamedTempFile::with_suffix(".conf").unwrap();
        write_vault_config(&mut config_file, &server, 1);

        let manager = ConfigManager::watched(config_file.path()).await.unwrap();
        let mut reloads = manager.notify_tx.subscribe();
        metadata.delete();
        secret.delete();
        let mut metadata = mock_metadata(&server, 2);
        let mut secret = mock_secret(&server, 2, json!({"password": "version-two"}));

        timeout(Duration::from_secs(4), reloads.recv())
            .await
            .expect("Vault version change should trigger a reload")
            .unwrap();
        assert_eq!(
            manager
                .config
                .read()
                .await
                .database
                .connection
                .expose_secret(),
            "version-two"
        );

        metadata.delete();
        secret.delete();
        let _metadata = mock_metadata(&server, 3);
        let invalid_secret = mock_secret(&server, 3, json!({"password": 12345}));
        timeout(Duration::from_secs(4), async {
            while invalid_secret.calls() == 0 {
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("invalid Vault version should be attempted");
        sleep(Duration::from_millis(100)).await;

        assert!(reloads.try_recv().is_err());
        assert_eq!(
            manager
                .config
                .read()
                .await
                .database
                .connection
                .expose_secret(),
            "version-two"
        );
    }

    #[tokio::test]
    #[parallel]
    async fn test_renewable_vault_token_is_renewed_halfway_through_ttl() {
        let server = MockServer::start();
        let _lookup = mock_lookup(&server, true, 2);
        let _metadata = mock_metadata(&server, 1);
        let _secret = mock_secret(&server, 1, json!({"password": "value"}));
        let renewal = mock_renew(&server, 2);
        let mut config_file = NamedTempFile::with_suffix(".conf").unwrap();
        write_vault_config(&mut config_file, &server, 60);

        let _manager = ConfigManager::watched(config_file.path()).await.unwrap();
        timeout(Duration::from_secs(4), async {
            while renewal.calls() == 0 {
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("renewable token should be renewed");
        assert!(renewal.calls() >= 1);
    }

    #[tokio::test]
    #[parallel]
    async fn test_initial_load() {
        let dir = tempdir().unwrap();
        let config_path = setup_files(dir.path());

        // A tiny delay for a higher probability that FS operations are really complete.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let manager = ConfigManager::watched(config_path)
            .await
            .expect("Should initialize");

        let initial = manager.config.read().await;
        assert_eq!(initial.database.connection.expose_secret(), "foo");
        let _ = dir;
    }

    #[tokio::test]
    #[parallel]
    async fn test_reload_on_config_change() {
        let dir = tempdir().unwrap();
        let config_path = setup_files(dir.path());
        // A tiny delay for a higher probability that FS operations are really complete.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let manager = ConfigManager::watched(config_path.clone())
            .await
            .expect("Should initialize");

        // Another delay to correlate update the config after the watch thread is
        // started
        tokio::time::sleep(Duration::from_millis(10)).await;
        // Update the config file
        fs::write(
            &config_path,
            r#"
    [auth]
    methods = []
    [database]
    connection = "bar"
    "#,
        )
        .unwrap();

        // Wait for notify + debounce (which was 100ms in our code)
        // We check a few times for the change to propagate
        let mut success = false;
        for _ in 0..10 {
            sleep(Duration::from_millis(200)).await;
            let updated = manager.config.read().await;
            if updated.database.connection.expose_secret() == "bar" {
                success = true;
                break;
            }
        }
        assert!(success, "Config did not update after file change");
    }

    #[tokio::test]
    #[parallel]
    async fn test_reload_on_cert_change() {
        let config_file = NamedTempFile::with_suffix(".conf").unwrap();
        let mut ca_file = NamedTempFile::new().unwrap();
        write!(ca_file, "ca").unwrap();
        let mut cert_file = NamedTempFile::new().unwrap();
        write!(cert_file, "cert").unwrap();
        let mut key_file = NamedTempFile::new().unwrap();
        write!(key_file, "key").unwrap();
        let mut f = fs::File::create(config_file.path()).unwrap();
        f.write_all(
            format!(
                r#"
    [auth]
    methods = []
    [database]
    connection = "foo"
    [distributed_storage]
    node_cluster_addr = https://localhost:8310
    node_id = 1
    path = /keystone/storage
    dev_mode = true
    tls_key_file = {:?}
    tls_cert_file = {:?}
    tls_client_ca_file = {:?}
                "#,
                key_file.path(),
                cert_file.path(),
                ca_file.path()
            )
            .as_bytes(),
        )
        .unwrap();
        f.sync_all().unwrap();
        // A tiny delay for a higher probability that FS operations are really complete.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let mgr = ConfigManager::watched(config_file.path())
            .await
            .expect("Should initialize");

        // Another delay to correlate update the config after the watch thread is
        // started
        tokio::time::sleep(Duration::from_millis(10)).await;

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(cert_file.path())
            .unwrap();
        f.write_all("another cert".as_bytes()).unwrap();

        // Wait for notify + debounce (which was 100ms in our code)
        // We check a few times for the change to propagate
        let mut success = false;
        for _ in 0..10 {
            sleep(Duration::from_millis(200)).await;
            let updated = mgr.config.read().await;
            if let Some(ds) = &updated.distributed_storage
                && let RaftTlsConfiguration::Tls(data) = &ds.tls_configuration
                && data.tls_cert_content.as_ref().map(|x| x.expose_secret())
                    == Some("another cert".as_bytes())
            {
                success = true;
                break;
            }
        }
        assert!(success, "Config did not update after file change");
    }
    #[tokio::test]
    #[parallel]
    async fn test_invalid_security_compliance_validation() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let config_file = NamedTempFile::with_suffix(".conf").unwrap();
        let mut f = std::fs::File::create(config_file.path()).unwrap();
        f.write_all(
            r#"
    [auth]
    methods = []

    [database]
    connection = "foo"

    [distributed_storage]
    node_cluster_addr = "https://localhost:8310"
    node_id = 1
    path = "/keystone/storage"

    [security_compliance]
    password_expires_days = 0
    disable_user_account_days_inactive = 0
    lockout_failure_attempts = 0
    invalid_password_hash_max_chars = 0
            "#
            .as_bytes(),
        )
        .unwrap();
        f.sync_all().unwrap();

        // 1. Attempt to load the configuration
        let result = Config::load_all(config_file.path().to_path_buf()).await;

        // 2. Assert that it completely fails and catches our error
        assert!(
            result.is_err(),
            "Expected configuration to be REJECTED because of 0 values, but it loaded successfully!"
        );

        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("Configuration validation failed"),
            "Expected a validation error, got: {}",
            err_msg
        );

        // 3. FULL COVERAGE: Explicitly ensure the error message blames every single
        //    invalid field
        assert!(
            err_msg.contains("security_compliance.password_expires_days"),
            "Error message should explicitly blame password_expires_days, but got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("security_compliance.disable_user_account_days_inactive"),
            "Error message should explicitly blame disable_user_account_days_inactive, but got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("security_compliance.lockout_failure_attempts"),
            "Error message should explicitly blame lockout_failure_attempts, but got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("security_compliance.invalid_password_hash_max_chars"),
            "Error message should explicitly blame invalid_password_hash_max_chars, but got: {}",
            err_msg
        );
    }

    #[test]
    fn test_api_key_defaults() {
        let cfg = ApiKeyProvider::default();
        assert_eq!(cfg.argon2_memory_kib, 65536);
        assert_eq!(cfg.argon2_time_cost, 3);
        assert_eq!(cfg.argon2_parallelism, 4);
        assert_eq!(cfg.janitor_inactive_days, 90);
        assert_eq!(cfg.janitor_grace_days, 7);
        assert_eq!(cfg.janitor_tombstone_retention_days, 365);
        assert!(cfg.trusted_proxies.is_empty());
    }

    #[tokio::test]
    #[parallel]
    async fn test_api_key_trusted_proxies_and_validation() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let config_file = NamedTempFile::with_suffix(".conf").unwrap();
        let mut f = std::fs::File::create(config_file.path()).unwrap();
        f.write_all(
            r#"
    [auth]
    methods = []

    [database]
    connection = "foo"

    [distributed_storage]
    node_cluster_addr = "https://localhost:8310"
    node_id = 1
    path = "/keystone/storage"
    dev_mode = true

    [api_key]
    trusted_proxies = 10.0.0.0/8,192.168.1.0/24
            "#
            .as_bytes(),
        )
        .unwrap();
        f.sync_all().unwrap();

        let cfg = Config::load_all(config_file.path().to_path_buf())
            .await
            .unwrap();
        assert_eq!(
            cfg.api_key.trusted_proxies,
            vec![
                "10.0.0.0/8".parse::<ipnet::IpNet>().unwrap(),
                "192.168.1.0/24".parse::<ipnet::IpNet>().unwrap()
            ]
        );
    }

    #[tokio::test]
    #[parallel]
    async fn test_invalid_api_key_validation() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let config_file = NamedTempFile::with_suffix(".conf").unwrap();
        let mut f = std::fs::File::create(config_file.path()).unwrap();
        f.write_all(
            r#"
    [auth]
    methods = []

    [database]
    connection = "foo"

    [distributed_storage]
    node_cluster_addr = "https://localhost:8310"
    node_id = 1
    path = "/keystone/storage"
    dev_mode = true

    [api_key]
    argon2_memory_kib = 0
    argon2_time_cost = 0
    argon2_parallelism = 0
    janitor_inactive_days = 0
    janitor_tombstone_retention_days = 0
            "#
            .as_bytes(),
        )
        .unwrap();
        f.sync_all().unwrap();

        let result = Config::load_all(config_file.path().to_path_buf()).await;
        assert!(result.is_err());

        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("api_key.argon2_memory_kib"), "{}", err_msg);
        assert!(err_msg.contains("api_key.argon2_time_cost"), "{}", err_msg);
        assert!(
            err_msg.contains("api_key.argon2_parallelism"),
            "{}",
            err_msg
        );
        assert!(
            err_msg.contains("api_key.janitor_inactive_days"),
            "{}",
            err_msg
        );
        assert!(
            err_msg.contains("api_key.janitor_tombstone_retention_days"),
            "{}",
            err_msg
        );
    }
}
