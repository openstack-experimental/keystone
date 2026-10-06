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
use std::path::PathBuf;

use eyre::{Report, WrapErr};
use oslo_config::ConfigSection;
use serde::Deserialize;
use validator::Validate;

mod api_key;
mod application_credentials;
mod assignment;
mod auth;
mod auth_plugin_identity;
mod auth_plugins;
mod catalog;
mod common;
mod credential;
mod database;
mod default;
mod domain_config;
mod ec2;
mod federation;
mod fernet_token;
mod identity;
mod idmapping;
mod interface;
mod k8s_auth;
mod ldap;
mod limit;
mod listener;
mod local_emergency;
mod mapping;
mod oauth2;
mod oslo_middleware;
mod pagination;
mod policy;
mod policy_store;
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
mod vendordata;
mod webauthn;

pub use api_key::*;
pub use application_credentials::*;
pub use assignment::*;
pub use auth::*;
pub use auth_plugin_identity::*;
pub use auth_plugins::*;
pub use cadf::config::{AuditConfig, AuditSinkConfig, UNKNOWN_NODE_ID};
pub use catalog::*;
pub use common::*;
pub use credential::*;
pub use database::*;
pub use default::*;
pub use domain_config::*;
pub use ec2::*;
pub use federation::*;
pub use fernet_token::*;
pub use identity::*;
pub use idmapping::*;
pub use interface::*;
pub use k8s_auth::*;
pub use ldap::*;
pub use limit::*;
pub use listener::*;
pub use local_emergency::*;
pub use mapping::*;
pub use oauth2::*;
pub use oslo_middleware::*;
pub use pagination::*;
pub use policy::*;
pub use policy_store::*;
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
pub use vendordata::*;
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

    /// Unified limits provider configuration.
    #[serde(default)]
    pub limit: LimitProvider,

    /// Credential provider configuration.
    #[serde(default)]
    pub credential: CredentialProvider,

    /// Database configuration.
    //#[serde(default)]
    pub database: DatabaseSection,

    /// Global configuration options.
    #[serde(rename = "DEFAULT", default)]
    pub default: DefaultSection,

    /// `[domain_config]` section: per-domain configuration resolver sources
    /// (ADR 0034 §2). Unset keys inherit the deprecated `[identity]` switches.
    #[serde(default)]
    pub domain_config: DomainConfigSection,

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

    /// Policy store provider configuration (legacy `/v3/policies`).
    ///
    /// Bound to `[policy]`, matching python keystone. The OPA authorization
    /// configuration is a different section, `[api_policy]` above.
    #[serde(default)]
    pub policy: PolicyStoreProvider,

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

    /// Vendor data JWT provider configuration (SPIRE integration plan,
    /// Phase 2).
    #[serde(default)]
    pub vendordata: VendordataProvider,

    /// Webauthn configuration.
    #[serde(default)]
    pub webauthn: WebauthnSection,
}

impl Config {
    /// Load and parse the config file.
    ///
    /// The engine resolves `vault://` references from the `[vault]` section,
    /// which it reads itself; see [`oslo_config`].
    ///
    /// # Parameters
    /// - `path`: Path to the config file
    ///
    /// # Returns
    /// - `Ok(Self)` if the config was parsed successfully
    pub async fn new(path: PathBuf) -> Result<Self, Report> {
        oslo_config::load::<Self>(path).await
    }

    /// Load the config file, resolve `vault://` references (engine feature,
    /// see [`oslo_config`]) and all certificates referred, and validate the
    /// complete configuration.
    ///
    /// # Parameters
    /// - `path`: Path to the config file
    ///
    /// # Returns
    /// - `Ok(Self)` if the config was parsed successfully
    pub async fn load_all(path: PathBuf) -> Result<Self, Report> {
        oslo_config::load_all::<Self>(path).await
    }

    fn finish_load(mut cfg: Self, ctx: &oslo_config::LoadCtx) -> Result<Self, Report> {
        ConfigSection::finish(&mut cfg.database, ctx)?;
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
        watched_paths.extend(ConfigSection::watch_files(&self.database));
        // Per-domain config files (ADR 0034 §9): watch the directory so an
        // operator's edit to a `keystone.<name>.conf` triggers a reload and the
        // `fs` domain-config driver re-scans. Only when it actually exists —
        // the default path is rarely present and a missing watch target
        // just logs.
        if self.identity.domain_config_dir.is_dir() {
            watched_paths.insert(self.identity.domain_config_dir.clone());
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
    /// loading it from a file. It does not resolve `vault://` references, load
    /// referred certificates, or run validation; use [`Config::load_all`] for
    /// the full loading pipeline.
    fn try_from(
        builder: config::ConfigBuilder<config::builder::DefaultState>,
    ) -> Result<Self, Self::Error> {
        let raw = builder
            .build()
            .wrap_err("Failed to read configuration file")?;
        oslo_config::from_raw::<Self>(raw)
    }
}

/// Read access to the core configuration and the registered sections.
pub type ConfigView<'a> = oslo_config::ConfigView<'a, Config>;

/// One snapshot of the configuration: the core schema and the registered
/// sections.
pub type LoadedConfig = oslo_config::Loaded<Config>;

/// Config Manager supporting config file watch and reload.
pub type ConfigManager = oslo_config::ConfigManager<Config>;

impl oslo_config::CoreSchema for Config {
    fn source() -> oslo_config::SourceSpec {
        oslo_config::SourceSpec {
            env_prefix: "OS",
            env_prefix_separator: "_",
            env_separator: "__",
            site_vars_env: "KEYSTONE_SITE_VARS_FILE",
        }
    }

    fn reserved_sections() -> &'static [&'static str] {
        &[
            "api_key",
            "application_credential",
            "audit",
            "auth_plugin_identity",
            "api_policy",
            "assignment",
            "auth",
            "catalog",
            "limit",
            "credential",
            "database",
            "DEFAULT",
            "domain_config",
            "auth_plugins",
            "auth_plugin",
            "ec2",
            "federation",
            "fernet_tokens",
            "identity",
            "idmapping",
            "k8s_auth",
            "ldap",
            "local_emergency",
            "mapping",
            "oauth2",
            "oslo_middleware",
            "interface_internal",
            "interface_public",
            "interface_admin",
            "rate_limit_global_ip",
            "rate_limit_trusted_proxies",
            "interface_metrics",
            "rate_limit_user_auth",
            "policy",
            "resource",
            "revoke",
            "role",
            "scim_realm",
            "scim_resource",
            "security_compliance",
            "token",
            "token_restriction",
            "trust",
            "vendordata",
            "webauthn",
        ]
    }

    fn finish_load(self, ctx: &oslo_config::LoadCtx) -> Result<Self, Report> {
        Config::finish_load(self, ctx)
    }

    fn watch_files(&self) -> HashSet<PathBuf> {
        self.get_watch_files()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;

    use secrecy::ExposeSecret;
    use serial_test::{parallel, serial};
    use tempfile::{NamedTempFile, tempdir};
    use tokio::time::{Duration, sleep, timeout};

    use super::*;

    /// Deserializer that only records the field names a struct asks for.
    struct FieldProbe(std::cell::RefCell<Vec<&'static str>>);

    impl<'de> serde::Deserializer<'de> for &FieldProbe {
        type Error = serde::de::value::Error;

        fn deserialize_struct<V: serde::de::Visitor<'de>>(
            self,
            _name: &'static str,
            fields: &'static [&'static str],
            _visitor: V,
        ) -> Result<V::Value, Self::Error> {
            self.0.borrow_mut().extend_from_slice(fields);
            Err(serde::de::Error::custom("probe"))
        }

        fn deserialize_any<V: serde::de::Visitor<'de>>(
            self,
            _visitor: V,
        ) -> Result<V::Value, Self::Error> {
            Err(serde::de::Error::custom("probe"))
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map enum identifier ignored_any
        }
    }

    /// `reserved_sections()` mirrors the fields of `Config`; a registered
    /// section must not be able to claim the name of a core section.
    #[test]
    fn reserved_sections_match_config_fields() {
        use oslo_config::CoreSchema;

        let probe = FieldProbe(Default::default());
        let _ = <Config as serde::Deserialize>::deserialize(&probe);
        let mut fields: Vec<&str> = probe.0.into_inner();
        let mut reserved: Vec<&str> = Config::reserved_sections().to_vec();
        fields.sort_unstable();
        reserved.sort_unstable();
        assert_eq!(
            reserved, fields,
            "Config::reserved_sections() is out of sync with the fields of Config"
        );
    }
    use config::{File, FileFormat};

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
    // marked `#[parallel]`, so a mutated variable (e.g. a
    // `KEYSTONE_SITE_VARS_FILE` pointing at a temp file that is about to be
    // dropped) can never leak into a concurrently loading test.
    /// ADR 0034 §9: the per-domain config directory joins the reload watch set
    /// when it exists on disk, and is left out when it does not (the common
    /// case, where watching a missing path would only log).
    #[test]
    #[parallel]
    fn domain_config_dir_is_watched_only_when_present() {
        let dir = tempdir().unwrap();

        let mut cfg = Config::default();
        cfg.identity.domain_config_dir = dir.path().join("absent");
        assert!(
            !cfg.get_watch_files()
                .contains(&cfg.identity.domain_config_dir)
        );

        cfg.identity.domain_config_dir = dir.path().to_path_buf();
        assert!(cfg.get_watch_files().contains(&dir.path().to_path_buf()));
    }

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
    [api_policy]
    opa_base_url = "http://site-vars:8181"
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
                assert_eq!(
                    "http://site-vars:8181/",
                    cfg.api_policy.opa_base_url.to_string()
                );
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

    #[tokio::test]
    #[parallel]
    async fn test_initial_load() {
        let dir = tempdir().unwrap();
        let config_path = setup_files(dir.path());

        // A tiny delay for a higher probability that FS operations are really
        // complete.
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
        // A tiny delay for a higher probability that FS operations are really
        // complete.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let manager = ConfigManager::watched(config_path.clone())
            .await
            .expect("Should initialize");

        // Another delay to correlate update the config after the watch thread
        // is started
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

    /// Overlay precedence is part of the python-keystone compatibility
    /// contract: `OS_*` env beats the site-vars file, which beats the main
    /// config file.
    #[test]
    #[serial]
    fn test_overlay_precedence_env_over_site_vars_over_file() {
        let mut site_vars_file = NamedTempFile::with_suffix(".toml").unwrap();
        write!(
            site_vars_file,
            r#"
    [database]
    connection = "from-site-vars"
    [api_policy]
    opa_base_url = "http://site-vars/"
            "#
        )
        .unwrap();
        let mut cfg_file = NamedTempFile::new().unwrap();
        write!(
            cfg_file,
            r#"
    [auth]
    methods = []
    [database]
    connection = "from-file"
    [api_policy]
    opa_base_url = "http://file/"
    [identity]
    max_password_length = 77
            "#
        )
        .unwrap();

        temp_env::with_vars(
            [
                (
                    "KEYSTONE_SITE_VARS_FILE",
                    Some(site_vars_file.path().as_os_str()),
                ),
                (
                    "OS_API_POLICY__OPA_BASE_URL",
                    Some(std::ffi::OsStr::new("http://env/")),
                ),
            ],
            || {
                let cfg = block_on_config_new(cfg_file.path().to_path_buf()).unwrap();
                // env > site-vars > file
                assert_eq!("http://env/", cfg.api_policy.opa_base_url.to_string());
                // site-vars > file
                assert_eq!(cfg.database.connection.expose_secret(), "from-site-vars");
                // untouched file value survives the overlays
                assert_eq!(77, cfg.identity.max_password_length);
            },
        );
    }

    /// A reload that fails to parse keeps serving the last-known-good
    /// configuration and does not notify listeners; a later valid edit
    /// recovers.
    #[tokio::test]
    #[parallel]
    async fn test_invalid_reload_retains_last_known_good() {
        let dir = tempdir().unwrap();
        let config_path = setup_files(dir.path());
        tokio::time::sleep(Duration::from_millis(10)).await;

        let manager = ConfigManager::watched(config_path.clone())
            .await
            .expect("Should initialize");
        let mut rx = manager.notify_tx.subscribe();
        tokio::time::sleep(Duration::from_millis(10)).await;

        // `[auth]` is required: a file without it cannot be loaded.
        fs::write(
            &config_path,
            r#"
    [database]
    connection = "broken"
    "#,
        )
        .unwrap();

        // Wait well past the notify + debounce window.
        sleep(Duration::from_millis(1500)).await;
        assert_eq!(
            manager
                .config
                .read()
                .await
                .database
                .connection
                .expose_secret(),
            "foo",
            "invalid reload must keep the last-known-good config"
        );
        assert!(
            rx.try_recv().is_err(),
            "invalid reload must not notify listeners"
        );

        // Recovery: a valid edit is picked up and announced.
        fs::write(
            &config_path,
            r#"
    [auth]
    methods = []
    [database]
    connection = "recovered"
    "#,
        )
        .unwrap();
        timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("listeners must be notified after a valid reload")
            .expect("notify channel open");
        assert_eq!(
            manager
                .config
                .read()
                .await
                .database
                .connection
                .expose_secret(),
            "recovered"
        );
    }

    /// A burst of file events must neither wedge the watcher (the notify
    /// callback uses `try_send` to avoid deadlocking notify's single event
    /// thread) nor lose the final state: after the burst settles the manager
    /// serves the last written value.
    #[tokio::test]
    #[parallel]
    async fn test_event_burst_converges_to_last_write() {
        let dir = tempdir().unwrap();
        let config_path = setup_files(dir.path());
        tokio::time::sleep(Duration::from_millis(10)).await;

        let manager = ConfigManager::watched(config_path.clone())
            .await
            .expect("Should initialize");
        tokio::time::sleep(Duration::from_millis(10)).await;

        for i in 0..50 {
            fs::write(
                &config_path,
                format!("[auth]\nmethods = []\n[database]\nconnection = \"burst-{i}\"\n"),
            )
            .unwrap();
        }

        let mut converged = false;
        for _ in 0..25 {
            sleep(Duration::from_millis(200)).await;
            if manager
                .config
                .read()
                .await
                .database
                .connection
                .expose_secret()
                == "burst-49"
            {
                converged = true;
                break;
            }
        }
        assert!(converged, "manager did not converge to the last write");
    }

    /// `shutdown()` on a watched manager stops the watcher, is idempotent and
    /// leaves the last loaded config readable.
    #[tokio::test]
    #[parallel]
    async fn test_watched_shutdown_is_idempotent() {
        let dir = tempdir().unwrap();
        let config_path = setup_files(dir.path());
        tokio::time::sleep(Duration::from_millis(10)).await;

        let manager = ConfigManager::watched(config_path.clone())
            .await
            .expect("Should initialize");

        timeout(Duration::from_secs(5), manager.shutdown())
            .await
            .expect("first shutdown completes");
        timeout(Duration::from_secs(5), manager.shutdown())
            .await
            .expect("second shutdown completes");

        // The watcher is gone: later edits are not applied.
        fs::write(
            &config_path,
            "[auth]\nmethods = []\n[database]\nconnection = \"after\"\n",
        )
        .unwrap();
        sleep(Duration::from_millis(1200)).await;
        assert_eq!(
            manager
                .config
                .read()
                .await
                .database
                .connection
                .expose_secret(),
            "foo"
        );
    }

    #[tokio::test]
    #[parallel]
    async fn test_reload_on_db_cert_change() {
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
        tokio::time::sleep(Duration::from_millis(10)).await;

        let mgr = ConfigManager::watched(config_file.path())
            .await
            .expect("Should initialize");

        tokio::time::sleep(Duration::from_millis(10)).await;

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(cert_file.path())
            .unwrap();
        f.write_all("another db cert".as_bytes()).unwrap();

        let mut success = false;
        for _ in 0..10 {
            sleep(Duration::from_millis(200)).await;
            let updated = mgr.config.read().await;
            if updated
                .database
                .tls
                .tls_cert_content
                .as_ref()
                .map(|x| x.expose_secret())
                == Some("another db cert".as_bytes())
            {
                success = true;
                break;
            }
        }
        assert!(
            success,
            "Database TLS cert did not update after file change"
        );
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

        // 3. FULL COVERAGE: Explicitly ensure the error message blames every
        //    single invalid field
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

    #[tokio::test]
    #[parallel]
    async fn test_db_spiffe_managed_requires_tls_files() {
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
    spiffe_managed = true
            "#
            .as_bytes(),
        )
        .unwrap();
        f.sync_all().unwrap();

        let result = Config::load_all(config_file.path().to_path_buf()).await;
        assert!(
            result.is_err(),
            "Expected spiffe_managed = true without TLS file paths to be rejected"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("spiffe_managed"),
            "Expected the error to mention spiffe_managed, got: {}",
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
