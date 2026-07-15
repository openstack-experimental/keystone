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
//! Main Keystone executable.
//!
//! This is the entry point of the `keystone` binary.

use std::io;
use std::net::SocketAddr;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router, ServiceExt,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{self, HeaderName, Request, StatusCode, header},
    response::IntoResponse,
};
use clap::{Parser, ValueEnum};
use color_eyre::eyre::{Report, Result, WrapErr};
use sea_orm::{ConnectOptions, Database};
use secrecy::{ExposeSecret, SecretBox};
use tokio::net::TcpListener;
use tokio::{signal, spawn, time};
use tokio_util::sync::CancellationToken;
// `Layer` imported anonymously: its `.layer()` method is needed to wrap the
// Router, but the name is already taken by `tracing_subscriber::Layer` below.
use tower::util::MapRequestLayer;
use tower::{Layer as _, ServiceBuilder};
use tower_http::{
    LatencyUnit, ServiceBuilderExt,
    normalize_path::NormalizePathLayer,
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::{Level, debug, error, info, info_span, trace, warn};
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    Layer,
    filter::{LevelFilter, Targets},
    prelude::*,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

use openstack_keystone::application_credential::ApplicationCredentialHook;
use openstack_keystone::assignment::AssignmentHook;
use openstack_keystone::auth_plugin_http_client::KeystoneDynamicPluginHttpFetcher;
use openstack_keystone::auth_plugin_identity::DynamicPluginIdentityHook;
use openstack_keystone::catalog::CatalogHook;
use openstack_keystone::config::{Config, ConfigManager, Interface, ListenerConfig};
use openstack_keystone::federation::FederationHook;
use openstack_keystone::identity::IdentityHook;
use openstack_keystone::idmapping::IdMappingHook;
use openstack_keystone::k8s_auth::K8sAuthHook;
use openstack_keystone::k8s_auth_client::KeystoneK8sHttpClient;
use openstack_keystone::keystone::Service as KeystoneServiceState;
use openstack_keystone::keystone::ServiceState;
use openstack_keystone::oauth2_key::Oauth2KeyHook;
use openstack_keystone::plugin_manager::PluginManager;
use openstack_keystone::policy::HttpPolicyEnforcer;
use openstack_keystone::provider::Provider;
use openstack_keystone::resource::ResourceHook;
use openstack_keystone::revoke::RevokeHook;
use openstack_keystone::role::RoleHook;
use openstack_keystone::scim;
use openstack_keystone::server::listener::{raft_grpc, spiffe_tls, spiffe_tls_uds};
use openstack_keystone::server::proxy_headers;
use openstack_keystone::token::TokenHook;
use openstack_keystone::trust::TrustHook;
use openstack_keystone::webauthn;
use openstack_keystone::{api, common};
use openstack_keystone_audit::spool::{replay_spool, run_spool_writer, spool_path};
use openstack_keystone_audit::{AuditDispatcher, HmacKeyStore, derive_audit_hmac_key};
use openstack_keystone_core::api_key::janitor as api_key_janitor;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::auth_plugin_startup::load_auth_plugins;
use openstack_keystone_core::cadf_hook::CadfAuditHook;
use openstack_keystone_core::db::sync_schema;
use openstack_keystone_core::error::KeystoneError;
use openstack_keystone_core::oauth2_key::janitor as oauth2_key_janitor;
use openstack_keystone_core::scim_resource::janitor as scim_resource_janitor;
use openstack_keystone_credential_driver_sql::fernet::FernetKeyRepository;
use openstack_keystone_distributed_storage::{StorageApi, app::Storage};
use openstack_keystone_token_driver_fernet::utils::FernetUtils;

// Default body limit 256kB
const DEFAULT_BODY_LIMIT: usize = 1024 * 256;

/// Version tag stamped on audit HMAC keys (ADR 0023 / ADR 0016-v2 §3.1).
const AUDIT_HMAC_KEY_VERSION: u64 = 1;

/// `OpenStack` Keystone.
///
/// Keystone is an `OpenStack` service that provides API client authentication,
/// service discovery, and distributed multi-tenant authorization by
/// implementing OpenStack's Identity API.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the keystone config file.
    #[arg(short, long, default_value = "/etc/keystone/keystone.conf")]
    config: PathBuf,

    /// Verbosity level. Repeat to increase level.
    #[arg(short, long, global=true, action = clap::ArgAction::Count, display_order = 920)]
    pub verbose: u8,

    /// Print the `OpenAPI` schema json instead of running the Keystone.
    #[arg(long)]
    pub dump_openapi: Option<OpenApiFormat>,
}

#[derive(Clone, Debug, Default, PartialEq, ValueEnum)]
enum OpenApiFormat {
    /// Json.
    Json,
    #[default]
    /// Yaml.
    Yaml,
}

// A `MakeRequestId` that increments an atomic counter
#[derive(Clone, Default)]
struct OpenStackRequestId {}

impl MakeRequestId for OpenStackRequestId {
    fn make_request_id<B>(&mut self, _request: &http::Request<B>) -> Option<RequestId> {
        let req_id = Uuid::new_v4().simple().to_string();

        Some(RequestId::new(
            http::HeaderValue::from_str(format!("req-{req_id}").as_str())
                // default to static value. This is not expected to ever happen.
                .unwrap_or_else(|_| http::HeaderValue::from_static("req-unknown")),
        ))
    }
}

#[allow(clippy::print_stdout)]
#[tokio::main]
async fn main() -> Result<(), Report> {
    let args = Args::parse();

    // When only dumping of the openapi spec is necessary we should not even start
    // parsing the config file. This means we cannot initialize the logging yet.
    let mut openapi = api::ApiDoc::openapi();
    let webauthn_openapi = webauthn::api::openapi_router();
    let (main_router, main_api) = api::openapi_router().split_for_parts();
    openapi.merge(main_api);
    openapi = openapi.nest("/v4", webauthn_openapi.into_openapi());

    if let Some(dump_format) = &args.dump_openapi {
        println!(
            "{}",
            match dump_format {
                OpenApiFormat::Yaml => openapi.to_yaml()?,
                OpenApiFormat::Json => openapi.to_pretty_json()?,
            }
        );
        return Ok(());
    }

    let cfg_mgr = ConfigManager::watched(args.config).await?;
    let cfg = cfg_mgr.config.read().await.clone();

    // Guard must stay alive for the process lifetime to flush buffered
    // file-appender logs; binding to `_guard` (rather than dropping the
    // `Option`) keeps that lifetime tied to `main`'s scope.
    let _guard = init_tracing(args.verbose, &cfg);
    color_eyre::install()?;

    info!("Starting Keystone...");

    // ADR 0019 §4: refuse to start if the credential Fernet key repository
    // contains the well-known Null Key, unless the operator has explicitly
    // opted in via [credential] insecure_allow_null_key. This is a startup
    // check in addition to the check `FernetKeyRepository::load` already
    // performs lazily on first credential access, so a misconfigured
    // repository is caught immediately rather than on first request.
    FernetKeyRepository::new(cfg.credential.key_repository.clone())
        .check_startup_null_key(cfg.credential.insecure_allow_null_key)
        .await
        .wrap_err("credential key repository failed startup check")?;

    // Same check for the token Fernet key repository (ADR 0019 §4, now
    // shared logic with the credential key repository above).
    FernetUtils {
        key_repository: cfg.fernet_tokens.key_repository.clone(),
        max_active_keys: cfg.fernet_tokens.max_active_keys,
    }
    .check_startup_null_key(cfg.fernet_tokens.insecure_allow_null_key)
    .await
    .wrap_err("token key repository failed startup check")?;

    let token = CancellationToken::new();
    let cloned_token = token.clone();

    let opt: ConnectOptions = ConnectOptions::new(cfg.database.get_connection().expose_secret())
        // Prevent dumping the password in plaintext.
        .sqlx_logging(false)
        .to_owned();

    debug!("Establishing the database connection...");
    let conn = Database::connect(opt.clone())
        .await
        .wrap_err("Database connection failed")?;
    if opt.get_url() == "sqlite::memory:" {
        warn!("The database connection represent in-memory SQLite Database.");
        sync_schema(&conn)
            .await
            .wrap_err("failed to sync schema for in-memory database")?;
    };

    let plugin_manager = PluginManager::with_config(&cfg)
        .await
        .wrap_err("initializing plugin manager")?;
    let k8s_http_client: Arc<dyn openstack_keystone_core::k8s_auth::K8sHttpClient> =
        Arc::new(KeystoneK8sHttpClient::new());
    let provider = Provider::new(&cfg, &plugin_manager, k8s_http_client)?;
    let policy = HttpPolicyEnforcer::new(cfg.api_policy.opa_base_url.clone()).await?;

    let concrete_storage: Option<Arc<Storage>> = if cfg.distributed_storage.is_some() {
        let storage = openstack_keystone_distributed_storage::app::init_storage(&cfg_mgr)
            .await
            .map_err(|e| KeystoneError::Provider {
                source: Box::new(e),
            })?;
        Some(storage)
    } else {
        None
    };

    let storage_for_service: Option<Arc<dyn StorageApi>> = concrete_storage
        .as_ref()
        .map(Arc::clone)
        .map(|s| s as Arc<dyn StorageApi>);

    let audit_dispatcher = init_audit(&cfg).await?;

    let shared_state = Arc::new(
        KeystoneServiceState::new(
            cfg_mgr,
            conn,
            provider,
            Arc::new(policy),
            audit_dispatcher,
            storage_for_service,
        )
        .await?,
    );

    // Also evicts stale rate-limit keyed-store entries (ADR-0022) and
    // shrinks idle auth-plugin invocation limiters (ADR-0025 §7) on the
    // same 60 s tick.
    spawn(cleanup(cloned_token, shared_state.clone()));

    // API Key (SCIM ingress) janitor: proactive inactivity disablement and
    // tombstone purge (ADR 0021 §6.F). Runs on every node; gated to actually
    // do work only on the current Raft leader.
    api_key_janitor::spawn(shared_state.clone());

    // SCIM resource janitor: permanent purge of tombstoned Users/Groups past
    // the configured retention window (ADR 0024 §6.C). Same leader-gated
    // pattern as the API Key janitor above.
    scim_resource_janitor::spawn(shared_state.clone());

    // OAuth2 signing key janitor: demoted `Previous` key retirement and
    // proactive JTI revocation-list pruning (ADR 0026 §3). Same leader-gated
    // pattern as the API Key janitor above.
    oauth2_key_janitor::spawn(shared_state.clone());

    // Reset the dummy-password-hash cache whenever the configuration is
    // hot-reloaded. The cache is keyed by (algorithm, rounds); if the operator
    // changes `password_hashing_algorithm` or `password_hash_rounds` at runtime,
    // stale entries would otherwise keep being served and reintroduce the very
    // timing side-channel the dummy hash exists to close.
    spawn(reset_dummy_hash_on_reload(
        token.clone(),
        shared_state.clone(),
    ));
    spawn(reload_rate_limits_on_config_change(
        token.clone(),
        shared_state.clone(),
    ));

    subscribe_event_hooks(&shared_state).await;

    // Dynamic auth plugins (ADR 0025): loaded post-construction, since
    // `CoreHostFunctions` needs a fully-built `ServiceState` - see
    // `load_auth_plugins`'s doc comment. A per-plugin load failure
    // disables only that plugin; every other auth method still starts.
    load_auth_plugins(
        &shared_state,
        Arc::new(KeystoneDynamicPluginHttpFetcher::new()),
    )
    .await;
    warn_on_unresolvable_auth_methods(&shared_state).await;

    let app = build_router(&shared_state, &token, main_router, openapi).await?;

    // Shutdown watcher
    let global_shutdown_token = token.clone();
    let signal_state = shared_state.clone();
    tokio::spawn(async move {
        // Your existing handler that takes Arc<AppState>
        // Instead of calling handle.graceful_shutdown, just cancel the token
        shutdown_signal(signal_state).await;
        global_shutdown_token.cancel();
    });

    let mut handles: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    start_raft(&cfg, &concrete_storage, &token, &mut handles).await?;
    spawn_opa_subprocess(&cfg, &token, &mut handles).await?;
    spawn_public_listener(&cfg, app.clone(), &token, &mut handles).await?;
    spawn_internal_listener(&cfg, app.clone(), &token, &mut handles)?;
    spawn_admin_listener(&cfg, app, &token, &mut handles);

    // Wait for both (or handle errors)
    handles.join_all().await;
    token.cancel();
    Ok(())
}

/// Initialize the tracing subscriber registry (stderr, and optionally a
/// rotating file appender) based on CLI verbosity and the loaded config.
///
/// Returns the file-appender's `WorkerGuard`, if file logging is enabled.
/// The caller must keep this alive for the process lifetime — dropping it
/// stops buffered log lines from being flushed.
fn init_tracing(verbose: u8, cfg: &Config) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let external_deps_log_level = match verbose {
        0 => LevelFilter::ERROR,
        1 => LevelFilter::WARN,
        2 => LevelFilter::INFO,
        _ => LevelFilter::DEBUG,
    };
    let stderr_log_filter = Targets::new()
        .with_default(match verbose {
            0 => LevelFilter::WARN,
            1 => LevelFilter::INFO,
            2 => LevelFilter::DEBUG,
            _ => LevelFilter::TRACE,
        })
        .with_target("cranelift_codegen", LevelFilter::ERROR)
        .with_target("wasmtime_internal_cranelift", LevelFilter::ERROR)
        .with_target("wasmtime", LevelFilter::ERROR)
        .with_target("h2", external_deps_log_level)
        .with_target("rustls", external_deps_log_level)
        .with_target("tower", external_deps_log_level)
        .with_target("openraft", external_deps_log_level)
        .with_target("lsm_tree", external_deps_log_level);

    // Build the stderr log layer.
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .with_filter(stderr_log_filter)
        .boxed();

    let mut log_layers = Vec::new();

    if cfg.default.use_stderr {
        log_layers.push(stderr_layer);
    }

    let mut guard = None;

    if let Some(log_dir) = &cfg.default.log_dir {
        // create a file appender that rotates hourly
        let file_appender = tracing_appender::rolling::never(log_dir, "keystone.log");
        // make the file appender non-blocking; the guard must outlive the
        // registry to make sure buffered logs get flushed to output.
        let (non_blocking, file_guard) = tracing_appender::non_blocking(file_appender);
        guard = Some(file_guard);

        let log_file_filter = Targets::new()
            .with_default(if cfg.default.debug {
                LevelFilter::DEBUG
            } else {
                LevelFilter::INFO
            })
            .with_target("cranelift_codegen", LevelFilter::ERROR)
            .with_target("wasmtime_internal_cranelift", LevelFilter::ERROR)
            .with_target("wasmtime", LevelFilter::ERROR)
            .with_target("h2", external_deps_log_level)
            .with_target("rustls", external_deps_log_level)
            .with_target("tower", external_deps_log_level)
            .with_target("openraft", external_deps_log_level)
            .with_target("lsm_tree", external_deps_log_level);
        log_layers.push(
            tracing_subscriber::fmt::layer()
                // No colors in the log file
                .with_ansi(false)
                .with_writer(non_blocking)
                .with_filter(log_file_filter)
                .boxed(),
        );
    }
    // build the tracing registry
    tracing_subscriber::registry()
        .with(ErrorLayer::default())
        .with(log_layers)
        .init();

    guard
}

/// Load or generate the persisted audit HMAC key-encryption-key (KEK),
/// derive the per-node signing key, build the `AuditDispatcher`, replay any
/// events spooled by a previous run (at-least-once delivery), and spawn the
/// background spool writers for both QoS channels. See ADR 0023 / ADR
/// 0016-v2 §3.1.
async fn init_audit(cfg: &Config) -> Result<Arc<AuditDispatcher>, Report> {
    let audit_cfg = cfg.audit.clone();
    let spool_dir = audit_cfg.spool_dir.clone();
    std::fs::create_dir_all(&spool_dir).wrap_err("failed to create audit spool directory")?;

    // Load or generate the persisted 32-byte KEK.  The KEK itself is not
    // used as the HMAC signing key — a per-node key is derived from it via
    // HKDF-Expand (see `derive_audit_hmac_key`).  Storing the KEK means a
    // restart can re-derive the same per-node key and replay the spool.
    let kek_file = spool_dir.join("hmac-key.bin");
    // `SecretBox` zeroizes the KEK bytes on drop, so the key-encryption-key
    // does not linger in memory beyond `init_audit`'s scope.
    let audit_kek: SecretBox<Vec<u8>> = SecretBox::new(Box::new(match std::fs::read(&kek_file) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                return Err(eyre::eyre!(
                    "audit KEK at {} is {} bytes — expected 32; \
                     delete the file to regenerate",
                    kek_file.display(),
                    bytes.len()
                ));
            }
            bytes
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            use std::fs::OpenOptions;
            use std::io::{Read as _, Write as _};
            use std::os::unix::fs::OpenOptionsExt;
            let mut raw = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut raw))
                .wrap_err("failed to generate audit KEK from /dev/urandom")?;
            // Write to a temp file with restricted permissions, then atomically
            // rename.  This avoids both a world-readable key file (permissions)
            // and a TOCTOU window where two processes each generate independent
            // keys.
            let tmp_path = kek_file.with_extension("tmp");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)
                .wrap_err("failed to create temporary audit KEK file")?;
            file.write_all(&raw).wrap_err("failed to write audit KEK")?;
            std::fs::rename(&tmp_path, &kek_file).wrap_err("failed to finalize audit KEK file")?;
            info!(path = %kek_file.display(), "generated new audit KEK");
            raw.to_vec()
        }
        Err(e) => {
            // File exists but can't be read — permissions error or similar.
            // Fall back to regenerating (the old file will be silently left).
            return Err(e).wrap_err("failed to read audit KEK; fix permissions or delete the file");
        }
    }));

    // Derive the per-node signing key:
    //   HKDF-Expand(KEK, info="keystone-audit-hmac-v1:{node_id}", L=32)
    // Per ADR 0023 / ADR 0016-v2 §3.1: per-node derivation ensures a
    // compromised node cannot forge records attributed to other nodes.
    let audit_hmac_key: Arc<[u8]> = Arc::from(
        derive_audit_hmac_key(audit_kek.expose_secret(), audit_cfg.node_id.as_str()).as_slice(),
    );

    let (audit_dispatcher, audit_receivers) = AuditDispatcher::new(
        audit_cfg.node_id.as_str(),
        Uuid::new_v4().to_string(),
        Arc::clone(&audit_hmac_key),
        AUDIT_HMAC_KEY_VERSION,
    );

    // Replay the spool file left by the previous run (at-least-once delivery).
    //
    // `MultiKeyStore` holds all key versions seen during this process lifetime.
    // Currently only one version exists; the HashMap is pre-populated with the
    // current key so that `replay_spool` can verify events signed by it.
    // When key rotation is implemented, callers MUST insert the new version
    // before calling `refresh_hmac_key` on the dispatcher — spool events
    // written before the rotation will still carry the old version number and
    // must remain verifiable during the drain window (ADR 0023 §"Key Rotation").
    struct MultiKeyStore(std::collections::HashMap<u64, Arc<[u8]>>);
    impl HmacKeyStore for MultiKeyStore {
        fn get_key(&self, version: u64) -> Option<Arc<[u8]>> {
            self.0.get(&version).map(Arc::clone)
        }
    }
    let mut key_store = MultiKeyStore(std::collections::HashMap::new());
    key_store
        .0
        .insert(AUDIT_HMAC_KEY_VERSION, Arc::clone(&audit_hmac_key));
    let spool_file = spool_path(&spool_dir, audit_cfg.node_id.as_str());
    replay_spool(
        &spool_file,
        audit_cfg.node_id.as_str(),
        &audit_dispatcher,
        &key_store,
    )
    .await
    .wrap_err("audit spool replay failed")?;

    // Start background spool writers for both QoS channels.
    spawn(run_spool_writer(
        audit_receivers.perimeter,
        spool_dir.clone(),
        audit_cfg.node_id.clone(),
    ));
    spawn(run_spool_writer(
        audit_receivers.critical,
        spool_dir,
        audit_cfg.node_id.clone(),
    ));

    Ok(audit_dispatcher)
}

/// Subscribe all provider event hooks (application-credential, assignment,
/// catalog, auth-plugin-identity, federation, identity, ID-mapping,
/// k8s-auth, resource, revoke, role, token, trust) plus the CADF audit hook
/// to `shared_state`'s event dispatcher.
async fn subscribe_event_hooks(shared_state: &ServiceState) {
    shared_state
        .event_dispatcher
        .subscribe(Arc::new(ApplicationCredentialHook::new(
            shared_state.clone(),
        )))
        .await;
    shared_state
        .event_dispatcher
        .subscribe(Arc::new(AssignmentHook::new(shared_state.clone())))
        .await;
    shared_state
        .event_dispatcher
        .subscribe(Arc::new(CatalogHook::new(shared_state.clone())))
        .await;
    shared_state
        .event_dispatcher
        .subscribe(Arc::new(DynamicPluginIdentityHook::new(
            shared_state.clone(),
        )))
        .await;
    shared_state
        .event_dispatcher
        .subscribe(Arc::new(FederationHook::new(shared_state.clone())))
        .await;
    shared_state
        .event_dispatcher
        .subscribe(Arc::new(IdentityHook::new(shared_state.clone())))
        .await;
    shared_state
        .event_dispatcher
        .subscribe(Arc::new(IdMappingHook::new(shared_state.clone())))
        .await;
    shared_state
        .event_dispatcher
        .subscribe(Arc::new(K8sAuthHook::new(shared_state.clone())))
        .await;
    shared_state
        .event_dispatcher
        .subscribe(Arc::new(Oauth2KeyHook::new(shared_state.clone())))
        .await;
    shared_state
        .event_dispatcher
        .subscribe(Arc::new(ResourceHook::new(shared_state.clone())))
        .await;
    shared_state
        .event_dispatcher
        .subscribe(Arc::new(RevokeHook::new(shared_state.clone())))
        .await;
    shared_state
        .event_dispatcher
        .subscribe(Arc::new(RoleHook::new(shared_state.clone())))
        .await;
    shared_state
        .event_dispatcher
        .subscribe(Arc::new(TokenHook::new(shared_state.clone())))
        .await;
    shared_state
        .event_dispatcher
        .subscribe(Arc::new(TrustHook::new(shared_state.clone())))
        .await;

    // Phase 3: subscribe the CADF audit hook (fail-closed provider auditing).
    shared_state
        .event_dispatcher
        .subscribe_audit(Arc::new(CadfAuditHook::new(Arc::clone(
            &shared_state.audit_dispatcher,
        ))))
        .await;
}

/// Log a `WARN` for every `[auth] methods` entry that is neither a builtin
/// auth method nor a successfully-loaded dynamic plugin name (ADR 0025 §5:
/// a misconfiguration here degrades one method, not the node - never a
/// startup error).
async fn warn_on_unresolvable_auth_methods(shared_state: &ServiceState) {
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
    let methods = shared_state
        .config_manager
        .config
        .read()
        .await
        .auth
        .methods
        .clone();
    let registry = shared_state.auth_plugin_registry.read().await;
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

/// Assemble the full Axum application: merges the `OpenAPI`-generated
/// routes, metrics endpoint, optional `WebAuthN` extension, and SCIM
/// ingress sub-router; layers on request-id/tracing/compression
/// middleware; then wraps the result in `NormalizePathLayer` with Swagger
/// UI mounted outside the normalization boundary.
///
/// Serving a path with or without a trailing slash from the same handler
/// (matches Python Keystone, see issue #734) requires `NormalizePathLayer`
/// to rewrite the request URI *before* routing, so it must wrap the Router
/// from the outside, not be added via `Router::layer()` (which runs *after*
/// route matching, by which point "/v3/users/" has already failed to match
/// the "/v3/users" route). No HTTP redirect is involved.
/// <https://docs.rs/tower-http/latest/tower_http/normalize_path/index.html>
///
/// SwaggerUi is deliberately merged in *after* normalization and kept out
/// of the normalized service: SwaggerUi's own handler issues an internal
/// redirect between "/swagger-ui" and "/swagger-ui/", and trimming the
/// trailing slash before that handler runs turns the redirect into an
/// infinite loop. <https://github.com/juhaku/utoipa/issues/1467>
async fn build_router(
    shared_state: &ServiceState,
    token: &CancellationToken,
    main_router: Router<ServiceState>,
    openapi: utoipa::openapi::OpenApi,
) -> Result<Router, Report> {
    let x_request_id = HeaderName::from_static("x-openstack-request-id");
    let sensitive_headers: Arc<[_]> = vec![
        header::AUTHORIZATION,
        header::COOKIE,
        header::HeaderName::from_static("x-auth-token"),
        header::HeaderName::from_static("x-subject-token"),
    ]
    .into();

    let strip_x_request_id = x_request_id.clone();
    let middleware = ServiceBuilder::new()
        // Strip any client-supplied x-openstack-request-id before SetRequestIdLayer
        // runs, so we always generate a fresh server-controlled UUID (ADR 0023 §2.1).
        .layer(MapRequestLayer::new(move |mut req: Request<_>| {
            req.headers_mut().remove(strip_x_request_id.clone());
            req
        }))
        // Inject x-request-id header into processing
        // make sure to set request ids before the request reaches `TraceLayer`
        .layer(SetRequestIdLayer::new(
            x_request_id.clone(),
            OpenStackRequestId::default(),
        ))
        //.layer(PropagateRequestIdLayer::new(x_request_id))
        .sensitive_request_headers(sensitive_headers.clone())
        .layer(DefaultBodyLimit::max(DEFAULT_BODY_LIMIT))
        .layer(
            TraceLayer::new(common::KeystoneResponseClassifier)
                .make_span_with(|request: &Request<_>| {
                    // Client address captured into `ConnectInfo<SocketAddr>`
                    // (the keystone-ng analogue of Python Keystone's WSGI
                    // REMOTE_ADDR / flask.request.remote_addr): the raw TCP peer
                    // on the public listener via
                    // `into_make_service_with_connect_info`, or the mTLS peer on
                    // the internal SPIFFE-TLS listener (injected by hand). When
                    // `enable_proxy_headers_parsing` is on, the public value has
                    // been overwritten with the proxy-resolved client address.
                    // `None` on the admin UDS interface, which has no meaningful
                    // `SocketAddr`.
                    let client_addr = request
                        .extensions()
                        .get::<ConnectInfo<SocketAddr>>()
                        .map(|ConnectInfo(addr)| *addr);
                    info_span!(
                        "request",
                        method = ?request.method(),
                        client.addr = ?client_addr,
                        uri = ?request.uri().path(),
                        x_request_id = ?request.headers().get("x-openstack-request-id")
                    )
                })
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(
                    DefaultOnResponse::new()
                        .level(Level::INFO)
                        .latency_unit(LatencyUnit::Micros),
                ),
        )
        // Compress responses
        .compression()
        .sensitive_response_headers(sensitive_headers)
        // propagate the header to the response before the response reaches `TraceLayer`
        .layer(PropagateRequestIdLayer::new(x_request_id));
    //.layer(middleware::from_fn(cert_extension_middleware));

    let metrics_router = Router::new()
        .route("/metrics", axum::routing::get(metrics_handler))
        .with_state(shared_state.clone());

    let mut app = Router::new()
        .merge(main_router.with_state(shared_state.clone()))
        .merge(metrics_router);

    if shared_state
        .config_manager
        .config
        .read()
        .await
        .webauthn
        .enabled
    {
        let webauthn_cloned_token = token.clone();
        let webauthn_extension =
            webauthn::api::init_extension(shared_state.clone(), webauthn_cloned_token).await?;
        app = app.nest("/v4", webauthn_extension);
    } else {
        info!("Not enabling the WebAuthN extension due to the `config.webauthn.enabled` flag.");
    }

    // SCIM ingress sub-router (ADR 0021 §4): mounted independently of
    // `/v3`/`/v4` so that only these routes accept API-Key bearer tokens.
    app = app.nest("/SCIM/v2", scim::router().with_state(shared_state.clone()));

    app = app.layer(middleware);

    let normalized_app = NormalizePathLayer::trim_trailing_slash().layer(app);
    let app = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", openapi))
        .fallback_service(normalized_app);

    Ok(app)
}

/// Start the Raft gRPC listener and join the cluster, when distributed
/// storage is configured.
async fn start_raft(
    cfg: &Config,
    concrete_storage: &Option<Arc<Storage>>,
    token: &CancellationToken,
    handles: &mut tokio::task::JoinSet<()>,
) -> Result<(), Report> {
    if cfg.distributed_storage.is_some() {
        let raft_cancel_token = token.clone();
        let raft_config = cfg.clone();
        let raft_storage = concrete_storage.as_ref().expect("storage is None").clone();
        let raft_storage_init = raft_storage.clone();

        // Signal channel: start_raft_app sends `true` once the gRPC listener
        // is bound. `ensure_raft_initialized` waits for this before calling
        // join_cluster, ensuring the new node's listener is ready to accept
        // replication traffic from the leader.
        let (raft_bound_tx, raft_bound_rx) = tokio::sync::watch::channel(false);
        let raft_task_token = token.clone();
        handles.spawn(async move {
            if let Err(e) = raft_grpc::start_raft_app(
                raft_storage,
                raft_config,
                raft_cancel_token,
                raft_bound_tx,
            )
            .await
            {
                error!("Raft gRPC listener error: {:#}", e);
                raft_task_token.cancel();
            }
            debug!("Raft gRPC task exited");
        });
        debug!("Raft task spawned, calling ensure_raft_initialized...");
        raft_grpc::ensure_raft_initialized(raft_storage_init, cfg.clone(), raft_bound_rx).await?;
        debug!("Raft initialized and ready");
    }
    Ok(())
}

/// Launch the local OPA subprocess when `api_policy.opa_policies_path` is
/// configured, capture its log output, and wait for it to become ready before
/// returning.
///
/// Redirects OPA stdout/stderr and routes each line through the configured
/// tracing logger.  Polls `/health` with a back-off until OPA reports a
/// healthy status or the startup timeout expires.  This prevents a race where
/// Keystone listeners accept requests (and run policy checks) before the
/// embedded OPA is actually serving.
async fn spawn_opa_subprocess(
    cfg: &Config,
    _token: &CancellationToken,
    handles: &mut tokio::task::JoinSet<()>,
) -> Result<(), Report> {
    if let Some(policies_path) = &cfg.api_policy.opa_policies_path {
        let opa_url = cfg.api_policy.opa_base_url.clone();
        let addr = match opa_url.scheme() {
            "http" | "https" => format!(
                "{}:{}",
                opa_url.host_str().unwrap_or("0.0.0.0"),
                opa_url.port().unwrap_or(8181)
            ),
            "unix" | "http+unix" => format!("unix://{}", opa_url.path()),
            _ => format!(
                "{}:{}",
                opa_url.host_str().unwrap_or("0.0.0.0"),
                opa_url.port().unwrap_or(8181)
            ),
        };

        let opa_socket_path = match opa_url.scheme() {
            "unix" | "http+unix" => Some(PathBuf::from(opa_url.path())),
            _ => None,
        };

        let health_url = match &opa_socket_path {
            Some(_) => "http://localhost/health".parse().unwrap(),
            None => opa_url.join("/health").unwrap_or_else(|_| opa_url.clone()),
        };

        // Build the reqwest client.  When OPA listens on a Unix socket, the
        // client must use `.unix_socket()` so that HTTP requests are routed
        // over the socket rather than a TCP connection to localhost.
        let health_client = if let Some(ref socket_path) = opa_socket_path {
            reqwest::Client::builder()
                .unix_socket(socket_path.clone())
                .build()
                .wrap_err("failed to build reqwest client for OPA health check")?
        } else {
            reqwest::Client::new()
        };

        info!(
            "Starting OPA subprocess with policies from {:?} listening on {}",
            policies_path, addr
        );
        let mut opa_cmd = tokio::process::Command::new("opa");
        opa_cmd
            .arg("run")
            .arg("-s")
            .arg(policies_path)
            .arg("--addr")
            .arg(&addr)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = opa_cmd.spawn().wrap_err_with(|| {
            "failed to start OPA subprocess: is `opa` installed and on PATH?".to_string()
        })?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| eyre::eyre!("OPA stdout pipe unexpectedly missing"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| eyre::eyre!("OPA stderr pipe unexpectedly missing"))?;

        // Forward OPA stdout lines to the tracing logger.
        let stdout_task = async move {
            let mut reader = tokio::io::BufReader::new(stdout);
            let mut buf = String::new();
            use tokio::io::AsyncBufReadExt as _;
            loop {
                buf.clear();
                match reader.read_line(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        info!(target: "opa", "{}", buf.trim_end());
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to read OPA stdout line");
                        break;
                    }
                }
            }
        };

        // Forward OPA stderr lines to the tracing logger.
        let stderr_task = async move {
            let mut reader = tokio::io::BufReader::new(stderr);
            let mut buf = String::new();
            use tokio::io::AsyncBufReadExt as _;
            loop {
                buf.clear();
                match reader.read_line(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        warn!(target: "opa", "{}", buf.trim_end());
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to read OPA stderr line");
                        break;
                    }
                }
            }
        };

        // Wait for OPA to be ready so that policy checks won't fail on first
        // request.  Uses the same `/health` endpoint that OPA exposes.
        let ready_timeout = Duration::from_secs(10);
        let health_url_clone = health_url.clone();
        let ready_result = time::timeout(ready_timeout, async move {
            let client = &health_client;
            let mut backoff = Duration::from_millis(50);
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {
                        match client.get(health_url_clone.as_str()).send().await {
                            Ok(resp) => {
                                if resp.status().is_success() {
                                    return true;
                                }
                                warn!(
                                    status = %resp.status(),
                                    "OPA health check returned non-success, retrying"
                                );
                            }
                            Err(e) => {
                                trace!(error = %e, "OPA not yet ready, retrying");
                            }
                        }
                        backoff = backoff
                            .saturating_mul(2)
                            .min(Duration::from_secs(1));
                    }
                }
            }
        })
        .await;

        // Spawn the log-forwarding tasks so they keep draining pipes even after
        // we return; otherwise the child could block on a full pipe and deadlock.
        handles.spawn(stdout_task);
        handles.spawn(stderr_task);

        if ready_result.is_err() {
            error!(
                error_msg = "OPA subprocess failed to become healthy within \
                             timeout",
                timeout_secs = ready_timeout.as_secs(),
                addr = %addr,
                "OPA did not become healthy"
            );
            info!("the health url used was: {}", health_url);
            return Err(eyre::eyre!(
                "OPA did not become healthy within {} seconds",
                ready_timeout.as_secs()
            ));
        }

        info!(
            "OPA subprocess is ready on {}, health: {}",
            addr, health_url
        );

        handles.spawn(async move {
            match child.wait().await {
                Ok(code) => {
                    if code.success() {
                        info!("OPA subprocess exited cleanly with status {}", code);
                    } else if let Some(exit_code) = code.code() {
                        error!(
                            exit_code = exit_code,
                            "OPA subprocess exited with error code"
                        );
                    } else if let Some(signal) = code.signal() {
                        error!(signal = signal, "OPA subprocess was killed by signal");
                    } else {
                        error!("OPA subprocess exited abnormally (status unknown)");
                    }
                }
                Err(e) => {
                    error!(error = %e, "failed to wait on OPA subprocess");
                }
            }
        });
    }
    Ok(())
}

/// Start the public HTTP REST API listener.
async fn spawn_public_listener(
    cfg: &Config,
    app: Router,
    token: &CancellationToken,
    handles: &mut tokio::task::JoinSet<()>,
) -> Result<(), Report> {
    match cfg.interface_public.listener {
        ListenerConfig::Http => {
            info!("Starting Rest API at {}", cfg.interface_public.tcp_address);
            let listener = TcpListener::bind(&cfg.interface_public.tcp_address).await?;
            let rest_cancel_token = token.clone();
            // When operating behind a trusted reverse proxy (config-gated,
            // off by default), parse the explicitly selected forwarding
            // header and rewrite the raw-peer `ConnectInfo` with the client
            // *before* the tracing span and handlers read it. The header is
            // honoured only when the immediate peer matches `trusted_proxies`,
            // so an empty allowlist keeps the raw peer. The layer is added only
            // on this public interface — never on the internal SPIFFE/admin
            // listeners, whose peers are the mTLS mesh.
            let rest_app = if cfg.oslo_middleware.enable_proxy_headers_parsing {
                info!(
                    trusted_proxies = cfg.oslo_middleware.trusted_proxies.len(),
                    trusted_header = cfg.oslo_middleware.trusted_header.as_str(),
                    "Proxy header parsing enabled on the public interface"
                );
                let proxy_config = Arc::new(cfg.oslo_middleware.clone());
                app.layer(axum::middleware::from_fn_with_state(
                    proxy_config,
                    proxy_headers::rewrite_client_addr,
                ))
            } else {
                app
            };
            handles.spawn(async move {
                // `rest_app` is a `Router` whose fallback is the
                // `NormalizePath`-wrapped API service (issue #734, #1467); use
                // axum's `ServiceExt` (blanket-impl'd for any `Service`) with an
                // explicit request type to satisfy inference (E0284).
                //
                // `into_make_service_with_connect_info::<SocketAddr>` stores the
                // raw TCP peer address in a `ConnectInfo<SocketAddr>` request
                // extension (the analogue of Python Keystone's WSGI REMOTE_ADDR).
                // Behind a reverse proxy/LB this is the proxy's address; the
                // `rewrite_client_addr` layer wired above (when
                // `enable_proxy_headers_parsing` is on) preserves this raw
                // value separately before overwriting `ConnectInfo` with the
                // proxy-resolved client address.
                let cancel_token = rest_cancel_token.clone();
                if let Err(e) = axum::serve(
                    listener,
                    ServiceExt::<axum::extract::Request>::into_make_service_with_connect_info::<
                        SocketAddr,
                    >(rest_app),
                )
                .with_graceful_shutdown(async move {
                    rest_cancel_token.cancelled().await;
                })
                .await
                {
                    error!("Public REST API listener error: {:#}", e);
                    cancel_token.cancel();
                }
            });
        }
        _ => {
            // TODO: implement spiffe listener for public IF
            error!("only HTTP is supported for public interface");
        }
    }
    Ok(())
}

/// Start the SPIFFE mTLS listener on the internal interface, when configured.
///
/// Returns an error if the internal interface is configured with a listener
/// type other than SPIFFE — that is a startup-time misconfiguration, not a
/// condition to silently continue past.
fn spawn_internal_listener(
    cfg: &Config,
    app: Router,
    token: &CancellationToken,
    handles: &mut tokio::task::JoinSet<()>,
) -> Result<(), Report> {
    if let Some(internal_if) = &cfg.interface_internal {
        match &internal_if.listener {
            ListenerConfig::Spiffe(spiffe) => {
                // Spiffe listener
                let rest_addr = internal_if.tcp_address;
                let rest_app = app;
                let rest_cancel_token = token.clone();
                let rest_spiffe_trust_domains = spiffe.trust_domains.clone();

                handles.spawn(async move {
                    let cancel_token = rest_cancel_token.clone();
                    if let Err(e) = spiffe_tls::start_axum_app(
                        rest_addr,
                        rest_app,
                        rest_cancel_token,
                        rest_spiffe_trust_domains,
                        Interface::Internal,
                    )
                    .await
                    {
                        error!("Internal REST API interface listener error: {:#}", e);
                        cancel_token.cancel();
                    }
                });
            }
            _ => {
                return Err(eyre::eyre!(
                    "only SPIFFE is supported for internal interface"
                ));
            }
        }
    }
    Ok(())
}

/// Start the SPIFFE mTLS listener on the admin Unix-domain-socket interface,
/// when configured.
fn spawn_admin_listener(
    cfg: &Config,
    app: Router,
    token: &CancellationToken,
    handles: &mut tokio::task::JoinSet<()>,
) {
    if let Some(admin_if) = &cfg.interface_admin {
        // admin spiffe UDS listener
        let socket_path = admin_if.listener.socket_path.clone();
        let rest_app = app;
        let rest_cancel_token = token.clone();
        let rest_spiffe_trust_domains = admin_if.listener.trust_domains.clone();
        let peer_uid = admin_if.listener.peer_uid;
        let peer_gid = admin_if.listener.peer_gid;

        handles.spawn(async move {
            let cancel_token = rest_cancel_token.clone();
            if let Err(e) = spiffe_tls_uds::start_axum_app(
                socket_path.as_path(),
                rest_app,
                rest_cancel_token,
                rest_spiffe_trust_domains,
                Interface::Admin,
                peer_uid,
                peer_gid,
            )
            .await
            {
                error!("Admin interface listener error: {:#}", e);
                cancel_token.cancel();
                // remove the socket also when an error was raised.
                tokio::fs::remove_file(&socket_path).await.ok();
            }
        });
    }
}

/// Prometheus scrape endpoint — returns the three audit counters plus the
/// ADR 0025 `keystone_auth_plugin_load_failure{plugin_name}` counter in text
/// exposition format (v0.0.4). No authentication required; operators are
/// expected to firewall `:5000/metrics` (or expose it only on an internal
/// interface).
async fn metrics_handler(State(state): State<ServiceState>) -> impl IntoResponse {
    let mut body =
        openstack_keystone_audit::metrics::format_prometheus_text(&state.audit_dispatcher);
    body.push_str(
        &openstack_keystone_core::auth_plugin_startup::format_load_failure_metrics(
            &*state.auth_plugin_load_failures.read().await,
        ),
    );
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

async fn cleanup(cancel: CancellationToken, state: ServiceState) {
    let mut interval = time::interval(Duration::from_secs(60));
    interval.tick().await;
    info!("Start the periodic cleanup thread");
    loop {
        tokio::select! {
            _ = interval.tick() => {
                trace!("cleanup job tick");
                if let Err(e) = state.provider.get_federation_provider().cleanup(&ExecutionContext::internal(&state)).await {
                    error!("Error during cleanup job: {}", e);
                }
                // ADR 0025 §7: shrink each loaded auth plugin's per-source
                // rate-limit keyed store - unbounded otherwise, since every
                // distinct source address bound 1 sees allocates an entry
                // `governor` never expires on its own.
                for limiter in state.auth_plugin_limiters.read().await.values() {
                    limiter.shrink_idle_sources();
                }
                // ADR-0022 §Consequences: evict stale entries from the
                // global rate-limit keyed state stores, preventing
                // unbounded memory growth under adversarial unique-key
                // flooding. Shares this task's tick rather than running on
                // its own timer - both are best-effort, minute-scale
                // housekeeping over independent state.
                state.rate_limiters.retain_recent();
            },
            () = cancel.cancelled() => {
                info!("Cancellation requested. Stopping cleanup task.");
                break; // Exit the loop
            }
        }
    }
}

/// Clear the dummy-password-hash cache on every configuration reload.
///
/// Subscribes to `ConfigManager::notify_tx` — the broadcast channel the config
/// watcher fires `()` on after each successful `Config::load_all()`. On every
/// notification we drop all cached `(algorithm, rounds)` dummy hashes so the
/// next authentication of a non-existent user recomputes one matching the new
/// configuration. A lagged receiver (more than the channel's 16-slot buffer of
/// reloads occurred between ticks) is treated like a normal reload: we still
/// clear the cache, which is always safe.
async fn reset_dummy_hash_on_reload(cancel: CancellationToken, state: ServiceState) {
    let mut reload_rx = state.config_manager.notify_tx.subscribe();
    loop {
        tokio::select! {
            recv = reload_rx.recv() => {
                match recv {
                    Ok(()) => {
                        debug!("Configuration reloaded; clearing dummy-hash cache");
                        openstack_keystone_core::common::password_hashing::reset_dummy_hash_cache()
                            .await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        // We fell behind the reload stream; the cache may hold
                        // entries for a superseded config. Clearing is the safe
                        // response regardless of how many ticks we missed.
                        warn!(skipped, "Lagged behind config reloads; clearing dummy-hash cache");
                        openstack_keystone_core::common::password_hashing::reset_dummy_hash_cache()
                            .await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        // Sender dropped — config manager is gone, nothing more to do.
                        break;
                    }
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
/// previous validated limiter and its counters. Initial configuration remains
/// fail-hard in [`KeystoneServiceState::new`].
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
                            Err(error) => {
                                error!(
                                    %error,
                                    "Invalid rate-limit configuration reload; retaining last-known-good state"
                                );
                            }
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

/// Install shutdown and interrupt signal handler.
async fn shutdown_signal(state: ServiceState) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .inspect_err(|e| error!("failed to install Ctrl+C handler: {e}"))
            .ok();
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) = signal::unix::signal(signal::unix::SignalKind::terminate())
            .inspect_err(|e| error!("failed to install signal handler: {e}"))
        {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {state.terminate().await.ok();},
        () = terminate => {state.terminate().await.ok();},
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use http_body_util::BodyExt as _;
    use sea_orm::DatabaseConnection;
    use tower::ServiceExt as _;

    use openstack_keystone_core::keystone::Service;
    use openstack_keystone_core::policy::MockPolicy;
    use openstack_keystone_core::provider::Provider;

    use super::*;

    /// Build a `ServiceState` with a disconnected DB and mocked
    /// provider/policy/audit components — mirrors
    /// `openstack_keystone_core::tests::get_mocked_state`, which is
    /// `#[cfg(test)]`-gated inside the `core` crate and therefore not
    /// visible from this crate.
    async fn test_state(cfg: Config) -> ServiceState {
        Arc::new(
            Service::new(
                ConfigManager::not_watched(cfg),
                DatabaseConnection::Disconnected,
                Provider::mocked_builder().build().unwrap(),
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        )
    }

    fn test_config(spool_dir: PathBuf) -> Config {
        let mut cfg = Config::default();
        cfg.audit.spool_dir = spool_dir;
        cfg.audit.node_id = "test-node".into();
        cfg
    }

    // Regression test for https://github.com/juhaku/utoipa/issues/1467:
    // wrapping SwaggerUi in `NormalizePathLayer` turns its internal
    // "/swagger-ui" -> "/swagger-ui/" redirect into an infinite loop, because
    // the layer strips the trailing slash the redirect just added before
    // SwaggerUi's own router ever sees it. `build_router` keeps SwaggerUi
    // outside the normalized service (mounted via `fallback_service`), so a
    // direct request to "/swagger-ui/" must resolve without another redirect.
    #[tokio::test]
    async fn build_router_serves_swagger_ui_without_redirect_loop() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(test_config(tmp.path().to_path_buf())).await;
        let token = CancellationToken::new();
        let (main_router, _main_api) = api::openapi_router().split_for_parts();
        let openapi = api::ApiDoc::openapi();

        let app = build_router(&state, &token, main_router, openapi)
            .await
            .expect("router assembly succeeds");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/swagger-ui/")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "expected swagger-ui to serve directly, not redirect (utoipa#1467 regression)"
        );
    }

    // A path handled by NormalizePathLayer's remit (issue #734): a route
    // registered without a trailing slash must still resolve when the client
    // requests it with one, and vice versa, since the layer wraps everything
    // except SwaggerUi.
    #[tokio::test]
    async fn build_router_normalizes_trailing_slash_on_api_routes() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(test_config(tmp.path().to_path_buf())).await;
        let token = CancellationToken::new();
        let (main_router, _main_api) = api::openapi_router().split_for_parts();
        let openapi = api::ApiDoc::openapi();

        let app = build_router(&state, &token, main_router, openapi)
            .await
            .expect("router assembly succeeds");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics/")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // "/metrics" is registered without a trailing slash; NormalizePathLayer
        // must still route "/metrics/" to it rather than 404ing.
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn init_audit_generates_and_reuses_kek() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path().to_path_buf());

        init_audit(&cfg).await.expect("first init generates a KEK");
        let kek_file = tmp.path().join("hmac-key.bin");
        let generated = std::fs::read(&kek_file).expect("KEK file was written");
        assert_eq!(generated.len(), 32);

        // A second init on the same spool_dir must reuse the persisted KEK
        // rather than silently regenerating it (which would invalidate any
        // spooled events signed with the old key).
        init_audit(&cfg).await.expect("second init reuses the KEK");
        let reused = std::fs::read(&kek_file).unwrap();
        assert_eq!(generated, reused);
    }

    #[tokio::test]
    async fn init_audit_rejects_wrong_length_kek() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path().to_path_buf());
        std::fs::create_dir_all(&cfg.audit.spool_dir).unwrap();
        std::fs::write(cfg.audit.spool_dir.join("hmac-key.bin"), b"too-short").unwrap();

        match init_audit(&cfg).await {
            Ok(_) => panic!("expected init_audit to reject a wrong-length KEK"),
            Err(e) => assert!(e.to_string().contains("expected 32")),
        }
    }
}
