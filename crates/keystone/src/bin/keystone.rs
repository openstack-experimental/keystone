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
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router, ServiceExt,
    extract::{ConnectInfo, DefaultBodyLimit},
    http::{self, HeaderName, Request, header},
};
use clap::{Parser, ValueEnum};
use color_eyre::eyre::{Report, Result, WrapErr};
use sea_orm::{ConnectOptions, Database};
use secrecy::ExposeSecret;
use tokio::net::TcpListener;
use tokio::{signal, spawn, time};
use tokio_util::sync::CancellationToken;
// `Layer` imported anonymously: its `.layer()` method is needed to wrap the
// Router, but the name is already taken by `tracing_subscriber::Layer` below.
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
use openstack_keystone::catalog::CatalogHook;
use openstack_keystone::config::{ConfigManager, Interface, ListenerConfig};
use openstack_keystone::federation::FederationHook;
use openstack_keystone::identity::IdentityHook;
use openstack_keystone::idmapping::IdMappingHook;
use openstack_keystone::k8s_auth::K8sAuthHook;
use openstack_keystone::k8s_auth_client::KeystoneK8sHttpClient;
use openstack_keystone::keystone::Service as KeystoneServiceState;
use openstack_keystone::keystone::ServiceState;
use openstack_keystone::plugin_manager::PluginManager;
use openstack_keystone::policy::HttpPolicyEnforcer;
use openstack_keystone::provider::Provider;
use openstack_keystone::resource::ResourceHook;
use openstack_keystone::revoke::RevokeHook;
use openstack_keystone::role::RoleHook;
use openstack_keystone::server::listener::{raft_grpc, spiffe_tls, spiffe_tls_uds};
use openstack_keystone::token::TokenHook;
use openstack_keystone::trust::TrustHook;
use openstack_keystone::webauthn;
use openstack_keystone::{api, common};
use openstack_keystone_core::db::sync_schema;
use openstack_keystone_core::error::KeystoneError;
use openstack_keystone_distributed_storage::{StorageApi, app::Storage};

// Default body limit 256kB
const DEFAULT_BODY_LIMIT: usize = 1024 * 256;

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

    let stderr_log_filter = Targets::new()
        .with_default(match args.verbose {
            0 => LevelFilter::WARN,
            1 => LevelFilter::INFO,
            2 => LevelFilter::DEBUG,
            _ => LevelFilter::TRACE,
        })
        .with_target(
            "openraft",
            match args.verbose {
                0 | 1 => LevelFilter::WARN,
                _ => LevelFilter::INFO,
            },
        )
        .with_target(
            "lsm_tree",
            match args.verbose {
                0 | 1 => LevelFilter::WARN,
                2 => LevelFilter::INFO,
                _ => LevelFilter::DEBUG,
            },
        );

    // Build the stderr log layer.
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .with_filter(stderr_log_filter)
        .boxed();

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

    let mut log_layers = Vec::new();

    if cfg.default.use_stderr {
        log_layers.push(stderr_layer);
    }

    let non_blocking;
    let _guard;

    if let Some(log_dir) = &cfg.default.log_dir {
        // create a file appender that rotates hourly
        let file_appender = tracing_appender::rolling::never(log_dir, "keystone.log");
        // make the file appender non-blocking
        // the guard exists outside the scope to make sure buffered logs get flushed to
        // output
        (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
        log_layers.push(
            tracing_subscriber::fmt::layer()
                // No colors in the log file
                .with_ansi(false)
                .with_writer(non_blocking)
                .with_filter(if cfg.default.debug {
                    LevelFilter::DEBUG
                } else {
                    LevelFilter::INFO
                })
                .boxed(),
        );
    }
    // build the tracing registry
    tracing_subscriber::registry()
        .with(ErrorLayer::default())
        .with(log_layers)
        .init();
    color_eyre::install()?;

    info!("Starting Keystone...");

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

    let plugin_manager = PluginManager::with_config(&cfg);
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
        Some(Arc::new(storage))
    } else {
        None
    };

    let storage_for_service: Option<Arc<dyn StorageApi>> = concrete_storage
        .as_ref()
        .map(Arc::clone)
        .map(|s| s as Arc<dyn StorageApi>);

    let shared_state = Arc::new(
        KeystoneServiceState::new(
            cfg_mgr,
            conn,
            provider,
            Arc::new(policy),
            storage_for_service,
        )
        .await?,
    );

    spawn(cleanup(cloned_token.clone(), shared_state.clone()));
    // Evict stale entries from rate-limit keyed state stores every 60 s
    // (ADR-0022 §Consequences: memory overhead and store eviction).
    spawn(rate_limit_eviction(cloned_token, shared_state.clone()));

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

    let x_request_id = HeaderName::from_static("x-openstack-request-id");
    let sensitive_headers: Arc<[_]> = vec![
        header::AUTHORIZATION,
        header::COOKIE,
        header::HeaderName::from_static("x-auth-token"),
        header::HeaderName::from_static("x-subject-token"),
    ]
    .into();

    let middleware = ServiceBuilder::new()
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
                    // Raw TCP peer address captured by
                    // `into_make_service_with_connect_info` on the public
                    // listener (the keystone-ng analogue of Python Keystone's
                    // WSGI REMOTE_ADDR / flask.request.remote_addr). `None` for
                    // the SPIFFE interfaces, which do not populate ConnectInfo.
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

    let mut app = Router::new().merge(main_router.with_state(shared_state.clone()));

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

    app = app
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", openapi))
        .layer(middleware);

    // Serve a path with or without a trailing slash from the same handler
    // (matches Python Keystone, see issue #734). NormalizePathLayer rewrites
    // the request URI *before* routing, so it must wrap the Router from the
    // outside, not be added via Router::layer() (which runs *after* route
    // matching, by which point "/v3/users/" has already failed to match the
    // "/v3/users" route). No HTTP redirect is involved.
    // https://docs.rs/tower-http/latest/tower_http/normalize_path/index.html
    let app = NormalizePathLayer::trim_trailing_slash().layer(app);

    // Shutdown watcher
    let global_shutdown_token = token.clone();
    let signal_state = shared_state.clone();
    tokio::spawn(async move {
        // Your existing handler that takes Arc<AppState>
        // Instead of calling handle.graceful_shutdown, just cancel the token
        shutdown_signal(signal_state).await;
        global_shutdown_token.cancel();
    });

    let mut handles = tokio::task::JoinSet::new();

    // Raft
    if cfg.distributed_storage.is_some() {
        let raft_cancel_token = token.clone();
        let raft_config = cfg.clone();
        let raft_storage = concrete_storage.as_ref().expect("storage is None").clone();
        handles.spawn(async move {
            raft_grpc::start_raft_app(raft_storage, raft_config, raft_cancel_token)
                .await
                .unwrap()
        });
        raft_grpc::ensure_raft_initialized(shared_state.clone(), cfg.clone()).await?;
    }

    // OPA Subprocess
    if let Some(policies_path) = &cfg.api_policy.opa_policies_path {
        let opa_url = &cfg.api_policy.opa_base_url;
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
            .kill_on_drop(true);

        match opa_cmd.spawn() {
            Ok(mut child) => {
                let opa_cancel_token = token.clone();
                handles.spawn(async move {
                    tokio::select! {
                        status = child.wait() => {
                            error!("OPA subprocess exited unexpectedly: {:?}", status);
                        }
                        () = opa_cancel_token.cancelled() => {
                            info!("Killing OPA subprocess");
                            child.kill().await.ok();
                        }
                    }
                });
            }
            Err(e) => {
                error!("Failed to start OPA subprocess: {}", e);
                return Err(e).wrap_err("Failed to start OPA subprocess");
            }
        }
    }

    // Start the public interface listener
    match cfg.interface_public.listener {
        ListenerConfig::Http => {
            info!("Starting Rest API at {}", cfg.interface_public.tcp_address);
            let listener = TcpListener::bind(&cfg.interface_public.tcp_address).await?;
            let rest_cancel_token = token.clone();
            let rest_app = app.clone();
            handles.spawn(async move {
                // `rest_app` is `NormalizePath<Router>` (issue #734 wraps the
                // Router from the outside), which has no
                // `Router::into_make_service_with_connect_info`; use axum's
                // `ServiceExt` (blanket-impl'd for any `Service`) with an
                // explicit request type to satisfy inference (E0284).
                //
                // `into_make_service_with_connect_info::<SocketAddr>` stores the
                // raw TCP peer address in a `ConnectInfo<SocketAddr>` request
                // extension (the analogue of Python Keystone's WSGI REMOTE_ADDR).
                // This is the *raw* peer, not proxy-resolved: behind a reverse
                // proxy/LB it is the proxy's address. A trusted forwarded-header
                // layer (mirroring oslo_middleware's `enable_proxy_headers_parsing`,
                // off by default) is a deliberate follow-up before this is used
                // for any IP-based login control. See issue #358.
                axum::serve(
                    listener,
                    ServiceExt::<axum::extract::Request>::into_make_service_with_connect_info::<
                        SocketAddr,
                    >(rest_app),
                )
                .with_graceful_shutdown(async move {
                    rest_cancel_token.cancelled().await;
                })
                .await
                .unwrap();
            });
        }
        _ => {
            // TODO: implement spiffe listener for public IF
            error!("only HTTP is supported for public interface");
        }
    }

    // Start listener on the internal interface when necessary
    if let Some(internal_if) = &cfg.interface_internal {
        match &internal_if.listener {
            ListenerConfig::Spiffe(spiffe) => {
                // Spiffe listener
                let rest_addr = internal_if.tcp_address;
                let rest_app = app.clone();
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
                error!("only SPIFFE is supported for internal interface");
            }
        }
    }

    if let Some(admin_if) = &cfg.interface_admin {
        // admin spiffe UDS listener
        let socket_path = admin_if.listener.socket_path.clone();
        let rest_app = app.clone();
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

    // Wait for both (or handle errors)
    handles.join_all().await;
    token.cancel();
    Ok(())
}

async fn cleanup(cancel: CancellationToken, state: ServiceState) {
    let mut interval = time::interval(Duration::from_secs(60));
    interval.tick().await;
    info!("Start the periodic cleanup thread");
    loop {
        tokio::select! {
            _ = interval.tick() => {
                trace!("cleanup job tick");
                if let Err(e) = state.provider.get_federation_provider().cleanup(&state).await {
                    error!("Error during cleanup job: {}", e);
                }
            },
            () = cancel.cancelled() => {
                info!("Cancellation requested. Stopping cleanup task.");
                break; // Exit the loop
            }
        }
    }
}

/// Periodically evict stale entries from rate-limit keyed state stores.
///
/// Runs every 60 seconds, mirroring the [`cleanup`] task pattern. Calls
/// [`RateLimitState::retain_recent`] on all active buckets so that keys that
/// have not been seen within the last quota window are removed, preventing
/// unbounded memory growth under adversarial unique-key flooding (ADR-0022
/// §Consequences: memory overhead and store eviction).
async fn rate_limit_eviction(cancel: CancellationToken, state: ServiceState) {
    let mut interval = time::interval(Duration::from_secs(60));
    interval.tick().await;
    info!("Start the rate-limit eviction task");
    loop {
        tokio::select! {
            _ = interval.tick() => {
                trace!("rate-limit eviction tick");
                state.rate_limiters.retain_recent();
            },
            () = cancel.cancelled() => {
                info!("Cancellation requested. Stopping rate-limit eviction task.");
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
