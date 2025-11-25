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

use axum::extract::DefaultBodyLimit;
use axum::http::{self, HeaderName, Request, header};
use clap::{Parser, ValueEnum};
use color_eyre::eyre::{Report, Result};
use eyre::WrapErr;
use sea_orm::{ConnectOptions, Database};
use secrecy::ExposeSecret;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::{net::TcpListener, signal, spawn, time};
use tokio_util::sync::CancellationToken;
use tower::ServiceBuilder;
use tower_http::{
    LatencyUnit, ServiceBuilderExt,
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::{Level, debug, error, info, info_span, trace};
use tracing_subscriber::{
    Layer,
    filter::{LevelFilter, Targets},
    prelude::*,
};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

use openstack_keystone::api;
use openstack_keystone::config::Config;
use openstack_keystone::error::KeystoneError;
use openstack_keystone::federation::FederationApi;
use openstack_keystone::keystone::{Service, ServiceState};
use openstack_keystone::plugin_manager::PluginManager;
use openstack_keystone::policy::PolicyFactory;
use openstack_keystone::provider::Provider;

// Default body limit 256kB
const DEFAULT_BODY_LIMIT: usize = 1024 * 256;

/// `OpenStack` Keystone.
///
/// Keystone is an `OpenStack` service that provides API client authentication, service discovery,
/// and distributed multi-tenant authorization by implementing OpenStack’s Identity API.
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

#[tokio::main]
async fn main() -> Result<(), Report> {
    let args = Args::parse();

    let filter = Targets::new()
        .with_default(match args.verbose {
            0 => LevelFilter::WARN,
            1 => LevelFilter::INFO,
            2 => LevelFilter::DEBUG,
            _ => LevelFilter::TRACE,
        })
        .with_target("cranelift_codegen", Level::INFO)
        .with_target("wasmtime_codegen", Level::INFO)
        .with_target("wasmtime_cranelift", Level::INFO)
        .with_target("wasmtime::runtime", Level::INFO);

    let log_layer = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .with_filter(filter);

    // build the tracing registry
    tracing_subscriber::registry().with(log_layer).init();

    info!("Starting Keystone...");

    let openapi = api::ApiDoc::openapi();

    let (router, api) = OpenApiRouter::with_openapi(openapi.clone())
        .merge(api::openapi_router())
        .split_for_parts();

    if let Some(dump_format) = &args.dump_openapi {
        println!(
            "{}",
            match dump_format {
                OpenApiFormat::Yaml => api.to_yaml()?,
                OpenApiFormat::Json => api.to_pretty_json()?,
            }
        );
        return Ok(());
    }

    let token = CancellationToken::new();
    let cloned_token = token.clone();

    let cfg = Config::new(args.config)?;
    let opt: ConnectOptions = ConnectOptions::new(cfg.database.get_connection().expose_secret())
        // Prevent dumping the password in plaintext.
        .sqlx_logging(false)
        .to_owned();

    debug!("Establishing the database connection...");
    let conn = Database::connect(opt)
        .await
        .wrap_err("Database connection failed")?;

    let plugin_manager = PluginManager::default();

    let provider = Provider::new(cfg.clone(), plugin_manager)?;

    let policy = if let Some(opa_base_url) = &cfg.api_policy.opa_base_url {
        PolicyFactory::http(opa_base_url.clone()).await?
    } else {
        #[cfg(feature = "wasm")]
        {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("policy.wasm");
            PolicyFactory::from_wasm(&path).await?
        }
        return Err(KeystoneError::PolicyEnforcementNotAvailable)?;
    };

    let shared_state = Arc::new(Service::new(cfg, conn, provider, policy)?);

    spawn(cleanup(cloned_token, shared_state.clone()));

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
            TraceLayer::new_for_http()
                //.make_span_with(DefaultMakeSpan::new().include_headers(true))
                .make_span_with(|request: &Request<_>| {
                    info_span!(
                        "request",
                        method = ?request.method(),
                        some_other_field = tracing::field::Empty,
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

    let app = router
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api))
        .layer(middleware)
        .with_state(shared_state.clone());

    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080));
    let listener = TcpListener::bind(&address).await?;
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal(shared_state))
        .await?;

    token.cancel();
    Ok(())
}

/// Periodic cleanup job
async fn cleanup(cancel: CancellationToken, state: ServiceState) {
    let mut interval = time::interval(Duration::from_secs(60));
    interval.tick().await;
    // TODO: Clean passkeys expired states
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

/// Install shutdown and interrupt signal handler
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
