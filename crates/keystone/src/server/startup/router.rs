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

//! Axum application assembly: route merge, middleware stack, HTTP-metrics
//! layer, and the `NormalizePathLayer`/Swagger-UI wrapping.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Extension, Router,
    extract::{ConnectInfo, DefaultBodyLimit},
    http::{self, HeaderName, Request, header},
    middleware,
};
use color_eyre::eyre::{Report, Result};
use tower::util::MapRequestLayer;
use tower::{Layer as _, ServiceBuilder};
use tower_http::{
    ServiceBuilderExt,
    normalize_path::NormalizePathLayer,
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::{DefaultOnRequest, TraceLayer},
};
use tracing::{Level, info, info_span};
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

use super::Startup;
use crate::server::access_log::log_request;
use crate::server::error_log::log_error_body;
use crate::server::http_metrics::{HttpMetrics, record_http_metrics};
use crate::server::{proxy_headers, request_cache};
use crate::{common, scim, webauthn};
use openstack_keystone_core::keystone::ServiceState;

// Default body limit 256kB
const DEFAULT_BODY_LIMIT: usize = 1024 * 256;

/// A `MakeRequestId` that mints a fresh `req-<uuid>` per request.
#[derive(Clone, Default)]
pub struct OpenStackRequestId {}

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

/// Assemble the full Axum application: merges the `OpenAPI`-generated
/// routes, optional `WebAuthN` extension, and SCIM ingress sub-router;
/// layers on request-id/tracing/compression middleware; then wraps the
/// result in `NormalizePathLayer` with Swagger UI mounted outside the
/// normalization boundary.
///
/// Serving a path with or without a trailing slash from the same handler
/// (matches Python Keystone, see issue #734) requires `NormalizePathLayer`
/// to rewrite the request URI *before* routing, so it must wrap the Router
/// from the outside, not be added via `Router::layer()`.
///
/// SwaggerUi is deliberately merged in *after* normalization and kept out of
/// the normalized service: SwaggerUi's own handler issues an internal
/// redirect between "/swagger-ui" and "/swagger-ui/", and trimming the
/// trailing slash before that handler runs turns the redirect into an
/// infinite loop. <https://github.com/juhaku/utoipa/issues/1467>.
pub async fn build(
    startup: &Startup,
    main_router: Router<ServiceState>,
    openapi: utoipa::openapi::OpenApi,
) -> Result<(Router, Option<Arc<HttpMetrics>>), Report> {
    let state = &startup.state;
    let mut app = Router::new().merge(main_router.with_state(state.clone()));
    app = mount_extensions(app, startup).await?;
    app = apply_middleware(app);
    let (app, http_metrics) = attach_http_metrics(app, state).await;
    Ok((finalize(app, openapi), http_metrics))
}

/// Nest the config-gated `WebAuthN` extension (`/v4`) and the always-on SCIM
/// ingress sub-router (`/SCIM/v2`, ADR 0021 §4 — kept separate so only these
/// routes accept API-Key bearer tokens).
async fn mount_extensions(mut app: Router, startup: &Startup) -> Result<Router, Report> {
    let state = &startup.state;
    if state.config_manager.config.read().await.webauthn.enabled {
        let webauthn_extension =
            webauthn::api::init_extension(state.clone(), startup.token.clone()).await?;
        app = app.nest("/v4", webauthn_extension);
    } else {
        info!("Not enabling the WebAuthN extension due to the `config.webauthn.enabled` flag.");
    }
    app = app.nest("/SCIM/v2", scim::router().with_state(state.clone()));
    Ok(app)
}

/// Build and apply the shared request/response middleware stack (request-id
/// minting, per-request cache scope, body limit, tracing span, access/error
/// logging, compression, request-id propagation).
///
/// The `ServiceBuilder` runs top-to-bottom; it stays a local rather than a
/// named return type because the composed tower type is effectively
/// unwriteable.
fn apply_middleware(app: Router) -> Router {
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
        // Strip any client-supplied x-openstack-request-id before
        // SetRequestIdLayer runs, so we always generate a fresh
        // server-controlled UUID (ADR 0023 §2.1).
        .layer(MapRequestLayer::new(move |mut req: Request<_>| {
            req.headers_mut().remove(strip_x_request_id.clone());
            req
        }))
        // Inject x-request-id before the request reaches `TraceLayer`.
        .layer(SetRequestIdLayer::new(
            x_request_id.clone(),
            OpenStackRequestId::default(),
        ))
        // Establish the per-request cache scope (ADR 0030) before any
        // handler runs.
        .layer(middleware::from_fn(request_cache::with_request_cache))
        .sensitive_request_headers(sensitive_headers.clone())
        .layer(DefaultBodyLimit::max(DEFAULT_BODY_LIMIT))
        .layer(
            TraceLayer::new(common::KeystoneResponseClassifier)
                .make_span_with(|request: &Request<_>| {
                    // Client address captured into `ConnectInfo<SocketAddr>`
                    // (the keystone-ng analogue of Python Keystone's WSGI
                    // REMOTE_ADDR): the raw TCP peer on the public listener,
                    // or the mTLS peer on the internal SPIFFE-TLS listener.
                    // When `enable_proxy_headers_parsing` is on, the public
                    // value has been overwritten with the proxy-resolved
                    // client address. `None` on the admin UDS interface.
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
                // `on_response` alone is enough at INFO for one line per
                // request; keep the start-of-request event at DEBUG.
                .on_request(DefaultOnRequest::new().level(Level::DEBUG))
                // Finish-of-request logging is done by `log_request` below.
                .on_response(()),
        )
        // One INFO line per request with method/uri/request-id/status/
        // latency folded into the message text. Must stay after TraceLayer
        // so it runs inside the request span.
        .layer(middleware::from_fn(log_request))
        // Logs the body of any 4xx/5xx response. Must stay before
        // `.compression()` so it reads the body while it's still plain JSON.
        .layer(middleware::from_fn(log_error_body))
        .compression()
        .sensitive_response_headers(sensitive_headers)
        // Propagate the header to the response before it reaches `TraceLayer`.
        .layer(PropagateRequestIdLayer::new(x_request_id));

    app.layer(middleware)
}

/// Add the request-count/latency metrics layer when
/// `[interface_metrics] http_requests_enabled` is set, returning the shared
/// [`HttpMetrics`] handle so the `/metrics` scrape handler can render it.
async fn attach_http_metrics(
    mut app: Router,
    state: &ServiceState,
) -> (Router, Option<Arc<HttpMetrics>>) {
    if !state
        .config_manager
        .config
        .read()
        .await
        .interface_metrics
        .http_requests_enabled
    {
        return (app, None);
    }
    let http_metrics = Arc::new(HttpMetrics::new());
    // `Router::layer()` applies in reverse call order (last-added is
    // outermost) — `Extension` must be added *after* `from_fn` so it runs
    // first and the extractor inside `record_http_metrics` has something to
    // read.
    app = app
        .layer(middleware::from_fn(record_http_metrics))
        .layer(Extension(http_metrics.clone()));
    (app, Some(http_metrics))
}

/// Wrap the assembled app in `NormalizePathLayer` and mount Swagger UI
/// outside that boundary (see the module and [`build`] docs for why).
fn finalize(app: Router, openapi: utoipa::openapi::OpenApi) -> Router {
    let normalized_app = NormalizePathLayer::trim_trailing_slash().layer(app);
    Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", openapi))
        .fallback_service(normalized_app)
}

/// Apply the public-interface reverse-proxy header rewrite layer to `app`
/// when `[oslo_middleware] enable_proxy_headers_parsing` is on. Split out so
/// the public listener can call it without duplicating the config plumbing.
pub(crate) fn with_proxy_headers(app: Router, cfg: &crate::config::Config) -> Router {
    if !cfg.oslo_middleware.enable_proxy_headers_parsing {
        return app;
    }
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
}

#[cfg(test)]
#[path = "router/tests.rs"]
mod tests;
