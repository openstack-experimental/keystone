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

//! Per-interface listener startup (public REST, internal SPIFFE mTLS,
//! metrics/health, admin UDS) and the Prometheus scrape handler.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Extension, Router, ServiceExt,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
};
use color_eyre::eyre::{Report, Result};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{error, info};

use super::{Startup, router};
use crate::api;
use crate::config::{Interface, ListenerConfig};
use crate::server::http_metrics::format_prometheus_text as format_http_metrics_text;
use crate::server::http_metrics::{HttpMetrics, record_http_metrics};
use crate::server::listener::{spiffe_tls, spiffe_tls_uds};
use openstack_keystone_core::keystone::ServiceState;

/// Start the public HTTP REST API listener.
pub async fn spawn_public(
    startup: &Startup,
    app: Router,
    handles: &mut JoinSet<()>,
) -> Result<(), Report> {
    let cfg = &startup.cfg;
    match cfg.interface_public.listener {
        ListenerConfig::Http => {}
        _ => {
            // TODO: implement spiffe listener for public IF
            error!("only HTTP is supported for public interface");
            return Ok(());
        }
    }

    info!("Starting Rest API at {}", cfg.interface_public.tcp_address);
    let listener = TcpListener::bind(&cfg.interface_public.tcp_address).await?;
    let rest_cancel_token = startup.token.clone();
    // When operating behind a trusted reverse proxy (config-gated, off by
    // default), parse the selected forwarding header and rewrite the
    // raw-peer `ConnectInfo` with the client *before* the tracing span and
    // handlers read it. Added only on this public interface.
    let rest_app = router::with_proxy_headers(app, cfg);

    handles.spawn(async move {
        // `rest_app` is a `Router` whose fallback is the
        // `NormalizePath`-wrapped API service (issue #734, #1467); use
        // axum's `ServiceExt` with an explicit request type to satisfy
        // inference (E0284).
        //
        // `into_make_service_with_connect_info::<SocketAddr>` stores the raw
        // TCP peer address in a `ConnectInfo<SocketAddr>` extension (the
        // analogue of Python Keystone's WSGI REMOTE_ADDR). Behind a
        // proxy/LB this is the proxy's address; the `rewrite_client_addr`
        // layer wired above preserves this raw value separately before
        // overwriting `ConnectInfo` with the proxy-resolved client address.
        let cancel_token = rest_cancel_token.clone();
        if let Err(e) = axum::serve(
            listener,
            ServiceExt::<axum::extract::Request>::into_make_service_with_connect_info::<SocketAddr>(
                rest_app,
            ),
        )
        .with_graceful_shutdown(async move {
            rest_cancel_token.cancelled().await;
        })
        .await
        {
            error!("Public REST API listener error: {:#}", e);
            cancel_token.cancel();
        }
        tracing::debug!("Public REST API task exited");
    });
    Ok(())
}

/// Start the SPIFFE mTLS listener on the internal interface, when configured.
///
/// Returns an error if the internal interface is configured with a listener
/// type other than SPIFFE — that is a startup-time misconfiguration, not a
/// condition to silently continue past.
pub fn spawn_internal(
    startup: &Startup,
    app: Router,
    handles: &mut JoinSet<()>,
) -> Result<(), Report> {
    let Some(internal_if) = &startup.cfg.interface_internal else {
        return Ok(());
    };
    let ListenerConfig::Spiffe(spiffe) = &internal_if.listener else {
        return Err(eyre::eyre!(
            "only SPIFFE is supported for internal interface"
        ));
    };

    let rest_addr = internal_if.tcp_address;
    let rest_cancel_token = startup.token.clone();
    let rest_spiffe_trust_domains = spiffe.trust_domains.clone();

    handles.spawn(async move {
        let cancel_token = rest_cancel_token.clone();
        if let Err(e) = spiffe_tls::start_axum_app(
            rest_addr,
            app,
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
    Ok(())
}

/// Start the metrics and health interface listener on a dedicated port.
pub async fn spawn_metrics(
    startup: &Startup,
    http_metrics: Option<&Arc<HttpMetrics>>,
    handles: &mut JoinSet<()>,
) -> Result<(), Report> {
    let cfg = &startup.cfg;
    let state = &startup.state;
    info!(
        "Starting metrics/health API at {}",
        cfg.interface_metrics.tcp_address
    );
    let listener = TcpListener::bind(&cfg.interface_metrics.tcp_address).await?;
    let cancel_token = startup.token.clone();

    let (metrics_router, _) = api::metrics_router().split_for_parts();
    let mut metrics_app = Router::new()
        .merge(metrics_router.with_state(state.clone()))
        .route("/metrics", axum::routing::get(metrics_handler))
        .with_state(state.clone());
    if let Some(http_metrics) = http_metrics {
        // Same reverse-order caveat as `router::build`: `from_fn` must be
        // added first (innermost) so both `Extension` layers, added after,
        // run before it.
        metrics_app = metrics_app
            .layer(axum::middleware::from_fn(record_http_metrics))
            .layer(Extension(Interface::Metrics))
            .layer(Extension(http_metrics.clone()));
    }

    handles.spawn(async move {
        if let Err(e) = axum::serve(listener, metrics_app.into_make_service())
            .with_graceful_shutdown(async move {
                cancel_token.cancelled().await;
            })
            .await
        {
            error!("Metrics/health listener error: {:#}", e);
        }
    });
    Ok(())
}

/// Start the SPIFFE mTLS listener on the admin Unix-domain-socket interface,
/// when configured.
pub fn spawn_admin(startup: &Startup, app: Router, handles: &mut JoinSet<()>) {
    let Some(admin_if) = &startup.cfg.interface_admin else {
        return;
    };
    let socket_path = admin_if.listener.socket_path.clone();
    let rest_cancel_token = startup.token.clone();
    let rest_spiffe_trust_domains = admin_if.listener.trust_domains.clone();
    let peer_uid = admin_if.listener.peer_uid;
    let peer_gid = admin_if.listener.peer_gid;

    handles.spawn(async move {
        let cancel_token = rest_cancel_token.clone();
        if let Err(e) = spiffe_tls_uds::start_axum_app(
            socket_path.as_path(),
            app,
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

/// Prometheus scrape endpoint — returns the audit counters, the ADR 0025
/// `keystone_auth_plugin_load_failure{plugin_name}` counter, and (when
/// enabled) the HTTP request metrics in text exposition format (v0.0.4). No
/// authentication required; operators firewall this port.
pub async fn metrics_handler(
    State(state): State<ServiceState>,
    http_metrics: Option<Extension<Arc<HttpMetrics>>>,
) -> impl IntoResponse {
    let mut body =
        openstack_keystone_audit::metrics::format_prometheus_text(&state.audit_dispatcher);
    body.push_str(&crate::auth_plugin_startup::format_load_failure_metrics(
        &*state.auth_plugin_load_failures.read().await,
    ));
    if let Some(Extension(http_metrics)) = http_metrics {
        body.push_str(&format_http_metrics_text(&http_metrics));
    }
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

#[cfg(test)]
#[path = "listeners/tests.rs"]
mod tests;
