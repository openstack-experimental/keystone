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
//! # Proxy forwarded-header parsing
//!
//! When Keystone runs behind a trusted reverse proxy / load balancer, the raw
//! TCP peer captured in [`ConnectInfo<SocketAddr>`] is the proxy's address, not
//! the real client's. This middleware recovers the originating client address
//! from the standard forwarding headers and overwrites `ConnectInfo` with it,
//! so every downstream consumer (the `request` tracing span, the API-Key IP
//! allowlist, any future IP-based login control) transparently observes the
//! real client.
//!
//! It mirrors upstream Python Keystone's `[oslo_middleware]
//! enable_proxy_headers_parsing`: the [`rewrite_client_addr`] layer is only
//! wired onto the **public** listener when that flag is enabled, and it is
//! **off by default**.
//!
//! Extraction is not blind. The header is honoured only when the immediate TCP
//! peer matches the operator-configured `trusted_proxies` allowlist, and the
//! effective client is the rightmost address in the chain that is not itself a
//! trusted proxy — the same rightmost-non-trusted-proxy algorithm the API-Key
//! ingress uses ([`openstack_keystone_core::api::forwarded`]). A client able to
//! reach the listener directly therefore cannot spoof its apparent address, and
//! an empty allowlist trusts no one (the raw peer is always kept).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::extract::Request;
use axum::extract::State;
use axum::middleware::Next;
use axum::response::Response;

use openstack_keystone_core::api::forwarded::resolve_client_ip;

/// Axum middleware that overwrites the request's [`ConnectInfo<SocketAddr>`]
/// with the proxy-resolved client address when the immediate peer is a trusted
/// proxy and a forwarding header carries a different upstream client.
///
/// `trusted_proxies` is the operator-configured CIDR allowlist (`[oslo_middleware]
/// trusted_proxies`). When the resolved client equals the raw peer (direct
/// client, untrusted peer, or an all-trusted chain), `ConnectInfo` is left
/// untouched so the real source port is preserved. The recovered address has no
/// meaningful source port, so port `0` is used.
pub async fn rewrite_client_addr(
    State(trusted_proxies): State<Arc<Vec<String>>>,
    mut req: Request,
    next: Next,
) -> Response {
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());

    if let Some(client_ip) = resolve_client_ip(req.headers(), peer_ip, &trusted_proxies)
        && Some(client_ip) != peer_ip
    {
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(client_ip, 0)));
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::routing::get;
    use axum::{Router, ServiceExt as AxumServiceExt};
    use tower::ServiceExt as _;

    async fn echo(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> String {
        addr.to_string()
    }

    /// Build the app with the middleware carrying a fixed trusted-proxy list,
    /// drive it with `peer` as the raw TCP peer, and return the address the
    /// handler observed.
    async fn observed_addr(trusted: &[&str], peer: &str, headers: &[(&str, &str)]) -> String {
        let trusted = Arc::new(trusted.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let app =
            Router::new()
                .route("/echo", get(echo))
                .layer(axum::middleware::from_fn_with_state(
                    trusted,
                    rewrite_client_addr,
                ));
        let make =
            AxumServiceExt::<Request>::into_make_service_with_connect_info::<SocketAddr>(app);
        let peer: SocketAddr = peer.parse().unwrap();
        let svc = make.oneshot(peer).await.unwrap();

        let mut builder = Request::builder().uri("/echo");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let resp = svc
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn rewrites_to_client_when_peer_is_trusted() {
        // Raw peer 10.0.0.9 is a trusted proxy; the XFF chain carries the client.
        let addr = observed_addr(
            &["10.0.0.0/8"],
            "10.0.0.9:1111",
            &[("x-forwarded-for", "203.0.113.7, 10.0.0.9")],
        )
        .await;
        // Rewritten to the client IP (with the conventional port 0).
        assert_eq!(addr, "203.0.113.7:0");
    }

    #[tokio::test]
    async fn ignores_header_when_peer_is_untrusted() {
        // A direct (untrusted) client cannot spoof its address via the header;
        // the raw peer address — including its real port — is preserved.
        let addr = observed_addr(
            &["10.0.0.0/8"],
            "203.0.113.50:2222",
            &[("x-forwarded-for", "1.2.3.4")],
        )
        .await;
        assert_eq!(addr, "203.0.113.50:2222");
    }

    #[tokio::test]
    async fn preserves_peer_when_no_forwarded_header() {
        let addr = observed_addr(&["10.0.0.0/8"], "10.0.0.9:3333", &[]).await;
        // Peer is trusted but there is no header, so it stays the peer.
        assert_eq!(addr, "10.0.0.9:3333");
    }

    #[tokio::test]
    async fn empty_allowlist_trusts_no_one() {
        // With no trusted proxies configured, the header is never honoured.
        let addr = observed_addr(&[], "10.0.0.9:4444", &[("x-forwarded-for", "203.0.113.7")]).await;
        assert_eq!(addr, "10.0.0.9:4444");
    }
}
