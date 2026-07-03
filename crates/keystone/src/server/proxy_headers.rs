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
//! # Proxy forwarded-header parsing (issue #358)
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
//! enable_proxy_headers_parsing` (oslo.middleware `HTTPProxyToWSGI`): the
//! [`rewrite_client_addr`] layer is only wired onto the **public** listener
//! when that flag is enabled, and it is **off by default**. Enabling it asserts
//! that the immediate peer is a trusted proxy; a deployment not behind such a
//! proxy leaves it off and cannot be tricked into trusting a spoofed header.
//!
//! [RFC 7239] `Forwarded` is honoured first; `X-Forwarded-For` is the fallback.
//! In both the originating client is the **leftmost** entry (each proxy appends
//! the peer it received the request from), matching the trusted-proxy model.
//!
//! [RFC 7239]: https://datatracker.ietf.org/doc/html/rfc7239

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::extract::Request;
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;

/// Axum middleware that overwrites the request's [`ConnectInfo<SocketAddr>`]
/// with the proxy-resolved client address when a forwarding header is present.
///
/// Wired onto the public listener only, and only when
/// `[oslo_middleware] enable_proxy_headers_parsing` is on — so its mere
/// presence in the stack already means the operator has opted in to trusting
/// the peer's forwarding headers. The recovered address has no meaningful
/// source port, so port `0` is used.
pub async fn rewrite_client_addr(mut req: Request, next: Next) -> Response {
    if let Some(ip) = resolve_forwarded_ip(req.headers()) {
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 0)));
    }
    next.run(req).await
}

/// Resolve the originating client IP from forwarding headers, preferring
/// RFC 7239 `Forwarded` over `X-Forwarded-For`. Returns `None` when neither is
/// present or parseable (e.g. an obfuscated `for=_hidden` identifier), leaving
/// the raw peer address untouched.
fn resolve_forwarded_ip(headers: &HeaderMap) -> Option<IpAddr> {
    if let Some(ip) = headers
        .get("forwarded")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_forwarded_client)
    {
        return Some(ip);
    }

    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| parse_ip_maybe_port(s.trim()))
}

/// Extract the client IP from the leftmost element's `for=` parameter of an
/// RFC 7239 `Forwarded` header value.
fn parse_forwarded_client(value: &str) -> Option<IpAddr> {
    let first = value.split(',').next()?;
    for param in first.split(';') {
        let mut kv = param.trim().splitn(2, '=');
        let key = kv.next()?.trim();
        if key.eq_ignore_ascii_case("for") {
            let raw = kv.next()?.trim().trim_matches('"');
            return parse_ip_maybe_port(raw);
        }
    }
    None
}

/// Parse an address token that may be a bare IP, an `ip:port`, or a bracketed
/// IPv6 (`[::1]` / `[::1]:443`), returning just the IP. Obfuscated or malformed
/// tokens yield `None`.
fn parse_ip_maybe_port(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Bracketed IPv6 (RFC 7239 form), with an optional trailing port.
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        return rest[..end].parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    // `ip:port` (only unambiguous for IPv4; a bare IPv6 has many colons and is
    // handled by the bare-IP branch below).
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    // Bare IPv4 or IPv6, no port.
    s.parse::<IpAddr>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn no_headers_yields_none() {
        assert_eq!(resolve_forwarded_ip(&HeaderMap::new()), None);
    }

    #[test]
    fn xff_takes_leftmost_originating_client() {
        // client, proxy1, proxy2 — leftmost is the origin.
        let h = headers(&[("x-forwarded-for", "203.0.113.7, 10.0.0.1, 10.0.0.2")]);
        assert_eq!(resolve_forwarded_ip(&h), Some(ip("203.0.113.7")));
    }

    #[test]
    fn forwarded_header_takes_precedence_over_xff() {
        let h = headers(&[
            ("forwarded", "for=203.0.113.9"),
            ("x-forwarded-for", "198.51.100.1"),
        ]);
        assert_eq!(resolve_forwarded_ip(&h), Some(ip("203.0.113.9")));
    }

    #[test]
    fn forwarded_parses_leftmost_for_with_other_params() {
        let h = headers(&[(
            "forwarded",
            "for=203.0.113.9;proto=https;by=203.0.113.43, for=198.51.100.17",
        )]);
        assert_eq!(resolve_forwarded_ip(&h), Some(ip("203.0.113.9")));
    }

    #[test]
    fn forwarded_parses_quoted_ipv6_with_port() {
        let h = headers(&[("forwarded", r#"for="[2001:db8:cafe::17]:4711""#)]);
        assert_eq!(resolve_forwarded_ip(&h), Some(ip("2001:db8:cafe::17")));
    }

    #[test]
    fn forwarded_obfuscated_identifier_is_ignored() {
        let h = headers(&[("forwarded", "for=_hidden")]);
        assert_eq!(resolve_forwarded_ip(&h), None);
    }

    #[test]
    fn forwarded_case_insensitive_for_key() {
        let h = headers(&[("forwarded", "For=203.0.113.9")]);
        assert_eq!(resolve_forwarded_ip(&h), Some(ip("203.0.113.9")));
    }

    #[test]
    fn xff_ipv4_with_port_strips_port() {
        let h = headers(&[("x-forwarded-for", "203.0.113.7:5555")]);
        assert_eq!(resolve_forwarded_ip(&h), Some(ip("203.0.113.7")));
    }

    #[test]
    fn xff_bare_ipv6_is_parsed() {
        let h = headers(&[("x-forwarded-for", "2001:db8::1, 10.0.0.1")]);
        assert_eq!(resolve_forwarded_ip(&h), Some(ip("2001:db8::1")));
    }

    #[test]
    fn garbage_xff_yields_none() {
        let h = headers(&[("x-forwarded-for", "not-an-ip")]);
        assert_eq!(resolve_forwarded_ip(&h), None);
    }

    #[tokio::test]
    async fn middleware_overwrites_connect_info_when_forwarded_present() {
        use axum::body::Body;
        use axum::routing::get;
        use axum::{Router, ServiceExt as AxumServiceExt};
        use tower::ServiceExt as _;

        async fn echo(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> String {
            addr.ip().to_string()
        }

        let app = Router::new()
            .route("/echo", get(echo))
            .layer(axum::middleware::from_fn(rewrite_client_addr));
        let make =
            AxumServiceExt::<Request>::into_make_service_with_connect_info::<SocketAddr>(app);
        // Raw TCP peer is the proxy (10.0.0.9); the header carries the client.
        let peer: SocketAddr = "10.0.0.9:1111".parse().unwrap();
        let svc = make.oneshot(peer).await.unwrap();

        let resp = svc
            .oneshot(
                Request::builder()
                    .uri("/echo")
                    .header("x-forwarded-for", "203.0.113.7")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"203.0.113.7");
    }

    #[tokio::test]
    async fn middleware_preserves_peer_when_no_forwarded_header() {
        use axum::body::Body;
        use axum::routing::get;
        use axum::{Router, ServiceExt as AxumServiceExt};
        use tower::ServiceExt as _;

        async fn echo(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> String {
            addr.ip().to_string()
        }

        let app = Router::new()
            .route("/echo", get(echo))
            .layer(axum::middleware::from_fn(rewrite_client_addr));
        let make =
            AxumServiceExt::<Request>::into_make_service_with_connect_info::<SocketAddr>(app);
        let peer: SocketAddr = "203.0.113.50:2222".parse().unwrap();
        let svc = make.oneshot(peer).await.unwrap();

        let resp = svc
            .oneshot(Request::builder().uri("/echo").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"203.0.113.50");
    }
}
