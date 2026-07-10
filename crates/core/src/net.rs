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
//! # Trusted-proxy client-IP resolution
//!
//! The single shared resolver for every inbound path that needs a caller's
//! real address behind a reverse proxy: API-Key (SCIM ingress, ADR 0021 §3
//! Step 2), the global per-IP rate limiter (ADR 0022 Invariant 4), dynamic
//! auth plugin dispatch (ADR 0025 §4), and the public-listener proxy header
//! middleware (`[oslo_middleware] enable_proxy_headers_parsing`).
//!
//! It implements the trusted-proxy model: forwarding headers (RFC 7239
//! `Forwarded` preferred, else `X-Forwarded-For`) are consulted **only** when
//! the immediate TCP peer is a configured trusted proxy, and the effective
//! client is the rightmost address in the chain that is not itself a trusted
//! proxy. A client able to reach the listener directly therefore cannot spoof
//! its apparent address by prepending a forwarding-header entry.
//!
//! Each consumer passes its **own** `trusted_proxies` list — these are
//! different trust boundaries (SCIM ingress, anonymous pre-auth login, public
//! rate limiting, …) and must never share one trusted-proxy configuration.
//! Every list is parsed into [`IpNet`] networks at configuration-load time,
//! so this hot path never parses CIDRs or allocates a proxy list.
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use ipnet::IpNet;

/// Upper bound on forwarding-chain entries parsed, guarding against an
/// unbounded comma list (parsing DoS). Only the rightmost hops are relevant to
/// the rightmost-non-trusted walk, so any excess left-hand entries are ignored.
const MAX_FORWARDED_HOPS: usize = 10;

/// Resolve the effective client IP behind trusted reverse proxies.
///
/// The raw TCP `peer_ip` is appended to the right of the forwarding chain
/// (`forwarded_header`, the RFC 7239 `Forwarded` value, preferred;
/// `xff_header`, the `X-Forwarded-For` value, as fallback); the chain is then
/// walked right to left, returning the first address that is not a member of
/// `trusted_proxies`. If the immediate peer is itself not trusted, the headers
/// are ignored entirely and the peer is returned unchanged.
///
/// Takes already-extracted header values (not a raw header map) so this helper
/// has no dependency on any particular HTTP framework type — callers extract
/// them from whatever request-header representation they have. Callers holding
/// an `axum::http::HeaderMap` can use [`resolve_client_ip_from_headers`].
///
/// Returns `None` only when no peer address is available.
pub fn resolve_client_ip(
    forwarded_header: Option<&str>,
    xff_header: Option<&str>,
    peer_ip: Option<IpAddr>,
    trusted_proxies: &[IpNet],
) -> Option<IpAddr> {
    let is_trusted = |ip: &IpAddr| trusted_proxies.iter().any(|net| net.contains(ip));

    let peer = peer_ip?;
    // The immediate peer must be a trusted proxy before any header is honoured.
    if !is_trusted(&peer) {
        return Some(peer);
    }

    let mut chain = forwarded_chain(forwarded_header, xff_header);
    chain.push(peer);
    chain
        .into_iter()
        .rev()
        .find(|ip| !is_trusted(ip))
        .or(Some(peer))
}

/// [`resolve_client_ip`] for callers holding an `axum::http::HeaderMap`:
/// extracts the RFC 7239 `Forwarded` and `X-Forwarded-For` values and
/// delegates to the framework-neutral resolver.
///
/// Gated like [`crate::api`]: `axum` is an optional dependency pulled in by
/// the `api` feature (and unconditionally as a dev-dependency for tests).
#[cfg(any(feature = "api", test))]
pub fn resolve_client_ip_from_headers(
    headers: &axum::http::HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_proxies: &[IpNet],
) -> Option<IpAddr> {
    resolve_client_ip(
        headers.get("forwarded").and_then(|v| v.to_str().ok()),
        headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
        peer_ip,
        trusted_proxies,
    )
}

/// Parse the forwarding chain in left-to-right order, capped to the rightmost
/// [`MAX_FORWARDED_HOPS`] entries. Prefers the RFC 7239 `Forwarded` header;
/// `X-Forwarded-For` is consulted only when no `Forwarded` header is present
/// (header-level precedence, not per-entry fallback).
fn forwarded_chain(forwarded_header: Option<&str>, xff_header: Option<&str>) -> Vec<IpAddr> {
    if let Some(value) = forwarded_header {
        return capped_chain(value, forwarded_element_ip);
    }
    if let Some(value) = xff_header {
        return capped_chain(value, |s| parse_ip_maybe_port(s.trim()));
    }
    Vec::new()
}

/// Take the rightmost [`MAX_FORWARDED_HOPS`] comma-separated elements of a
/// header value, parse each with `parse`, and return them in left-to-right
/// order. Bounding the split before parsing caps the work an attacker can force.
fn capped_chain(value: &str, parse: impl Fn(&str) -> Option<IpAddr>) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = value
        .rsplit(',')
        .take(MAX_FORWARDED_HOPS)
        .filter_map(parse)
        .collect();
    ips.reverse();
    ips
}

/// Extract the `for=` IP from a single RFC 7239 `Forwarded` list element such as
/// `for=192.0.2.60;proto=http;by=203.0.113.43`. Obfuscated identifiers
/// (`for=_hidden`) yield `None`.
fn forwarded_element_ip(element: &str) -> Option<IpAddr> {
    for param in element.split(';') {
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

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const TRUSTED: &[&str] = &["10.0.0.0/8"];

    fn trusted() -> Vec<IpNet> {
        TRUSTED.iter().map(|s| s.parse().unwrap()).collect()
    }

    // ---------------------------------------------------------------------
    // Peer gating (ADR 0021 §6.E, ADR 0022 Invariant 4)
    // ---------------------------------------------------------------------

    #[test]
    fn no_peer_ip_resolves_to_none() {
        assert_eq!(resolve_client_ip(None, None, None, &trusted()), None);
    }

    #[test]
    fn untrusted_peer_ignores_headers_entirely() {
        // Peer is not a trusted proxy: neither header may be consulted, even
        // when present (prevents spoofing via a direct connection).
        let peer = Some(ip("203.0.113.5"));
        assert_eq!(
            resolve_client_ip(Some("for=1.2.3.4"), Some("1.2.3.4"), peer, &trusted()),
            Some(ip("203.0.113.5"))
        );
    }

    #[test]
    fn empty_trusted_list_always_uses_peer() {
        // No proxy is trusted: headers are never honoured.
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(None, Some("1.2.3.4"), peer, &[]),
            Some(ip("10.0.0.1"))
        );
    }

    // ---------------------------------------------------------------------
    // X-Forwarded-For walk (rightmost-non-trusted)
    // ---------------------------------------------------------------------

    #[test]
    fn trusted_peer_walks_xff_rightmost_non_trusted() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(None, Some("1.2.3.4, 10.0.0.5"), peer, &trusted()),
            Some(ip("1.2.3.4"))
        );
    }

    #[test]
    fn leftmost_xff_entry_is_never_trusted_blindly() {
        // Attacker prepends a spoofed leftmost entry; it must not be returned.
        let peer = Some(ip("10.0.0.1"));
        let effective = resolve_client_ip(
            None,
            Some("203.0.113.99, 1.2.3.4, 10.0.0.5"),
            peer,
            &trusted(),
        );
        assert_ne!(effective, Some(ip("203.0.113.99")));
        assert_eq!(effective, Some(ip("1.2.3.4")));
    }

    #[test]
    fn all_hops_trusted_falls_back_to_peer() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(None, Some("10.0.0.9"), peer, &trusted()),
            Some(ip("10.0.0.1"))
        );
    }

    #[test]
    fn xff_ipv4_with_port_strips_port() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(None, Some("203.0.113.7:5555"), peer, &trusted()),
            Some(ip("203.0.113.7"))
        );
    }

    #[test]
    fn hop_count_is_capped_against_long_chains() {
        // 12 spoofed public entries followed by two trusted hops and the peer.
        // The cap keeps only the rightmost 10 parsed hops, but the real client
        // (first non-trusted from the right) is still resolved correctly.
        let spoof = std::iter::repeat_n("203.0.113.1", 12)
            .collect::<Vec<_>>()
            .join(", ");
        let value = format!("{spoof}, 8.8.8.8, 10.0.0.5");
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(None, Some(value.as_str()), peer, &trusted()),
            Some(ip("8.8.8.8"))
        );
    }

    // ---------------------------------------------------------------------
    // RFC 7239 Forwarded parsing & precedence
    // ---------------------------------------------------------------------

    #[test]
    fn forwarded_header_is_preferred_and_walked_right_to_left() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(
                Some("for=203.0.113.7;proto=https, for=10.0.0.5;proto=https"),
                Some("198.51.100.1"),
                peer,
                &trusted()
            ),
            Some(ip("203.0.113.7"))
        );
    }

    #[test]
    fn forwarded_precedence_is_header_level_not_per_entry() {
        // When a Forwarded header is present but yields no usable address,
        // XFF must NOT be consulted as a fallback — a proxy that emits
        // Forwarded owns the chain, and mixing headers would let an attacker
        // smuggle an XFF entry past a Forwarded-emitting proxy.
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(Some("for=_hidden"), Some("1.2.3.4"), peer, &trusted()),
            Some(ip("10.0.0.1"))
        );
    }

    #[test]
    fn forwarded_quoted_ipv6_with_port_is_parsed() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(
                Some(r#"for="[2001:db8:cafe::17]:4711""#),
                None,
                peer,
                &trusted()
            ),
            Some(ip("2001:db8:cafe::17"))
        );
    }

    #[test]
    fn forwarded_obfuscated_identifier_falls_back_to_peer() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(Some("for=_hidden"), None, peer, &trusted()),
            Some(ip("10.0.0.1"))
        );
    }

    #[test]
    fn forwarded_for_key_is_case_insensitive() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(Some("For=203.0.113.7;Proto=https"), None, peer, &trusted()),
            Some(ip("203.0.113.7"))
        );
    }

    // ---------------------------------------------------------------------
    // HeaderMap convenience entry point
    // ---------------------------------------------------------------------

    mod from_headers {
        use axum::http::HeaderMap;

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

        #[test]
        fn extracts_forwarded_and_prefers_it_over_xff() {
            let h = headers(&[
                ("forwarded", "for=203.0.113.7"),
                ("x-forwarded-for", "198.51.100.1"),
            ]);
            let peer = Some(ip("10.0.0.1"));
            assert_eq!(
                resolve_client_ip_from_headers(&h, peer, &trusted()),
                Some(ip("203.0.113.7"))
            );
        }

        #[test]
        fn extracts_xff_when_no_forwarded() {
            let h = headers(&[("x-forwarded-for", "1.2.3.4, 10.0.0.5")]);
            let peer = Some(ip("10.0.0.1"));
            assert_eq!(
                resolve_client_ip_from_headers(&h, peer, &trusted()),
                Some(ip("1.2.3.4"))
            );
        }

        #[test]
        fn untrusted_peer_ignores_header_map() {
            let h = headers(&[("x-forwarded-for", "1.2.3.4")]);
            let peer = Some(ip("203.0.113.5"));
            assert_eq!(
                resolve_client_ip_from_headers(&h, peer, &trusted()),
                Some(ip("203.0.113.5"))
            );
        }

        #[test]
        fn no_headers_resolves_to_peer() {
            let peer = Some(ip("10.0.0.1"));
            assert_eq!(
                resolve_client_ip_from_headers(&HeaderMap::new(), peer, &trusted()),
                Some(ip("10.0.0.1"))
            );
        }
    }
}
