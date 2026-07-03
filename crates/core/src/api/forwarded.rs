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
//! # Client-IP resolution from proxy forwarding headers
//!
//! Shared by the API-key ingress (ADR 0021 §3) and the public-listener proxy
//! header middleware. It implements the trusted-proxy model: forwarding headers
//! are consulted **only** when the immediate TCP peer is a configured trusted
//! proxy, and the effective client is the rightmost address in the chain that
//! is not itself a trusted proxy. A client able to reach the listener directly
//! therefore cannot spoof its apparent address by prepending an
//! `X-Forwarded-For`/`Forwarded` entry.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use axum::http::HeaderMap;
use ipnet::IpNet;

/// Upper bound on forwarding-chain entries parsed, guarding against an
/// unbounded comma list (parsing DoS). Only the rightmost hops are relevant to
/// the rightmost-non-trusted walk, so any excess left-hand entries are ignored.
const MAX_FORWARDED_HOPS: usize = 10;

/// Resolve the effective client IP behind trusted reverse proxies.
///
/// The raw TCP `peer_ip` is appended to the right of the forwarding chain
/// (RFC 7239 `Forwarded` preferred, else `X-Forwarded-For`); the chain is then
/// walked right to left, returning the first address that is not a member of
/// `trusted_proxies`. If the immediate peer is itself not trusted, the headers
/// are ignored entirely and the peer is returned unchanged.
///
/// `trusted_proxies` is a list of CIDR blocks (e.g. `10.0.0.0/8`); unparsable
/// entries are skipped. Returns `None` only when no peer address is available.
pub fn resolve_client_ip(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_proxies: &[String],
) -> Option<IpAddr> {
    let trusted: Vec<IpNet> = trusted_proxies
        .iter()
        .filter_map(|c| c.trim().parse::<IpNet>().ok())
        .collect();
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|net| net.contains(ip));

    let peer = peer_ip?;
    // The immediate peer must be a trusted proxy before any header is honoured.
    if !is_trusted(&peer) {
        return Some(peer);
    }

    let mut chain = forwarded_chain(headers);
    chain.push(peer);
    chain
        .into_iter()
        .rev()
        .find(|ip| !is_trusted(ip))
        .or(Some(peer))
}

/// Parse the forwarding chain in left-to-right order, capped to the rightmost
/// [`MAX_FORWARDED_HOPS`] entries. Prefers the RFC 7239 `Forwarded` header,
/// falling back to `X-Forwarded-For`.
fn forwarded_chain(headers: &HeaderMap) -> Vec<IpAddr> {
    if let Some(value) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
        return capped_chain(value, forwarded_element_ip);
    }
    if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
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

    const TRUSTED: &[&str] = &["10.0.0.0/8"];

    fn trusted() -> Vec<String> {
        TRUSTED.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_peer_ip_resolves_to_none() {
        assert_eq!(resolve_client_ip(&HeaderMap::new(), None, &trusted()), None);
    }

    #[test]
    fn untrusted_peer_ignores_headers_entirely() {
        // Peer is not a trusted proxy: the header must not be consulted at all,
        // even when present (prevents spoofing via a direct connection).
        let h = headers(&[("x-forwarded-for", "1.2.3.4")]);
        let peer = Some(ip("203.0.113.5"));
        assert_eq!(
            resolve_client_ip(&h, peer, &trusted()),
            Some(ip("203.0.113.5"))
        );
    }

    #[test]
    fn trusted_peer_walks_xff_rightmost_non_trusted() {
        let h = headers(&[("x-forwarded-for", "1.2.3.4, 10.0.0.5")]);
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(resolve_client_ip(&h, peer, &trusted()), Some(ip("1.2.3.4")));
    }

    #[test]
    fn leftmost_xff_entry_is_never_trusted_blindly() {
        // Attacker prepends a spoofed leftmost entry; it must not be returned.
        let h = headers(&[("x-forwarded-for", "203.0.113.99, 1.2.3.4, 10.0.0.5")]);
        let peer = Some(ip("10.0.0.1"));
        let effective = resolve_client_ip(&h, peer, &trusted());
        assert_ne!(effective, Some(ip("203.0.113.99")));
        assert_eq!(effective, Some(ip("1.2.3.4")));
    }

    #[test]
    fn all_hops_trusted_falls_back_to_peer() {
        let h = headers(&[("x-forwarded-for", "10.0.0.9")]);
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(&h, peer, &trusted()),
            Some(ip("10.0.0.1"))
        );
    }

    #[test]
    fn forwarded_header_is_preferred_and_walked_right_to_left() {
        let h = headers(&[
            (
                "forwarded",
                "for=203.0.113.7;proto=https, for=10.0.0.5;proto=https",
            ),
            ("x-forwarded-for", "198.51.100.1"),
        ]);
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(&h, peer, &trusted()),
            Some(ip("203.0.113.7"))
        );
    }

    #[test]
    fn forwarded_quoted_ipv6_with_port_is_parsed() {
        let h = headers(&[("forwarded", r#"for="[2001:db8:cafe::17]:4711""#)]);
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(&h, peer, &trusted()),
            Some(ip("2001:db8:cafe::17"))
        );
    }

    #[test]
    fn forwarded_obfuscated_identifier_falls_back_to_peer() {
        let h = headers(&[("forwarded", "for=_hidden")]);
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(&h, peer, &trusted()),
            Some(ip("10.0.0.1"))
        );
    }

    #[test]
    fn xff_ipv4_with_port_strips_port() {
        let h = headers(&[("x-forwarded-for", "203.0.113.7:5555")]);
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(&h, peer, &trusted()),
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
        let h = headers(&[("x-forwarded-for", value.as_str())]);
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(resolve_client_ip(&h, peer, &trusted()), Some(ip("8.8.8.8")));
    }
}
