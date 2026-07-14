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
//! It implements the trusted-proxy model: each ingress boundary selects one
//! forwarding header that its proxies are required to sanitize. That header is
//! consulted **only** when the immediate TCP peer is a configured trusted
//! proxy, and the effective client is the rightmost address in the chain that
//! is not itself a trusted proxy. A client able to reach the listener directly
//! therefore cannot spoof its apparent address by prepending an entry.
//!
//! Each consumer passes its **own** `trusted_proxies` list — these are
//! different trust boundaries (SCIM ingress, anonymous pre-auth login, public
//! rate limiting, …) and must never share one trusted-proxy configuration.
//! Every list is parsed into [`IpNet`] networks at configuration-load time,
//! so this hot path never parses CIDRs or allocates a proxy list.
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use ipnet::IpNet;
use openstack_keystone_config::ProxyHeader;

#[cfg(any(feature = "api", test))]
use openstack_keystone_config::Interface;

/// Upper bound on forwarding-chain entries parsed, guarding against an
/// unbounded comma list (parsing DoS). A chain exceeding the bound is ignored
/// in full rather than truncated: trusting a partial chain would create an
/// ambiguous trust window at the cutoff.
const MAX_FORWARDED_HOPS: usize = 10;

/// Bound quote-aware RFC 7239 parsing even when an attacker supplies one very
/// large quoted element without commas.
const MAX_FORWARDING_HEADER_BYTES: usize = 4096;

/// Raw TCP peer saved before proxy middleware rewrites `ConnectInfo`.
///
/// Security controls use this value so their own trusted-proxy configuration
/// cannot be bypassed by an earlier middleware with a different trust boundary.
#[cfg(any(feature = "api", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalPeerAddr(pub SocketAddr);

/// Return the raw peer only for public-ingress requests.
///
/// Internal and admin interfaces deliberately return `None` even when they
/// carry `ConnectInfo` for audit logging. When no `Interface` extension is
/// present, the request is treated as public for compatibility with direct
/// router tests and the public listener's make-service path.
#[cfg(any(feature = "api", test))]
pub fn public_ingress_peer_addr(extensions: &axum::http::Extensions) -> Option<SocketAddr> {
    if extensions
        .get::<Interface>()
        .is_some_and(|interface| interface != &Interface::Public)
    {
        return None;
    }

    extensions
        .get::<OriginalPeerAddr>()
        .map(|peer| peer.0)
        .or_else(|| {
            extensions
                .get::<axum::extract::ConnectInfo<SocketAddr>>()
                .map(|connect_info| connect_info.0)
        })
}

/// Resolve the effective client IP behind trusted reverse proxies.
///
/// The raw TCP `peer_ip` is appended to the right of the selected forwarding
/// chain; the chain is then walked right to left, returning the first address
/// that is not a member of `trusted_proxies`. If the immediate peer is itself
/// not trusted, the header is ignored entirely and the peer is returned
/// unchanged.
///
/// Takes already-extracted header values (not a raw header map) so this helper
/// has no dependency on any particular HTTP framework type — callers extract
/// them from whatever request-header representation they have. Callers holding
/// an `axum::http::HeaderMap` can use [`resolve_client_ip_from_headers`].
///
/// Returns `None` only when no peer address is available.
pub fn resolve_client_ip(
    header_value: Option<&str>,
    trusted_header: ProxyHeader,
    peer_ip: Option<IpAddr>,
    trusted_proxies: &[IpNet],
) -> Option<IpAddr> {
    let is_trusted = |ip: &IpAddr| trusted_proxies.iter().any(|net| net.contains(ip));

    let peer = peer_ip?;
    // The immediate peer must be a trusted proxy before any header is honoured.
    if !is_trusted(&peer) {
        return Some(peer);
    }

    let mut chain = header_value
        .and_then(|value| forwarding_chain(value, trusted_header))
        .unwrap_or_default();
    chain.push(peer);
    chain
        .into_iter()
        .rev()
        .find(|ip| !is_trusted(ip))
        .or(Some(peer))
}

/// [`resolve_client_ip`] for callers holding an `axum::http::HeaderMap`:
/// extracts only `trusted_header` and delegates to the framework-neutral
/// resolver.
///
/// Gated like [`crate::api`]: `axum` is an optional dependency pulled in by
/// the `api` feature (and unconditionally as a dev-dependency for tests).
#[cfg(any(feature = "api", test))]
pub fn resolve_client_ip_from_headers(
    headers: &axum::http::HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_proxies: &[IpNet],
    trusted_header: ProxyHeader,
) -> Option<IpAddr> {
    resolve_client_ip(
        proxy_header_value(headers, trusted_header),
        trusted_header,
        peer_ip,
        trusted_proxies,
    )
}

/// Extract the one operator-selected forwarding header.
#[cfg(any(feature = "api", test))]
pub fn proxy_header_value(
    headers: &axum::http::HeaderMap,
    trusted_header: ProxyHeader,
) -> Option<&str> {
    headers
        .get(trusted_header.as_str())
        .and_then(|value| value.to_str().ok())
}

/// Parse a complete forwarding chain in left-to-right order. Malformed,
/// oversized, or over-hop-limit chains are rejected in full.
fn forwarding_chain(value: &str, trusted_header: ProxyHeader) -> Option<Vec<IpAddr>> {
    if value.len() > MAX_FORWARDING_HEADER_BYTES {
        return None;
    }

    let elements = match trusted_header {
        ProxyHeader::XForwardedFor => value.split(',').collect::<Vec<_>>(),
        ProxyHeader::Forwarded => split_quoted(value, ',')?,
    };
    if elements.len() > MAX_FORWARDED_HOPS {
        return None;
    }

    elements
        .into_iter()
        .map(|element| match trusted_header {
            ProxyHeader::XForwardedFor => parse_ip_maybe_port(element.trim()),
            ProxyHeader::Forwarded => forwarded_element_ip(element),
        })
        .collect()
}

/// Extract the `for=` IP from a single RFC 7239 `Forwarded` list element such
/// as `for=192.0.2.60;proto=http;by=203.0.113.43`. Obfuscated identifiers
/// (`for=_hidden`) yield `None`.
fn forwarded_element_ip(element: &str) -> Option<IpAddr> {
    let mut result = None;
    for param in split_quoted(element, ';')? {
        let (key, value) = param.trim().split_once('=')?;
        if key.eq_ignore_ascii_case("for") {
            if result.is_some() {
                return None;
            }
            let raw = value.trim();
            let unquoted = if let Some(inner) = raw
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
            {
                // IP literals never require quoted-pair escaping. Rejecting it
                // keeps parsing strict and prevents delimiters being hidden.
                if inner.contains('\\') {
                    return None;
                }
                inner
            } else {
                if raw.contains('"') {
                    return None;
                }
                raw
            };
            result = Some(parse_ip_maybe_port(unquoted)?);
        }
    }
    result
}

/// Split an RFC 7239 list/parameter sequence without treating delimiters
/// inside quoted strings as structure. Invalid quoting fails closed.
fn split_quoted(value: &str, delimiter: char) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;

    for (index, ch) in value.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
        } else if ch == delimiter {
            parts.push(&value[start..index]);
            start = index + ch.len_utf8();
        }
    }
    if quoted || escaped {
        return None;
    }
    parts.push(&value[start..]);
    Some(parts)
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
        let trailing = &rest[end + 1..];
        if !trailing.is_empty()
            && trailing
                .strip_prefix(':')
                .and_then(|port| port.parse::<u16>().ok())
                .is_none()
        {
            return None;
        }
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
        assert_eq!(
            resolve_client_ip(None, ProxyHeader::XForwardedFor, None, &trusted()),
            None
        );
    }

    #[test]
    fn untrusted_peer_ignores_headers_entirely() {
        // Peer is not a trusted proxy: the header may not be consulted.
        let peer = Some(ip("203.0.113.5"));
        assert_eq!(
            resolve_client_ip(
                Some("1.2.3.4"),
                ProxyHeader::XForwardedFor,
                peer,
                &trusted()
            ),
            Some(ip("203.0.113.5"))
        );
    }

    #[test]
    fn empty_trusted_list_always_uses_peer() {
        // No proxy is trusted: headers are never honoured.
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(Some("1.2.3.4"), ProxyHeader::XForwardedFor, peer, &[]),
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
            resolve_client_ip(
                Some("1.2.3.4, 10.0.0.5"),
                ProxyHeader::XForwardedFor,
                peer,
                &trusted()
            ),
            Some(ip("1.2.3.4"))
        );
    }

    #[test]
    fn leftmost_xff_entry_is_never_trusted_blindly() {
        // Attacker prepends a spoofed leftmost entry; it must not be returned.
        let peer = Some(ip("10.0.0.1"));
        let effective = resolve_client_ip(
            Some("203.0.113.99, 1.2.3.4, 10.0.0.5"),
            ProxyHeader::XForwardedFor,
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
            resolve_client_ip(
                Some("10.0.0.9"),
                ProxyHeader::XForwardedFor,
                peer,
                &trusted()
            ),
            Some(ip("10.0.0.1"))
        );
    }

    #[test]
    fn xff_ipv4_with_port_strips_port() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(
                Some("203.0.113.7:5555"),
                ProxyHeader::XForwardedFor,
                peer,
                &trusted()
            ),
            Some(ip("203.0.113.7"))
        );
    }

    #[test]
    fn hop_count_is_capped_against_long_chains() {
        // The entire over-limit chain is ignored instead of creating a trust
        // window by considering only one side of the cutoff.
        let spoof = std::iter::repeat_n("203.0.113.1", 12)
            .collect::<Vec<_>>()
            .join(", ");
        let value = format!("{spoof}, 8.8.8.8, 10.0.0.5");
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(
                Some(value.as_str()),
                ProxyHeader::XForwardedFor,
                peer,
                &trusted()
            ),
            peer
        );
    }

    #[test]
    fn malformed_xff_entry_rejects_the_entire_chain() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(
                Some("203.0.113.7, not-an-ip, 10.0.0.5"),
                ProxyHeader::XForwardedFor,
                peer,
                &trusted()
            ),
            peer
        );
    }

    #[test]
    fn oversized_header_rejects_the_entire_chain() {
        let value = "1".repeat(MAX_FORWARDING_HEADER_BYTES + 1);
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(Some(&value), ProxyHeader::XForwardedFor, peer, &trusted()),
            peer
        );
    }

    // ---------------------------------------------------------------------
    // RFC 7239 Forwarded parsing & precedence
    // ---------------------------------------------------------------------

    #[test]
    fn forwarded_header_is_walked_right_to_left_when_selected() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(
                Some("for=203.0.113.7;proto=https, for=10.0.0.5;proto=https"),
                ProxyHeader::Forwarded,
                peer,
                &trusted()
            ),
            Some(ip("203.0.113.7"))
        );
    }

    #[test]
    fn malformed_forwarded_value_falls_back_to_peer() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(
                Some("for=_hidden"),
                ProxyHeader::Forwarded,
                peer,
                &trusted()
            ),
            Some(ip("10.0.0.1"))
        );
    }

    #[test]
    fn forwarded_quoted_ipv6_with_port_is_parsed() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(
                Some(r#"for="[2001:db8:cafe::17]:4711""#),
                ProxyHeader::Forwarded,
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
            resolve_client_ip(
                Some("for=_hidden"),
                ProxyHeader::Forwarded,
                peer,
                &trusted()
            ),
            Some(ip("10.0.0.1"))
        );
    }

    #[test]
    fn forwarded_for_key_is_case_insensitive() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(
                Some("For=203.0.113.7;Proto=https"),
                ProxyHeader::Forwarded,
                peer,
                &trusted()
            ),
            Some(ip("203.0.113.7"))
        );
    }

    #[test]
    fn forwarded_quoted_comma_is_not_split_as_a_hop() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(
                Some(r#"for=203.0.113.7;ext="a,b", for=10.0.0.5"#),
                ProxyHeader::Forwarded,
                peer,
                &trusted()
            ),
            Some(ip("203.0.113.7"))
        );
    }

    #[test]
    fn forwarded_for_hidden_inside_quoted_parameter_is_ignored() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(
                Some(r#"ext="x;for=198.51.100.99";for=203.0.113.7"#),
                ProxyHeader::Forwarded,
                peer,
                &trusted()
            ),
            Some(ip("203.0.113.7"))
        );
    }

    #[test]
    fn malformed_bracketed_ipv6_suffix_is_rejected() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(
                Some(r#"for="[2001:db8::1]garbage""#),
                ProxyHeader::Forwarded,
                peer,
                &trusted()
            ),
            peer
        );
    }

    #[test]
    fn unterminated_forwarded_quote_rejects_the_entire_chain() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(
                Some(r#"for=203.0.113.7;ext="unterminated"#),
                ProxyHeader::Forwarded,
                peer,
                &trusted()
            ),
            peer
        );
    }

    #[test]
    fn duplicate_forwarded_for_parameter_rejects_the_entire_chain() {
        let peer = Some(ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(
                Some("for=203.0.113.7;for=198.51.100.9"),
                ProxyHeader::Forwarded,
                peer,
                &trusted()
            ),
            peer
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
        fn extracts_only_explicitly_selected_forwarded_header() {
            let h = headers(&[
                ("forwarded", "for=203.0.113.7"),
                ("x-forwarded-for", "198.51.100.1"),
            ]);
            let peer = Some(ip("10.0.0.1"));
            assert_eq!(
                resolve_client_ip_from_headers(&h, peer, &trusted(), ProxyHeader::Forwarded),
                Some(ip("203.0.113.7"))
            );
        }

        #[test]
        fn default_xff_selection_ignores_forged_forwarded_header() {
            let h = headers(&[
                ("forwarded", "for=203.0.113.99"),
                ("x-forwarded-for", "1.2.3.4, 10.0.0.5"),
            ]);
            let peer = Some(ip("10.0.0.1"));
            assert_eq!(
                resolve_client_ip_from_headers(&h, peer, &trusted(), ProxyHeader::XForwardedFor),
                Some(ip("1.2.3.4"))
            );
        }

        #[test]
        fn untrusted_peer_ignores_header_map() {
            let h = headers(&[("x-forwarded-for", "1.2.3.4")]);
            let peer = Some(ip("203.0.113.5"));
            assert_eq!(
                resolve_client_ip_from_headers(&h, peer, &trusted(), ProxyHeader::XForwardedFor),
                Some(ip("203.0.113.5"))
            );
        }

        #[test]
        fn no_headers_resolves_to_peer() {
            let peer = Some(ip("10.0.0.1"));
            assert_eq!(
                resolve_client_ip_from_headers(
                    &HeaderMap::new(),
                    peer,
                    &trusted(),
                    ProxyHeader::XForwardedFor
                ),
                Some(ip("10.0.0.1"))
            );
        }
    }

    mod public_peer {
        use axum::extract::ConnectInfo;

        use super::*;

        fn extensions(interface: Option<Interface>) -> axum::http::Extensions {
            let mut extensions = axum::http::Extensions::new();
            extensions.insert(ConnectInfo("10.0.0.1:1234".parse::<SocketAddr>().unwrap()));
            if let Some(interface) = interface {
                extensions.insert(interface);
            }
            extensions
        }

        #[test]
        fn internal_connect_info_is_not_public_ingress() {
            assert_eq!(
                public_ingress_peer_addr(&extensions(Some(Interface::Internal))),
                None
            );
        }

        #[test]
        fn admin_connect_info_is_not_public_ingress() {
            assert_eq!(
                public_ingress_peer_addr(&extensions(Some(Interface::Admin))),
                None
            );
        }

        #[test]
        fn missing_interface_defaults_to_public() {
            assert_eq!(
                public_ingress_peer_addr(&extensions(None)),
                Some("10.0.0.1:1234".parse().unwrap())
            );
        }

        #[test]
        fn original_peer_wins_over_rewritten_connect_info() {
            let mut extensions = extensions(Some(Interface::Public));
            extensions.insert(ConnectInfo("203.0.113.7:0".parse::<SocketAddr>().unwrap()));
            extensions.insert(OriginalPeerAddr(
                "10.0.0.1:1234".parse::<SocketAddr>().unwrap(),
            ));
            assert_eq!(
                public_ingress_peer_addr(&extensions),
                Some("10.0.0.1:1234".parse().unwrap())
            );
        }
    }
}
