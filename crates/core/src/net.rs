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
//! Shared trusted-proxy client-IP resolution, used by any inbound path that
//! needs a caller's real address behind a reverse proxy - originally
//! written for the API Key (SCIM ingress) path (ADR 0021 §3 Step 2) and
//! reused, with its own separate `trusted_proxies` list, for dynamic auth
//! plugin dispatch (ADR 0025 §4) - these are different trust boundaries
//! (SCIM ingress vs. anonymous pre-auth login) and must never share one
//! trusted-proxy configuration.
use std::net::IpAddr;

use ipnet::IpNet;

/// Compute the effective client IP using the rightmost-non-trusted-proxy
/// algorithm: append the raw TCP peer to the right of the
/// `X-Forwarded-For` chain, then walk right to left, returning the first
/// address not in `trusted_proxies`. If the raw TCP peer itself is not
/// trusted, it is used directly without consulting XFF at all.
///
/// Takes the already-extracted `X-Forwarded-For` header value (not a raw
/// header map) so this helper has no dependency on any particular HTTP
/// framework type - callers extract it from whatever request-header
/// representation they have (`axum::http::HeaderMap`, a plain
/// `HashMap<String, String>`, ...).
pub(crate) fn resolve_client_ip(
    xff_header: Option<&str>,
    peer_ip: Option<IpAddr>,
    trusted_proxies: &[String],
) -> Option<IpAddr> {
    let trusted: Vec<IpNet> = trusted_proxies
        .iter()
        .filter_map(|c| c.parse::<IpNet>().ok())
        .collect();

    let is_trusted = |ip: &IpAddr| trusted.iter().any(|net| net.contains(ip));

    let peer = peer_ip?;
    if !is_trusted(&peer) {
        return Some(peer);
    }

    let xff_chain: Vec<IpAddr> = xff_header
        .map(|h| {
            h.split(',')
                .filter_map(|s| s.trim().parse::<IpAddr>().ok())
                .collect()
        })
        .unwrap_or_default();

    let mut chain = xff_chain;
    chain.push(peer);

    chain
        .into_iter()
        .rev()
        .find(|ip| !is_trusted(ip))
        .or(Some(peer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_untrusted_peer_is_used_directly() {
        let ip = resolve_client_ip(Some("1.1.1.1"), Some("8.8.8.8".parse().unwrap()), &[]);
        assert_eq!(ip, Some("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_trusted_peer_walks_xff_chain() {
        let ip = resolve_client_ip(
            Some("203.0.113.5, 10.0.0.2"),
            Some("10.0.0.1".parse().unwrap()),
            &["10.0.0.0/8".to_string()],
        );
        assert_eq!(ip, Some("203.0.113.5".parse().unwrap()));
    }

    #[test]
    fn test_no_peer_returns_none() {
        assert_eq!(resolve_client_ip(None, None, &[]), None);
    }
}
