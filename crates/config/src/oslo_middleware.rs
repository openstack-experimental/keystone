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
//! # `[oslo_middleware]` configuration
//!
//! Mirrors the subset of upstream Python Keystone's `[oslo_middleware]`
//! section that is relevant to client-address capture.

use serde::Deserialize;

use crate::common::csv;

/// `[oslo_middleware]` section.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct OsloMiddleware {
    /// Whether to parse proxy forwarding headers (`Forwarded` per RFC 7239,
    /// falling back to `X-Forwarded-For`) on the public interface to recover
    /// the originating client address, overwriting the raw TCP peer captured
    /// in `ConnectInfo<SocketAddr>`.
    ///
    /// The name and default (**off**) match upstream oslo.middleware's
    /// `HTTPProxyToWSGI`. Even when enabled, a header is only honoured when the
    /// immediate TCP peer matches [`trusted_proxies`](Self::trusted_proxies), so
    /// a client reaching the listener directly cannot spoof its address.
    #[serde(default)]
    pub enable_proxy_headers_parsing: bool,

    /// CIDR blocks of reverse proxies trusted to set the forwarding headers
    /// (e.g. `10.0.0.0/8, 192.168.0.0/16`). The client address is recovered
    /// only when the immediate TCP peer falls within one of these ranges; the
    /// effective client is then the rightmost address in the forwarding chain
    /// that is not itself a trusted proxy. Empty (the default) means no proxy
    /// is trusted, so the raw peer address is always used even when parsing is
    /// enabled.
    #[serde(default, deserialize_with = "csv")]
    pub trusted_proxies: Vec<String>,
}

#[cfg(test)]
mod tests {
    use config::{Config, File, FileFormat};

    use super::*;

    #[test]
    fn defaults_to_disabled() {
        let sot = OsloMiddleware::default();
        assert!(!sot.enable_proxy_headers_parsing);
    }

    #[test]
    fn parses_enabled_flag_from_ini() {
        let c = Config::builder()
            .add_source(File::from_str(
                "enable_proxy_headers_parsing = true",
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let sot: OsloMiddleware = c.try_deserialize().unwrap();
        assert!(sot.enable_proxy_headers_parsing);
    }

    #[test]
    fn defaults_to_no_trusted_proxies() {
        assert!(OsloMiddleware::default().trusted_proxies.is_empty());
    }

    #[test]
    fn parses_trusted_proxies_csv_from_ini() {
        let c = Config::builder()
            .add_source(File::from_str(
                "trusted_proxies = 10.0.0.0/8,192.168.0.0/16",
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let sot: OsloMiddleware = c.try_deserialize().unwrap();
        assert_eq!(
            sot.trusted_proxies,
            vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]
        );
    }
}
