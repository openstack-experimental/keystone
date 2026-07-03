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
//! section that is relevant to client-address capture (issue #358).

use serde::Deserialize;

/// `[oslo_middleware]` section.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct OsloMiddleware {
    /// Whether to parse proxy forwarding headers (`Forwarded` per RFC 7239,
    /// falling back to `X-Forwarded-For`) on the public interface to recover
    /// the originating client address, overwriting the raw TCP peer captured
    /// in `ConnectInfo<SocketAddr>`.
    ///
    /// The name and default (**off**) match upstream oslo.middleware's
    /// `HTTPProxyToWSGI`. It MUST only be enabled when Keystone sits behind a
    /// trusted reverse proxy / load balancer: with it on, the immediate peer is
    /// trusted to have set these headers honestly, so a client able to reach
    /// the listener directly could otherwise spoof its apparent address. Off by
    /// default, a deployment that is not actually behind a trusted proxy cannot
    /// be tricked into trusting a forged header.
    #[serde(default)]
    pub enable_proxy_headers_parsing: bool,
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
}
