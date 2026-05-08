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
//! # Server interfaces
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde::Deserialize;

use crate::ListenerConfig;

/// Keystone internal API interface.
#[derive(Debug, Deserialize, Clone)]
pub struct InternalInterface {
    /// Default address to use for the Rest API. Defaults to `0.0.0.0:8080`.
    #[serde(default = "default_public_tcp_address")]
    pub tcp_address: SocketAddr,

    /// Listener configuration.
    #[serde(flatten, default)]
    pub listener: ListenerConfig,
}

/// Keystone public API interface.
#[derive(Debug, Deserialize, Clone)]
pub struct PublicInterface {
    /// Default address to use for the Rest API. Defaults to `0.0.0.0:8081`.
    #[serde(default = "default_internal_tcp_address")]
    pub tcp_address: SocketAddr,

    /// Listener configuration.
    #[serde(flatten)]
    pub listener: ListenerConfig,
}

impl Default for PublicInterface {
    fn default() -> Self {
        Self {
            tcp_address: default_public_tcp_address(),
            listener: ListenerConfig::Http,
        }
    }
}

fn default_public_tcp_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080)
}

fn default_internal_tcp_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8081)
}

#[cfg(test)]
mod tests {

    use config::{Config, File, FileFormat};
    use serde_json::json;

    use super::*;

    #[test]
    fn test_deser() {
        let sot: InternalInterface = serde_json::from_value(json!({
            "tcp_address": "1.2.3.4:5678",
            "type": "http",
        }))
        .unwrap();
        assert_eq!(sot.tcp_address.to_string(), "1.2.3.4:5678");
        if let ListenerConfig::Http = sot.listener {
        } else {
            panic!("should be Http listener");
        }
        let sot: InternalInterface = serde_json::from_value(json!({
            "tcp_address": "1.2.3.4:5678",
            "type": "spiffe",
            "trust_domains": "a,b,c"
        }))
        .unwrap();
        assert_eq!(sot.tcp_address.to_string(), "1.2.3.4:5678");
        if let ListenerConfig::Spiffe(s) = sot.listener {
            assert!(s.trust_domains.contains(&String::from("a")));
        } else {
            panic!("should be Http listener");
        }
    }

    #[test]
    fn test_deser_ini() {
        let c = Config::builder()
            .add_source(File::from_str(
                r#"
tcp_address = "1.2.3.4:5678"
type = http
"#,
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let sot: InternalInterface = c.try_deserialize().unwrap();
        assert_eq!(sot.tcp_address.to_string(), "1.2.3.4:5678");
        if let ListenerConfig::Http = sot.listener {
        } else {
            panic!("should be Http listener");
        }
        let c = Config::builder()
            .add_source(File::from_str(
                r#"
tcp_address = "1.2.3.4:5678"
type = spiffe
trust_domains = "a,b,c"
"#,
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let sot: InternalInterface = c.try_deserialize().unwrap();
        assert_eq!(sot.tcp_address.to_string(), "1.2.3.4:5678");
        if let ListenerConfig::Spiffe(s) = sot.listener {
            assert!(s.trust_domains.contains(&String::from("a")));
        } else {
            panic!("should be Http listener");
        }
    }
}
