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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde::Deserialize;

use crate::common::TlsConfiguration;

/// Server listener section.
#[derive(Debug, Deserialize, Clone)]
pub struct Listener {
    /// Default address to use for the server to server communication. This
    /// defaults to one port higher than the value of address.
    #[serde(default)]
    pub cluster_address: Option<SocketAddr>,

    /// Default address to use for the Rest API. Defaults to `0.0.0.0:8080`.
    #[serde(default = "default_tcp_address")]
    pub tcp_address: SocketAddr,

    /// TLS configuration for the server listener.
    #[serde(default)]
    #[serde(flatten)]
    pub tls_configuration: Option<TlsConfiguration>,
}

impl Default for Listener {
    fn default() -> Self {
        Self {
            cluster_address: None,
            tcp_address: default_tcp_address(),
            tls_configuration: None,
        }
    }
}

impl Listener {
    /// Get cluster address.
    ///
    /// Obtain the address to use for the server to server communication. This
    /// defaults to one port higher than the value of address.
    pub fn get_cluster_address(&self) -> SocketAddr {
        match self.cluster_address {
            Some(addr) => addr,
            None => SocketAddr::new(self.tcp_address.ip(), self.tcp_address.port() + 1),
        }
    }
}

fn default_tcp_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use config::{Config, File, FileFormat};
    use serde_json::json;
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn test_deser() {
        let cfg: Listener = serde_json::from_value(json!({
            "tcp_address": "127.1.1.1:1234"
        }))
        .unwrap();
        assert_eq!(
            cfg.tcp_address,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 1, 1, 1)), 1234)
        );
    }

    #[test]
    fn test_deser_ini() {
        let c = Config::builder()
            .add_source(File::from_str(
                r#"
tcp_address = 128.0.0.1:1234
"#,
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let cfg: Listener = c.try_deserialize().unwrap();
        assert_eq!(
            cfg.tcp_address,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 1)), 1234)
        );
    }

    #[test]
    fn test_env() {
        temp_env::with_vars(
            [("OS_LISTENER__TCP_ADDRESS", Some("127.0.0.1:8080"))],
            || {
                let mut cfg_file = NamedTempFile::new().unwrap();
                write!(
                    cfg_file,
                    r#"
[auth]
methods = []
[database]
connection = "foo"
            "#
                )
                .unwrap();

                let cfg = crate::Config::new(cfg_file.path().to_path_buf()).unwrap();
                assert_eq!("127.0.0.1:8080", cfg.listener.tcp_address.to_string());
            },
        );
    }
}
