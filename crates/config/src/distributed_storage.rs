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
use std::path::PathBuf;

use http::Uri;
use serde::Deserialize;

use crate::common::{TlsConfiguration, csv};

/// Raft cluster configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct DistributedStorageConfiguration {
    /// The address of the node in the cluster.
    #[serde(with = "http_serde::uri")]
    pub node_cluster_addr: Uri,

    /// Address on which current node listens for peer connections.
    #[serde(default = "default_tcp_address")]
    pub node_listener_addr: SocketAddr,

    /// Node id.
    pub node_id: u64,

    /// Path to the storage.
    pub path: PathBuf,

    /// TLS configuration for the Raft cluster communication.
    #[serde(flatten)]
    pub tls_configuration: RaftTlsConfiguration,
}

fn default_tcp_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8081)
}

///// Raft cluster node.
//#[derive(Debug, Deserialize, Clone)]
//pub struct ClusterNode {
//    /// Node address.
//    pub addr: String,
//    /// Node ID.
//    pub id: u64,
//}

/// Raft TLS implementation.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum RaftTlsConfiguration {
    /// Spiffe mTLS - not supported yet.
    Spiffe(SpiffeTls),
    /// Basic (manual) TLS.
    Tls(TlsConfiguration),
}

/// Spiffe backed mTLS for the Raft.
#[derive(Debug, Deserialize, Clone)]
pub struct SpiffeTls {
    /// Trusted domains for SPIFFE verification.
    #[serde(deserialize_with = "csv")]
    pub trust_domains: Vec<String>,
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
        let _cfg: DistributedStorageConfiguration = serde_json::from_value(json!({
            "node_cluster_addr": "http://1.2.3.4:5678",
            "node_id": 1,
            "path": "/tmp",
            "tls_cert_file": "/tmp/tls.cert",
            "tls_key_file": "/tmp/tls.key"
        }))
        .unwrap();
    }

    #[test]
    fn test_deser_ini() {
        let c = Config::builder()
            .add_source(File::from_str(
                r#"
node_cluster_addr = https://localhost:8310
node_id = 1
path = /keystone/storage
tls_key_file = /foo
tls_cert_file = /bar
tls_client_ca_file = /baz
"#,
                FileFormat::Ini,
            ))
            .build()
            .unwrap();
        let cfg: DistributedStorageConfiguration = c.try_deserialize().unwrap();
        assert_eq!("https://localhost:8310/", cfg.node_cluster_addr.to_string());
        assert_eq!(1, cfg.node_id);
        assert_eq!("/keystone/storage", cfg.path.to_str().unwrap());
        if let RaftTlsConfiguration::Tls(tls) = cfg.tls_configuration {
            assert_eq!(tls.tls_key_file, Some(PathBuf::from("/foo")));
            assert_eq!(tls.tls_cert_file, Some(PathBuf::from("/bar")));
            assert_eq!(tls.tls_client_ca_file, Some(PathBuf::from("/baz")));
        } else {
            panic!("should be regular tls");
        }
    }

    #[test]
    fn test_env() {
        temp_env::with_vars(
            [(
                "OS_DISTRIBUTED_STORAGE__NODE_CLUSTER_ADDR",
                Some("http://test/"),
            )],
            || {
                let mut cfg_file = NamedTempFile::new().unwrap();
                write!(
                    cfg_file,
                    r#"
[auth]
methods = []
[database]
connection = "foo"
[distributed_storage]
node_id = 5
path = /foo
            "#
                )
                .unwrap();

                let cfg = crate::Config::new(cfg_file.path().to_path_buf()).unwrap();
                assert_eq!(
                    "http://test/",
                    cfg.distributed_storage
                        .expect("must be present")
                        .node_cluster_addr
                        .to_string()
                );
            },
        );
    }
}
