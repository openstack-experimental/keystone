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
use std::path::PathBuf;

use http::Uri;
use serde::Deserialize;

use crate::common::TlsConfiguration;

/// Raft cluster configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct DistributedStorageConfiguration {
    /// Cluster address.
    #[serde(with = "http_serde::uri")]
    pub cluster_addr: Uri,

    /// Node id.
    pub node_id: u64,

    /// Path to the storage.
    pub path: PathBuf,

    /// TLS configuration for the Raft cluster communication.
    #[serde(flatten)]
    pub tls_configuration: TlsConfiguration,
}

/// Raft cluster node.
#[derive(Debug, Deserialize, Clone)]
pub struct ClusterNode {
    /// Node address.
    pub addr: String,
    /// Node ID.
    pub id: u64,
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
            "cluster_addr": "http://1.2.3.4:5678",
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
cluster_addr = https://localhost:8310
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
        assert_eq!("https://localhost:8310/", cfg.cluster_addr.to_string());
        assert_eq!(1, cfg.node_id);
        assert_eq!("/keystone/storage", cfg.path.to_str().unwrap());
        assert_eq!(
            cfg.tls_configuration.tls_key_file,
            Some(PathBuf::from("/foo"))
        );
        assert_eq!(
            cfg.tls_configuration.tls_cert_file,
            Some(PathBuf::from("/bar"))
        );
        assert_eq!(
            cfg.tls_configuration.tls_client_ca_file,
            Some(PathBuf::from("/baz"))
        );
    }

    #[test]
    fn test_env() {
        temp_env::with_vars(
            [("OS_DISTRIBUTED_STORAGE__CLUSTER_ADDR", Some("http://test/"))],
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
                        .cluster_addr
                        .to_string()
                );
            },
        );
    }
}
