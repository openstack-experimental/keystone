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
use serde::Deserialize;
use std::path::PathBuf;

/// Raft cluster configuration.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct DistributedStorageConfiguration {
    /// Cluster address.
    pub cluster_addr: String,

    /// Node id.
    pub node_id: u64,

    // /// List of cluster nodes.
    // #[serde(default)]
    // pub nodes: Vec<ClusterNode>,
    /// Path to the storage.
    pub path: PathBuf,

    /// Disable the mTLS for cluster nodes communication.
    #[serde(default)]
    pub disable_tls: bool,

    /// TLS configuration.
    #[serde(flatten)]
    pub tls_configuration: Option<TlsConfiguration>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct TlsConfiguration {
    /// Path to the CA certificate to validate connections from clients or
    /// peers.
    #[serde(default)]
    pub tls_client_ca_file: Option<PathBuf>,

    /// Path to the mTLS client certificate file.
    #[serde(default)]
    pub tls_cert_file: PathBuf,

    /// Path to the mTLS certificate key file.
    #[serde(default)]
    pub tls_key_file: PathBuf,
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
    use super::*;
    use serde_json::json;

    #[test]
    fn test_deser() {
        let cfg: DistributedStorageConfiguration = serde_json::from_value(json!({
            "cluster_addr": "1.2.3.4:5678",
            "node_id": 1,
            "path": "/tmp",
            "tls_cert_file": "/tmp/tls.cert",
            "tls_key_file": "/tmp/tls.key"
        }))
        .unwrap();
        assert!(!cfg.disable_tls);
        assert!(cfg.tls_configuration.is_some());
    }
}
