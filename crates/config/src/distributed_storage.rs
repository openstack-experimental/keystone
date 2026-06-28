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

    /// Enable development mode.
    ///
    /// When `true` the node relaxes production-only enforcement:
    /// - Startup pre-flight failures (RLIMIT_CORE, PR_SET_DUMPABLE,
    ///   RLIMIT_MEMLOCK) are logged as errors but do not abort startup (ADR
    ///   0016-v2 §9 / §12).
    /// - The `KEYSTONE_DEV_KEK` environment variable is accepted as a KEK
    ///   source (ADR 0016-v2 §2.1 invariant 6).
    ///
    /// Production deployments MUST leave this unset (default `false`). Any
    /// service definition containing `dev_mode = true` is rejected by the
    /// CI/CD deployment validation check (ADR 0016-v2 §10 invariant 11).
    #[serde(default)]
    pub dev_mode: bool,

    /// Nodes to attempt Raft cluster join against on startup (ADR 0016-v2
    /// §4.3).
    ///
    /// CSV list of ``<node_id>=<address>`` pairs, analogous to HashCorp Vault's
    /// ``[auto_join]``, ZooKeeper's ``initialMembers``, or etcd's
    /// ``--initial-cluster``. Every node in the cluster should configure
    /// the same list.
    ///
    /// The bootstrap node (``node_id == 0``) passes the full map to
    /// ``Raft::initialize()`` so all members are known from the start.
    /// Non-bootstrap nodes iterate the list and attempt ``add_learner`` at
    /// each address until one succeeds.  If empty, non-bootstrap nodes will
    /// not auto-join and must be joined manually via ``keystone-manage
    /// storage join``.
    ///
    /// Example (INI / site.toml):
    /// ```toml
    /// retry_join_nodes = "0=https://keystone-rs-0.svc:8300,1=https://keystone-rs-1.svc:8300,2=https://keystone-rs-2.svc:8300"
    /// ```
    #[serde(default, deserialize_with = "deserialize_retry_join_nodes")]
    pub retry_join_nodes: Vec<(u64, String)>,
}

/// Deserialize ``id=address`` pairs from a CSV string.
///
/// Format: ``"0=https://node0:8300,1=https://node1:8300"``.  Entries without
/// an ``=`` separator or with invalid node IDs are silently skipped.
fn deserialize_retry_join_nodes<'de, D>(deserializer: D) -> Result<Vec<(u64, String)>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let mut out = Vec::new();
    for entry in s.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (id_part, addr) = entry.split_once('=').ok_or_else(|| {
            serde::de::Error::custom(format!("expected 'id=addr' format, got '{}'", entry))
        })?;
        let id: u64 = id_part.trim().parse().map_err(|e| {
            serde::de::Error::custom(format!("invalid node id '{}': {}", id_part.trim(), e))
        })?;
        out.push((id, addr.trim().to_string()));
    }
    Ok(out)
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

    /// SPIFFE path prefix required on all storage SVIDs (e.g.
    /// `/keystone/storage/`). The role segment follows this prefix:
    /// `spiffe://<td><spiffe_path_prefix><role>`.
    #[serde(default = "default_spiffe_path_prefix")]
    pub spiffe_path_prefix: String,

    /// SPIFFE role that authorises sensitive management operations (backup,
    /// restore, rotate DEK, clear quarantine, etc.).  Defaults to
    /// `"storage-operator"`.
    #[serde(default = "default_operator_role")]
    pub operator_role: String,

    /// Allow-list of SPIFFE SVIDs that may participate in peer-to-peer Raft
    /// operations (`metrics`, `init`, `add_learner`, `change_membership`).
    /// When empty the check falls back to trust-domain-only validation.
    ///
    /// Example:
    /// ```yaml
    /// allowed_peer_svids:
    ///   - spiffe://example.org/ns/default/sa/keystone
    ///   - spiffe://example.org/keystone/storage/node
    /// ```
    #[serde(default)]
    pub allowed_peer_svids: Vec<String>,
}

fn default_spiffe_path_prefix() -> String {
    "/keystone/storage/".to_string()
}

fn default_operator_role() -> String {
    "storage-operator".to_string()
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
    fn test_spiffe_peer_svids_toml() {
        let c = Config::builder()
            .add_source(File::from_str(
                r#"
node_cluster_addr = "https://localhost:8310"
node_id = 1
path = "/keystone/storage"
trust_domains = "example.org"
allowed_peer_svids = ["spiffe://example.org/ns/default/sa/keystone"]
"#,
                FileFormat::Toml,
            ))
            .build()
            .unwrap();
        let cfg: DistributedStorageConfiguration = c.try_deserialize().unwrap();
        assert_eq!(1, cfg.node_id);
        if let RaftTlsConfiguration::Spiffe(spiffe) = &cfg.tls_configuration {
            assert!(spiffe.trust_domains.contains(&"example.org".to_string()));
            assert_eq!(
                spiffe.allowed_peer_svids,
                vec!["spiffe://example.org/ns/default/sa/keystone".to_string()]
            );
        } else {
            panic!("should be spiffe");
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
