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

use eyre::{Context, Report};
use http::Uri;
use secrecy::SecretSlice;
use serde::Deserialize;
use validator::Validate;

use crate::common::{TlsConfiguration, csv, option_u32_from_str_or_int};

/// Raft cluster configuration.
#[derive(Debug, Deserialize, Clone, Validate)]
#[validate(schema(function = "validate_kek_selection"))]
pub struct DistributedStorageConfiguration {
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

    /// Key Encryption Key (KEK) provider used to wrap/unwrap the storage
    /// Data Encryption Key (ADR 0016-v2 §2.1 / §2.5).
    ///
    /// Defaults to `env`, which is only a valid choice when `dev_mode =
    /// true` (ADR 0016-v2 invariant 6). Production deployments MUST set
    /// this explicitly to `pkcs11` or `tpm`.
    #[serde(default)]
    pub kek_provider: KekProvider,

    /// The address of the node in the cluster.
    #[serde(with = "http_serde::uri")]
    pub node_cluster_addr: Uri,

    /// Node id.
    pub node_id: u64,

    /// Address on which current node listens for peer connections.
    #[serde(default = "default_tcp_address")]
    pub node_listener_addr: SocketAddr,

    /// Path to the storage.
    pub path: PathBuf,

    /// PKCS#11 KEK configuration (ADR 0016-v2 §2.5.1). Required when
    /// `kek_provider = "pkcs11"`.
    #[serde(default)]
    #[validate(nested)]
    pub pkcs11: Option<Pkcs11KekConfiguration>,

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

    /// TLS configuration for the Raft cluster communication.
    #[serde(flatten)]
    pub tls_configuration: RaftTlsConfiguration,

    /// TPM 2.0 KEK configuration (ADR 0016-v2 §2.5.2). Required when
    /// `kek_provider = "tpm"`.
    #[serde(default)]
    #[validate(nested)]
    pub tpm: Option<TpmKekConfiguration>,
}

/// Cross-field validation for the `kek_provider` selection (ADR 0016-v2
/// §2.5): the selected provider's configuration section must be present,
/// and `env` is only reachable in `dev_mode` (enforced again at startup —
/// this is a config-time fail-fast, not the sole enforcement point).
fn validate_kek_selection(
    cfg: &DistributedStorageConfiguration,
) -> Result<(), validator::ValidationError> {
    match cfg.kek_provider {
        KekProvider::Env => {
            if !cfg.dev_mode {
                return Err(validator::ValidationError::new("kek_provider_env_requires_dev_mode")
                    .with_message(std::borrow::Cow::Borrowed(
                        "kek_provider = \"env\" is only valid when dev_mode = true (ADR 0016-v2 invariant 6)",
                    )));
            }
        }
        KekProvider::Pkcs11 => {
            if cfg.pkcs11.is_none() {
                return Err(
                    validator::ValidationError::new("kek_provider_pkcs11_missing_section")
                        .with_message(std::borrow::Cow::Borrowed(
                        "kek_provider = \"pkcs11\" requires a [distributed_storage.pkcs11] section",
                    )),
                );
            }
        }
        KekProvider::Tpm => match &cfg.tpm {
            None => {
                return Err(
                    validator::ValidationError::new("kek_provider_tpm_missing_section")
                        .with_message(std::borrow::Cow::Borrowed(
                            "kek_provider = \"tpm\" requires a [distributed_storage.tpm] section",
                        )),
                );
            }
            Some(tpm) => {
                if tpm.tpm_key_handle.is_none() && tpm.tpm_key_context_file.is_none() {
                    return Err(validator::ValidationError::new(
                        "kek_provider_tpm_missing_key_reference",
                    )
                    .with_message(std::borrow::Cow::Borrowed(
                        "[distributed_storage.tpm] requires either tpm_key_handle or tpm_key_context_file",
                    )));
                }
                if tpm.tpm_key_handle.is_some() && tpm.tpm_key_context_file.is_some() {
                    return Err(validator::ValidationError::new(
                        "kek_provider_tpm_ambiguous_key_reference",
                    )
                    .with_message(std::borrow::Cow::Borrowed(
                        "[distributed_storage.tpm] accepts either tpm_key_handle or tpm_key_context_file, not both",
                    )));
                }
            }
        },
    }
    Ok(())
}

/// Selects which Key Encryption Key provider backs DEK wrap/unwrap (ADR
/// 0016-v2 §2.1 / §2.5).
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KekProvider {
    /// Development-mode KEK sourced from `KEYSTONE_DEV_KEK`. Only valid
    /// when `dev_mode = true` (ADR 0016-v2 invariant 6).
    #[default]
    Env,
    /// PKCS#11 HSM/token-backed KEK (ADR 0016-v2 §2.5.1).
    Pkcs11,
    /// TPM 2.0 resident-key-backed KEK (ADR 0016-v2 §2.5.2).
    Tpm,
}

/// PKCS#11 KEK provider configuration (ADR 0016-v2 §2.5.1).
#[derive(Debug, Deserialize, Clone, Validate)]
pub struct Pkcs11KekConfiguration {
    /// Path to the PKCS#11 module implementing the Cryptoki API, e.g.
    /// `/usr/lib/softhsm/libsofthsm2.so` for SoftHSM2 or the vendor HSM's
    /// PKCS#11 shared library in production.
    /// `CKA_LABEL` of the AES-256 key object used as the KEK. The key MUST
    /// be created with `CKA_EXTRACTABLE = false` (ADR 0016-v2 §10
    /// invariant 13).
    #[validate(length(min = 1))]
    pub pkcs11_key_label: String,

    pub pkcs11_module_path: PathBuf,

    /// The PIN content, populated by [`Self::load_secrets`]. Never
    /// serialised and never logged.
    #[serde(skip)]
    pub pkcs11_pin_content: Option<SecretSlice<u8>>,

    /// Path to a file containing the token PIN. Read once at startup into
    /// locked memory and never accepted via environment variable or inline
    /// config value (ADR 0016-v2 §10 invariant 14).
    pub pkcs11_pin_file: PathBuf,

    /// Numeric slot id to open. Either this or `pkcs11_slot_label` must be
    /// given; the label is preferred where supported since slot ids can
    /// shift across token re-initialisation.
    #[serde(default)]
    pub pkcs11_slot_id: Option<u64>,

    /// Token label used to resolve the slot when `pkcs11_slot_id` is not
    /// given.
    #[serde(default)]
    pub pkcs11_slot_label: Option<String>,
}

impl Pkcs11KekConfiguration {
    /// Read `pkcs11_pin_file` into [`Self::pkcs11_pin_content`].
    pub fn load_secrets(&mut self) -> Result<(), Report> {
        self.pkcs11_pin_content = Some(
            std::fs::read(&self.pkcs11_pin_file)
                .wrap_err_with(|| format!("reading PKCS#11 PIN file {:?}", self.pkcs11_pin_file))?
                .into(),
        );
        Ok(())
    }
}

/// TPM 2.0 KEK provider configuration (ADR 0016-v2 §2.5.2).
#[derive(Debug, Deserialize, Clone, Validate)]
pub struct TpmKekConfiguration {
    /// Path to a file containing the key's auth value, if the key was
    /// provisioned with `userWithAuth` authorisation. Optional because a
    /// TPM key may instead rely on a PCR/policy session. Never accepted via
    /// environment variable or inline config value (ADR 0016-v2 §10
    /// invariant 14).
    /// The auth value content, populated by [`Self::load_secrets`]. Never
    /// serialised and never logged.
    #[serde(skip)]
    pub tpm_auth_content: Option<SecretSlice<u8>>,

    #[serde(default)]
    pub tpm_auth_file: Option<PathBuf>,

    /// Path to a saved TPM2 key context blob, used instead of a persistent
    /// handle. Mutually exclusive with `tpm_key_handle`.
    #[serde(default)]
    pub tpm_key_context_file: Option<PathBuf>,

    /// Persistent handle (decimal or `0x`-prefixed hex, e.g. `0x81000001`)
    /// of the pre-provisioned, non-duplicable AES-256 symmetric-cipher key
    /// used as the KEK. Mutually exclusive with `tpm_key_context_file`.
    #[serde(default, deserialize_with = "option_u32_from_str_or_int")]
    pub tpm_key_handle: Option<u32>,

    /// TCTI connection string for the TPM 2.0 stack, e.g.
    /// `device:/dev/tpmrm0` for a hardware TPM or
    /// `swtpm:host=127.0.0.1,port=2321` for the software TPM used in the
    /// documented sample.
    #[validate(length(min = 1))]
    pub tpm_tcti: String,
}

impl TpmKekConfiguration {
    /// Read `tpm_auth_file` (if configured) into [`Self::tpm_auth_content`].
    pub fn load_secrets(&mut self) -> Result<(), Report> {
        if let Some(path) = &self.tpm_auth_file {
            self.tpm_auth_content = Some(
                std::fs::read(path)
                    .wrap_err_with(|| format!("reading TPM auth file {:?}", path))?
                    .into(),
            );
        }
        Ok(())
    }
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

    /// SPIFFE role that authorises sensitive management operations (backup,
    /// restore, rotate DEK, clear quarantine, etc.).  Defaults to
    /// `"storage-operator"`.
    #[serde(default = "default_operator_role")]
    pub operator_role: String,

    /// SPIFFE path prefix required on all storage SVIDs (e.g.
    /// `/keystone/storage/`). The role segment follows this prefix:
    /// `spiffe://<td><spiffe_path_prefix><role>`.
    #[serde(default = "default_spiffe_path_prefix")]
    pub spiffe_path_prefix: String,

    /// Trusted domains for SPIFFE verification.
    #[serde(deserialize_with = "csv")]
    pub trust_domains: Vec<String>,
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
        // `Config::new` is async, but this test drives it from the synchronous
        // `temp_env::with_vars` closure API, so run it to completion on a local
        // current-thread runtime.
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

                let cfg = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap()
                    .block_on(crate::Config::new(cfg_file.path().to_path_buf()))
                    .unwrap();
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

    #[test]
    fn test_kek_provider_defaults_to_env() {
        let cfg: DistributedStorageConfiguration = serde_json::from_value(json!({
            "node_cluster_addr": "http://1.2.3.4:5678",
            "node_id": 1,
            "path": "/tmp",
            "tls_cert_file": "/tmp/tls.cert",
            "tls_key_file": "/tmp/tls.key"
        }))
        .unwrap();
        assert_eq!(cfg.kek_provider, KekProvider::Env);
        assert!(cfg.pkcs11.is_none());
        assert!(cfg.tpm.is_none());
    }

    #[test]
    fn test_kek_provider_env_requires_dev_mode() {
        let cfg: DistributedStorageConfiguration = serde_json::from_value(json!({
            "node_cluster_addr": "http://1.2.3.4:5678",
            "node_id": 1,
            "path": "/tmp",
            "tls_cert_file": "/tmp/tls.cert",
            "tls_key_file": "/tmp/tls.key",
            "dev_mode": false
        }))
        .unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("kek_provider = \"env\" is only valid when dev_mode"),
            "unexpected error: {err}"
        );

        let cfg_dev: DistributedStorageConfiguration = serde_json::from_value(json!({
            "node_cluster_addr": "http://1.2.3.4:5678",
            "node_id": 1,
            "path": "/tmp",
            "tls_cert_file": "/tmp/tls.cert",
            "tls_key_file": "/tmp/tls.key",
            "dev_mode": true
        }))
        .unwrap();
        cfg_dev
            .validate()
            .expect("dev_mode=true with env kek must validate");
    }

    #[test]
    fn test_kek_provider_pkcs11_requires_section() {
        let cfg: DistributedStorageConfiguration = serde_json::from_value(json!({
            "node_cluster_addr": "http://1.2.3.4:5678",
            "node_id": 1,
            "path": "/tmp",
            "tls_cert_file": "/tmp/tls.cert",
            "tls_key_file": "/tmp/tls.key",
            "kek_provider": "pkcs11"
        }))
        .unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("requires a [distributed_storage.pkcs11] section"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_kek_provider_pkcs11_valid_section() {
        let cfg: DistributedStorageConfiguration = serde_json::from_value(json!({
            "node_cluster_addr": "http://1.2.3.4:5678",
            "node_id": 1,
            "path": "/tmp",
            "tls_cert_file": "/tmp/tls.cert",
            "tls_key_file": "/tmp/tls.key",
            "kek_provider": "pkcs11",
            "pkcs11": {
                "pkcs11_module_path": "/usr/lib/softhsm/libsofthsm2.so",
                "pkcs11_slot_label": "keystone",
                "pkcs11_key_label": "keystone-kek",
                "pkcs11_pin_file": "/etc/keystone/pkcs11-pin"
            }
        }))
        .unwrap();
        cfg.validate().expect("valid pkcs11 section must validate");
    }

    #[test]
    fn test_kek_provider_tpm_requires_key_reference() {
        let cfg: DistributedStorageConfiguration = serde_json::from_value(json!({
            "node_cluster_addr": "http://1.2.3.4:5678",
            "node_id": 1,
            "path": "/tmp",
            "tls_cert_file": "/tmp/tls.cert",
            "tls_key_file": "/tmp/tls.key",
            "kek_provider": "tpm",
            "tpm": {
                "tpm_tcti": "device:/dev/tpmrm0"
            }
        }))
        .unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("requires either tpm_key_handle or tpm_key_context_file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_kek_provider_tpm_ambiguous_key_reference() {
        let cfg: DistributedStorageConfiguration = serde_json::from_value(json!({
            "node_cluster_addr": "http://1.2.3.4:5678",
            "node_id": 1,
            "path": "/tmp",
            "tls_cert_file": "/tmp/tls.cert",
            "tls_key_file": "/tmp/tls.key",
            "kek_provider": "tpm",
            "tpm": {
                "tpm_tcti": "device:/dev/tpmrm0",
                "tpm_key_handle": "0x81000001",
                "tpm_key_context_file": "/var/lib/keystone/tpm-key.ctx"
            }
        }))
        .unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("accepts either tpm_key_handle or tpm_key_context_file, not both"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_kek_provider_tpm_valid_with_hex_handle() {
        let cfg: DistributedStorageConfiguration = serde_json::from_value(json!({
            "node_cluster_addr": "http://1.2.3.4:5678",
            "node_id": 1,
            "path": "/tmp",
            "tls_cert_file": "/tmp/tls.cert",
            "tls_key_file": "/tmp/tls.key",
            "kek_provider": "tpm",
            "tpm": {
                "tpm_tcti": "swtpm:host=127.0.0.1,port=2321",
                "tpm_key_handle": "0x81000001"
            }
        }))
        .unwrap();
        cfg.validate().expect("valid tpm section must validate");
        assert_eq!(
            cfg.tpm.as_ref().and_then(|t| t.tpm_key_handle),
            Some(0x8100_0001)
        );
    }

    #[test]
    fn test_pkcs11_load_secrets() {
        let mut pin_file = NamedTempFile::new().unwrap();
        write!(pin_file, "1234").unwrap();
        let mut cfg = Pkcs11KekConfiguration {
            pkcs11_module_path: "/usr/lib/softhsm/libsofthsm2.so".into(),
            pkcs11_slot_id: None,
            pkcs11_slot_label: Some("keystone".to_string()),
            pkcs11_key_label: "keystone-kek".to_string(),
            pkcs11_pin_file: pin_file.path().to_path_buf(),
            pkcs11_pin_content: None,
        };
        cfg.load_secrets().expect("load_secrets");
        use secrecy::ExposeSecret;
        assert_eq!(
            cfg.pkcs11_pin_content.unwrap().expose_secret(),
            b"1234".as_slice()
        );
    }

    #[test]
    fn test_tpm_load_secrets_optional_auth_file() {
        let mut cfg = TpmKekConfiguration {
            tpm_tcti: "device:/dev/tpmrm0".to_string(),
            tpm_key_handle: Some(0x8100_0001),
            tpm_key_context_file: None,
            tpm_auth_file: None,
            tpm_auth_content: None,
        };
        cfg.load_secrets().expect("load_secrets with no auth file");
        assert!(cfg.tpm_auth_content.is_none());

        let mut auth_file = NamedTempFile::new().unwrap();
        write!(auth_file, "secret-auth").unwrap();
        cfg.tpm_auth_file = Some(auth_file.path().to_path_buf());
        cfg.load_secrets().expect("load_secrets with auth file");
        use secrecy::ExposeSecret;
        assert_eq!(
            cfg.tpm_auth_content.unwrap().expose_secret(),
            b"secret-auth".as_slice()
        );
    }
}
