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
//! Per-site KEK (ADR 0045 §11.2): two nodes whose sites hold different
//! private keys share one DEK.

use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

use super::harness::*;
use super::*;
use openstack_keystone_distributed_storage::config::PerSiteKekConfiguration;

const PER_SITE_PORT_BASE: u16 = 2450;
const CLUSTER_ID: &str = "per-site-test";

struct SiteFiles {
    dir: TempDir,
}

impl SiteFiles {
    /// RSA key pairs for sites `a` and `b`, written as PEM files.
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        for name in ["a", "b"] {
            let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
            std::fs::write(
                dir.path().join(format!("{name}.pub")),
                key.to_public_key()
                    .to_public_key_pem(LineEnding::LF)
                    .unwrap(),
            )
            .unwrap();
            std::fs::write(
                dir.path().join(format!("{name}.key")),
                &*key.to_pkcs8_pem(LineEnding::LF).unwrap(),
            )
            .unwrap();
        }
        Self { dir }
    }

    fn config(&self, site: &str, private: &str) -> PerSiteKekConfiguration {
        let p = |f: &str| self.dir.path().join(f).display().to_string();
        PerSiteKekConfiguration {
            cluster_id: CLUSTER_ID.into(),
            escrow_site: None,
            site: site.into(),
            site_key_file: Some(self.dir.path().join(format!("{private}.key"))),
            site_key_transit_name: None,
            sites: vec![format!("a={}", p("a.pub")), format!("b={}", p("b.pub"))],
        }
    }
}

async fn site_node(
    node_id: u64,
    port_base: u16,
    tls: &TlsConfiguration,
    per_site: PerSiteKekConfiguration,
) -> Result<Arc<InstanceHolder>> {
    Ok(Arc::new(
        InstanceHolder::new_with_ds_config(node_id, |path| DistributedStorageConfiguration {
            kek_provider: KekProvider::PerSite,
            per_site: Some(per_site),
            ..get_ds_config_with_port(node_id, port_base, path, tls.clone())
        })
        .await?,
    ))
}

/// A node in site `b` joins a cluster led from site `a` and decrypts the data
/// of both the snapshot of earlier writes and the writes made afterwards,
/// although it never holds site `a`'s private key.
#[serial_test::serial]
#[test]
fn test_two_sites_share_a_dek_with_separate_keys() {
    TypeConfig::run(async {
        test_two_sites_share_a_dek_with_separate_keys_inner()
            .await
            .unwrap();
    });
}

async fn test_two_sites_share_a_dek_with_separate_keys_inner() -> Result<()> {
    let provider = openstack_keystone_tls_provider::provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls = make_certificates()?;
    let files = SiteFiles::new();

    let node1 = site_node(1, PER_SITE_PORT_BASE, &tls, files.config("a", "a")).await?;
    spawn_raft_app(&node1).await;
    let tls_client = get_client_tls_config(&node1.config)?;
    let mut admin1 = new_admin_client(node1.config.node_cluster_addr.clone(), &tls_client).await?;
    admin1
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, PER_SITE_PORT_BASE)],
        })
        .await?;
    wait_for_leader(&mut admin1, 1).await;

    const NUM_KEYS: usize = 10;
    for i in 0..NUM_KEYS {
        node1
            .storage
            .set_value(format!("k{i}"), make_env(&format!("v{i}"))?, None, None)
            .await?;
    }

    let node2 = site_node(2, PER_SITE_PORT_BASE, &tls, files.config("b", "b")).await?;
    spawn_raft_app(&node2).await;
    node2
        .storage
        .join_cluster(
            &get_addr_with_port(1, PER_SITE_PORT_BASE).to_string(),
            &get_addr_with_port(2, PER_SITE_PORT_BASE).to_string(),
        )
        .await?;
    node1
        .storage
        .set_value("after".into(), make_env("joined")?, None, None)
        .await?;

    let leader_index = node1.storage.last_log_index().expect("node 1 has a log");
    let mut caught_up = false;
    for _ in 0..100 {
        let applied = node2
            .storage
            .raft
            .metrics()
            .borrow_watched()
            .last_applied
            .map(|l| l.index);
        if applied >= Some(leader_index) {
            caught_up = true;
            break;
        }
        TypeConfig::sleep(Duration::from_millis(100)).await;
    }
    assert!(caught_up, "node 2 did not catch up to index {leader_index}");

    for key in (0..NUM_KEYS)
        .map(|i| format!("k{i}"))
        .chain(["after".to_owned()])
    {
        let metadata = node1
            .storage
            .state_machine_store()
            .meta()
            .get(meta_key("data", key.as_bytes()))?
            .map(|raw| Metadata::unpack(raw.as_ref()))
            .transpose()?
            .unwrap_or_else(|| panic!("node 1 has no metadata for {key}"));
        let ciphertext = node2
            .storage
            .state_machine_store()
            .data()
            .get(key.as_bytes())?
            .unwrap_or_else(|| panic!("node 2 has no ciphertext for {key}"));
        node2
            .storage
            .state_machine_store()
            .decrypt_state(
                ciphertext.as_ref(),
                metadata.tier as u8,
                b"data",
                key.as_bytes(),
                metadata.dek_version,
            )
            .unwrap_or_else(|e| panic!("node 2 cannot decrypt {key} with its own site key: {e}"));
    }
    Ok(())
}

/// A node that claims site `b` but holds site `a`'s key cannot adopt the
/// cluster's DEK.
#[serial_test::serial]
#[test]
fn test_wrong_site_key_cannot_join() {
    TypeConfig::run(async {
        test_wrong_site_key_cannot_join_inner().await.unwrap();
    });
}

async fn test_wrong_site_key_cannot_join_inner() -> Result<()> {
    const PORT_BASE: u16 = PER_SITE_PORT_BASE + 20;
    let provider = openstack_keystone_tls_provider::provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls = make_certificates()?;
    let files = SiteFiles::new();

    let node1 = site_node(1, PORT_BASE, &tls, files.config("a", "a")).await?;
    spawn_raft_app(&node1).await;
    let tls_client = get_client_tls_config(&node1.config)?;
    let mut admin1 = new_admin_client(node1.config.node_cluster_addr.clone(), &tls_client).await?;
    admin1
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, PORT_BASE)],
        })
        .await?;
    wait_for_leader(&mut admin1, 1).await;

    // Site b's name with site a's private key. The node may already refuse to
    // start; if it starts, adopting the cluster's DEK must fail.
    let joined = async {
        let node2 = site_node(2, PORT_BASE, &tls, files.config("b", "a")).await?;
        spawn_raft_app(&node2).await;
        node2
            .storage
            .join_cluster(
                &get_addr_with_port(1, PORT_BASE).to_string(),
                &get_addr_with_port(2, PORT_BASE).to_string(),
            )
            .await?;
        Ok::<_, eyre::Report>(())
    }
    .await;
    let err = joined.expect_err("a node with the wrong site key must not join");
    assert!(
        format!("{err:#}").contains("OAEP decryption failed"),
        "unexpected error: {err:#}"
    );
    Ok(())
}
