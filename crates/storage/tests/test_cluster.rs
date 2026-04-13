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
#![allow(clippy::uninlined_format_args)]
use std::collections::BTreeMap;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use eyre::{Result, WrapErr};
use openraft::async_runtime::AsyncRuntime;
use openraft::type_config::TypeConfigExt;
use openraft::type_config::alias::AsyncRuntimeOf;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use tempfile::TempDir;
use tonic::transport::{Channel, ClientTlsConfig, Identity, ServerTlsConfig};

use openstack_keystone_config::{DistributedStorageConfiguration, TlsConfiguration};
use openstack_keystone_distributed_storage::TypeConfig;
use openstack_keystone_distributed_storage::app::{Storage, get_app_server, init_storage};
use openstack_keystone_distributed_storage::network::load_tls_client_config;
use openstack_keystone_distributed_storage::protobuf as pb;
use openstack_keystone_distributed_storage::protobuf::raft::cluster_admin_service_client::ClusterAdminServiceClient;

/// Set up a cluster of 3 nodes.
/// Write to it and read from it.
#[tracing_test::traced_test]
#[test]
fn test_cluster() {
    TypeConfig::run(test_cluster_inner()).unwrap();
}

struct InstanceHolder {
    pub node_id: u64,
    pub config: DistributedStorageConfiguration,
    storage_dir: TempDir,
    pub storage: Storage,
}

impl InstanceHolder {
    async fn new(node_id: u64, tls_config: Option<TlsConfiguration>) -> Result<Self> {
        let storage_dir = tempfile::TempDir::new().unwrap();
        let config = get_config(node_id, storage_dir.path().to_path_buf(), tls_config);
        let storage = init_storage(&config).await?;
        Ok(Self {
            node_id,
            config,
            storage_dir,
            storage,
        })
    }
}

async fn test_cluster_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    rustls::crypto::CryptoProvider::install_default(provider).unwrap();

    let certs_dir = TempDir::new()?;
    let tls_configuration = Some(make_certificates(&certs_dir)?);
    let tls_client_config = load_tls_client_config(false, tls_configuration.as_ref())?;

    // --- Start 3 raft node in 3 threads.
    let instance1 = Arc::new(InstanceHolder::new(1, tls_configuration.clone()).await?);
    let instance2 = Arc::new(InstanceHolder::new(2, tls_configuration.clone()).await?);
    let instance3 = Arc::new(InstanceHolder::new(3, tls_configuration.clone()).await?);
    let instances = vec![instance1.clone(), instance2.clone(), instance3.clone()];

    let inst1 = instance1.clone();
    let _h1 = thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let x = rt.block_on(start_raft_app(&inst1.config, &inst1.storage));
        println!("raft app exit result: {:?}", x);
    });

    let inst2 = instance2.clone();
    let _h2 = thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let x = rt.block_on(start_raft_app(&inst2.config, &inst2.storage));
        println!("raft app exit result: {:?}", x);
    });

    let inst3 = instance3.clone();
    let _h3 = thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let x = rt.block_on(start_raft_app(&inst3.config, &inst3.storage));
        println!("raft app exit result: {:?}", x);
    });

    // Wait for server to start up.
    TypeConfig::sleep(Duration::from_millis(200)).await;

    let mut admin_client1 = new_admin_client(get_addr(1), &tls_client_config).await?;

    // --- Initialize the target node as a cluster of only one node.
    //     After init(), the single node cluster will be fully functional.
    println!("=== init single node cluster");
    {
        admin_client1
            .init(pb::raft::InitRequest {
                nodes: vec![new_node(1)],
            })
            .await?;

        let metrics = admin_client1.metrics(()).await?.into_inner();
        println!("=== metrics after init: {:?}", metrics);
    }

    println!(
        "=== Add node 2, 3 to the cluster as learners, to let them start to receive log replication from the leader"
    );
    {
        println!("=== add-learner 2");
        admin_client1
            .add_learner(pb::raft::AddLearnerRequest {
                node: Some(new_node(2)),
            })
            .await?;

        println!("=== add-learner 3");
        admin_client1
            .add_learner(pb::raft::AddLearnerRequest {
                node: Some(new_node(3)),
            })
            .await?;

        let metrics = admin_client1.metrics(()).await?.into_inner();
        println!("=== metrics after add-learner: {:?}", metrics);
        assert_eq!(
            vec![pb::raft::NodeIdSet {
                node_ids: BTreeMap::from([(1, ())]),
            }],
            metrics.membership.clone().unwrap().configs
        );
        assert_eq!(
            BTreeMap::from([(1, new_node(1)), (2, new_node(2)), (3, new_node(3))]),
            metrics.membership.unwrap().nodes
        );
    }

    // --- Turn the two learners to members.
    //     A member node can vote or elect itself as leader.

    println!("=== change-membership to 1,2,3");
    {
        admin_client1
            .change_membership(pb::raft::ChangeMembershipRequest {
                members: vec![1, 2, 3],
                retain: false,
            })
            .await?;

        let metrics = admin_client1.metrics(()).await?.into_inner();
        println!("=== metrics after change-member: {:?}", metrics);
        assert_eq!(
            vec![pb::raft::NodeIdSet {
                node_ids: BTreeMap::from([(1, ()), (2, ()), (3, ())]),
            }],
            metrics.membership.unwrap().configs
        );
    }

    println!("=== write `foo=bar`");
    {
        // Need to try to write to different nodes ensuring the write operation distributes across
        // the cluster
        instance1
            .storage
            .set_value("foo", "bar", None::<String>)
            .await?;
        instance2
            .storage
            .set_value("foo1", "bar1", Some("another_keyspace"))
            .await?;
        //    // --- Wait for a while to let the replication get done.
        TypeConfig::sleep(Duration::from_millis(1_000)).await;
    }

    println!("=== read `foo` on every node");
    {
        for instance in &instances {
            println!("=== read `foo` on node {}", instance.node_id);
            let got: Option<String> = instance.storage.get_by_key("foo", None::<String>).await?;
            assert_eq!(Some("bar".to_string()), got);

            let got: Option<String> = instance.storage.get_by_key("foo1", None::<String>).await?;
            assert!(got.is_none());

            let got: Option<String> = instance
                .storage
                .get_by_key("foo1", Some("another_keyspace"))
                .await?;
            assert_eq!(Some("bar1".to_string()), got);
        }
    }

    println!("=== delete `foo=bar`");
    {
        instance3.storage.remove("foo", None::<String>).await?;

        // --- Wait for a while to let the replication get done.
        TypeConfig::sleep(Duration::from_millis(1_000)).await;
    }

    println!("=== read `foo` on every node");
    {
        for instance in &instances {
            println!("=== read `foo` on node {}", instance.node_id);

            let got: Option<String> = instance.storage.get_by_key("foo", None::<String>).await?;
            assert!(got.is_none());

            let got: Option<String> = instance
                .storage
                .get_by_key("foo1", Some("another_keyspace"))
                .await?;
            assert_eq!(Some("bar1".to_string()), got);
        }
    }

    println!("=== Remove node 1,2 by change-membership to {{3}}");
    {
        admin_client1
            .change_membership(pb::raft::ChangeMembershipRequest {
                members: vec![3],
                retain: false,
            })
            .await?;

        TypeConfig::sleep(Duration::from_millis(2_000)).await;

        let metrics = admin_client1.metrics(()).await?.into_inner();
        println!(
            "=== metrics after change-membership to {{3}}: {:?}",
            metrics
        );
        assert_eq!(
            vec![pb::raft::NodeIdSet {
                node_ids: BTreeMap::from([(3, ())]),
            }],
            metrics.membership.unwrap().configs
        );
    }

    Ok(())
}

async fn new_admin_client(
    addr: String,
    client_tls_config: &Option<ClientTlsConfig>,
) -> Result<ClusterAdminServiceClient<Channel>> {
    let channel = if let Some(tls_config) = client_tls_config {
        Channel::builder(format!("https://{}", addr).parse()?).tls_config(tls_config.clone())?
    } else {
        Channel::builder(format!("http://{}", addr).parse()?)
    };
    let client = ClusterAdminServiceClient::new(channel.connect().await?);
    Ok(client)
}

fn new_node(node_id: u64) -> pb::raft::Node {
    pb::raft::Node {
        node_id,
        rpc_addr: get_addr(node_id),
    }
}

fn get_addr(node_id: u64) -> String {
    match node_id {
        1 => "127.0.0.1:21001".to_string(),
        2 => "127.0.0.1:21002".to_string(),
        3 => "127.0.0.1:21003".to_string(),
        _ => {
            unreachable!("node_id must be 1, 2, or 3");
        }
    }
}

pub async fn start_raft_app(
    config: &DistributedStorageConfiguration,
    storage: &Storage,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let http_addr = config.cluster_addr.clone();
    let node_id = config.node_id;
    //let storage = init_storage(config).await?;

    let mut server = tonic::transport::Server::builder();
    if !config.disable_tls
        && let Some(tls_config) = &config.tls_configuration
    {
        let ca = tonic::transport::Certificate::from_pem(std::fs::read_to_string(
            &tls_config
                .tls_client_ca_file
                .as_ref()
                .expect("ca cert must be present"),
        )?);
        let identity = Identity::from_pem(
            std::fs::read_to_string(&tls_config.tls_cert_file)
                .wrap_err("reading server cert file")?,
            std::fs::read_to_string(&tls_config.tls_key_file)
                .wrap_err("reading server cert key file")?,
        );
        let tls_config = ServerTlsConfig::new().client_ca_root(ca).identity(identity);
        server = server.tls_config(tls_config)?;
    }

    let server_future = server
        .add_routes(get_app_server(&storage).await?)
        .serve(http_addr.parse()?);

    println!("Node {node_id} starting server at {http_addr}");
    server_future.await?;

    Ok(())
}

fn make_certificates<P: AsRef<Path>>(certs_path: P) -> Result<TlsConfiguration> {
    // 1. Generate CA private key and certificate
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];

    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "CA");
    ca_params.distinguished_name = ca_dn;

    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca = Issuer::new(ca_params, ca_key);
    let ca_cert_file_name = certs_path.as_ref().join("ca.crt");
    let mut ca_cert_file = std::fs::File::create(&ca_cert_file_name)?;
    ca_cert_file.write_all(ca_cert.pem().as_bytes())?;

    // 2. Generate peer certificate (signed by CA)
    let mut peer_cert_params = CertificateParams::default();

    let client_ip: IpAddr = "127.0.0.1".parse()?;
    peer_cert_params.subject_alt_names = vec![SanType::IpAddress(client_ip)];
    peer_cert_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    peer_cert_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let peer_key = KeyPair::generate()?;
    let peer_cert = peer_cert_params.signed_by(&peer_key, &ca)?;

    let peer_cert_file_name = certs_path.as_ref().join("peer.crt");
    let mut peer_cert_file = std::fs::File::create(&peer_cert_file_name)?;
    peer_cert_file.write_all(peer_cert.pem().as_bytes())?;
    let peer_key_file_name = certs_path.as_ref().join("peer.key");
    let mut peer_key_file = std::fs::File::create(&peer_key_file_name)?;
    peer_key_file.write_all(peer_key.serialize_pem().as_bytes())?;

    Ok(TlsConfiguration {
        tls_client_ca_file: Some(ca_cert_file_name.to_path_buf()),
        tls_cert_file: peer_cert_file_name.to_path_buf(),
        tls_key_file: peer_key_file_name.to_path_buf(),
    })
}

fn get_config(
    node_id: u64,
    db_path: PathBuf,
    tls_config: Option<TlsConfiguration>,
) -> DistributedStorageConfiguration {
    DistributedStorageConfiguration {
        cluster_addr: get_addr(node_id),
        node_id: node_id,
        path: db_path,
        disable_tls: tls_config.is_none(),
        tls_configuration: tls_config.clone(),
    }
}
