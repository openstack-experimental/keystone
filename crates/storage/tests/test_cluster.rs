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
use std::backtrace::Backtrace;
use std::collections::BTreeMap;
use std::io::Write;
use std::net::IpAddr;
use std::panic::PanicHookInfo;
use std::path::{Path, PathBuf};
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
use tracing_subscriber::EnvFilter;

use openstack_keystone_config::{DistributedStorageConfiguration, TlsConfiguration};
use openstack_keystone_distributed_storage::TypeConfig;
use openstack_keystone_distributed_storage::app::get_app_server;
use openstack_keystone_distributed_storage::protobuf as pb;
use openstack_keystone_distributed_storage::protobuf::api::identity_service_client::IdentityServiceClient;
use openstack_keystone_distributed_storage::protobuf::raft::cluster_admin_service_client::ClusterAdminServiceClient;

pub fn log_panic(panic: &PanicHookInfo) {
    let backtrace = { format!("{:?}", Backtrace::force_capture()) };

    eprintln!("{}", panic);

    if let Some(location) = panic.location() {
        tracing::error!(
            message = %panic,
            backtrace = %backtrace,
            panic.file = location.file(),
            panic.line = location.line(),
            panic.column = location.column(),
        );
        eprintln!(
            "{}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    } else {
        tracing::error!(message = %panic, backtrace = %backtrace);
    }

    eprintln!("{}", backtrace);
}

/// Set up a cluster of 3 nodes.
/// Write to it and read from it.
#[test]
fn test_cluster() {
    TypeConfig::run(test_cluster_inner()).unwrap();
}

async fn test_cluster_inner() -> Result<()> {
    std::panic::set_hook(Box::new(|panic| {
        log_panic(panic);
    }));

    tracing_subscriber::fmt()
        .with_target(true)
        .with_thread_ids(true)
        .with_level(true)
        .with_ansi(false)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    rustls::crypto::CryptoProvider::install_default(provider).unwrap();

    let certs_dir = TempDir::new()?;
    let tls_configuration = Some(make_certificates(&certs_dir)?);
    let tls_client_config = get_client_tls_config(&tls_configuration)?;

    // --- Start 3 raft node in 3 threads.

    let certs_h1 = tls_configuration.clone();
    let _h1 = thread::spawn(|| {
        let d1 = tempfile::TempDir::new().unwrap();
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let x = rt.block_on(start_raft_app(&get_config(
            1,
            d1.path().to_path_buf(),
            certs_h1,
        )));
        println!("raft app exit result: {:?}", x);
    });

    let certs_h2 = tls_configuration.clone();
    let _h2 = thread::spawn(|| {
        let d2 = tempfile::TempDir::new().unwrap();
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let x = rt.block_on(start_raft_app(&get_config(
            2,
            d2.path().to_path_buf(),
            certs_h2,
        )));
        println!("raft app exit result: {:?}", x);
    });

    let certs_h3 = tls_configuration.clone();
    let _h3 = thread::spawn(|| {
        let d3 = tempfile::TempDir::new().unwrap();
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let x = rt.block_on(start_raft_app(&get_config(
            3,
            d3.path().to_path_buf(),
            certs_h3,
        )));
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
    let mut client1 = new_client(get_addr(1), &tls_client_config).await?;

    println!("=== write `foo=bar`");
    {
        client1
            .set(pb::api::SetRequest {
                key: "foo".to_string(),
                value: "bar".to_string(),
            })
            .await?;

        // --- Wait for a while to let the replication get done.
        TypeConfig::sleep(Duration::from_millis(1_000)).await;
    }

    println!("=== read `foo` on every node");
    {
        println!("=== read `foo` on node 1");
        {
            let got = client1
                .get(pb::api::GetRequest {
                    key: "foo".to_string(),
                })
                .await?;
            assert_eq!(Some("bar".to_string()), got.into_inner().value);
        }

        println!("=== read `foo` on node 2");
        {
            let mut client2 = new_client(get_addr(2), &tls_client_config).await?;
            let got = client2
                .get(pb::api::GetRequest {
                    key: "foo".to_string(),
                })
                .await?;
            assert_eq!(Some("bar".to_string()), got.into_inner().value);
        }

        println!("=== read `foo` on node 3");
        {
            let mut client3 = new_client(get_addr(3), &tls_client_config).await?;
            let got = client3
                .get(pb::api::GetRequest {
                    key: "foo".to_string(),
                })
                .await?;
            assert_eq!(Some("bar".to_string()), got.into_inner().value);
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

fn get_client_tls_config(config: &Option<TlsConfiguration>) -> Result<Option<ClientTlsConfig>> {
    if let Some(tls_config) = &config {
        let ca = tonic::transport::Certificate::from_pem(std::fs::read_to_string(
            &tls_config.tls_client_ca_file.as_ref().unwrap(),
        )?);
        let identity = Identity::from_pem(
            std::fs::read_to_string(&tls_config.tls_cert_file)?,
            std::fs::read_to_string(&tls_config.tls_key_file)?,
        );
        return Ok(Some(
            ClientTlsConfig::new().identity(identity).ca_certificate(ca),
        ));
    } else {
        Ok(None)
    }
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

async fn new_client(
    addr: String,
    client_tls_config: &Option<ClientTlsConfig>,
) -> Result<IdentityServiceClient<Channel>> {
    let channel = if let Some(tls_config) = client_tls_config {
        Channel::builder(format!("https://{}", addr).parse()?).tls_config(tls_config.clone())?
    } else {
        Channel::builder(format!("http://{}", addr).parse()?)
    };
    let client = IdentityServiceClient::new(channel.connect().await?);
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let http_addr = config.cluster_addr.clone();
    let node_id = config.node_id;

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
        .add_routes(get_app_server(config).await?)
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
