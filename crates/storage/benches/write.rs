use std::collections::HashMap;
use std::hint::black_box;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use eyre::{Result, WrapErr};
use openraft::async_runtime::AsyncRuntime;
use openraft::type_config::TypeConfigExt;
use openraft::type_config::alias::AsyncRuntimeOf;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use reserve_port::ReservedSocketAddr;
use tempfile::TempDir;
use tokio::runtime::Runtime;
use tonic::transport::{Identity, ServerTlsConfig};

use openstack_keystone_config::{Config, DistributedStorageConfiguration, TlsConfiguration};
use openstack_keystone_distributed_storage::TypeConfig;
use openstack_keystone_distributed_storage::app::{Storage, get_app_server, init_storage};
use openstack_keystone_distributed_storage::network::load_tls_client_config;
use openstack_keystone_distributed_storage::protobuf as pb;
use openstack_keystone_distributed_storage::store_command::*;

#[allow(dead_code)]
struct InstanceHolder {
    pub node_id: u64,
    pub config: Config,
    storage_dir: TempDir,
    pub storage: Storage,
    pub addr: SocketAddr,
}

impl InstanceHolder {
    fn get_ds_config(
        node_id: u64,
        db_path: PathBuf,
        tls_config: TlsConfiguration,
        addr: &SocketAddr,
    ) -> DistributedStorageConfiguration {
        DistributedStorageConfiguration {
            cluster_addr: format!("https://{}", addr).parse().unwrap(),
            node_id: node_id,
            path: db_path,
            tls_configuration: tls_config.clone(),
        }
    }

    async fn new(node_id: u64, tls_config: TlsConfiguration) -> Result<Self> {
        let storage_dir = tempfile::TempDir::new().unwrap();
        let addr = ReservedSocketAddr::reserve_random_socket_addr()?.socket_addr();
        let ds_config = InstanceHolder::get_ds_config(
            node_id,
            storage_dir.path().to_path_buf(),
            tls_config,
            &addr,
        );
        let storage = init_storage(&ds_config).await?;
        let mut config = Config::default();
        config.listener.cluster_address = Some(addr);
        config.distributed_storage = Some(ds_config);
        Ok(Self {
            node_id,
            config,
            storage_dir,
            storage,
            addr,
        })
    }
}

pub async fn start_raft_app(
    config: &Config,
    storage: &Storage,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let http_addr = config.listener.get_cluster_address();
    let ds_config = config
        .distributed_storage
        .as_ref()
        .expect("ds config must be present");
    let node_id = ds_config.node_id;

    let mut server = tonic::transport::Server::builder();
    let ca = tonic::transport::Certificate::from_pem(std::fs::read_to_string(
        &ds_config
            .tls_configuration
            .tls_client_ca_file
            .as_ref()
            .expect("ca cert must be present"),
    )?);
    let identity = Identity::from_pem(
        std::fs::read_to_string(&ds_config.tls_configuration.tls_cert_file)
            .wrap_err("reading server cert file")?,
        std::fs::read_to_string(&ds_config.tls_configuration.tls_key_file)
            .wrap_err("reading server cert key file")?,
    );
    let tls_config = ServerTlsConfig::new().client_ca_root(ca).identity(identity);
    server = server.tls_config(tls_config)?;

    let server_future = server
        .add_routes(get_app_server(&storage).await?)
        .serve(http_addr);

    tracing::info!("Node {node_id} starting server at {http_addr}");
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

async fn build_cluster(count_nodes: u64) -> Result<Vec<Arc<InstanceHolder>>> {
    let certs_dir = TempDir::new()?;
    let tls_configuration = make_certificates(&certs_dir)?;
    //let tls_client_config = load_tls_client_config(&tls_configuration)?;
    let mut instances: Vec<Arc<InstanceHolder>> = Vec::new();

    for num in 0..count_nodes {
        let instance = Arc::new(InstanceHolder::new(num, tls_configuration.clone()).await?);
        let loc_inst = instance.clone();
        let _h1 = thread::spawn(move || {
            let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
            let x = rt.block_on(start_raft_app(&loc_inst.config, &loc_inst.storage));
            tracing::info!("raft app exit result: {:?}", x);
        });
        instances.push(instance);
    }

    // Wait for server to start up.
    TypeConfig::sleep(Duration::from_millis(200)).await;

    let mut nodes: HashMap<u64, pb::raft::Node> = HashMap::new();
    for inst in &instances {
        nodes.insert(
            inst.node_id,
            pb::raft::Node {
                node_id: inst.node_id,
                rpc_addr: inst.addr.to_string(),
            },
        );
    }
    if let Some(inst) = instances.first() {
        inst.storage.raft.initialize(nodes).await?;
    }
    // Wait for server to start up.
    TypeConfig::sleep(Duration::from_millis(200)).await;
    Ok(instances)
}

async fn test_write(instances: &Vec<Arc<InstanceHolder>>) {
    if let Some(inst) = instances.first() {
        inst.storage
            .set_value("foo", "barz", None::<&str>)
            .await
            .unwrap();
    }
}

async fn test_read(instances: &Vec<Arc<InstanceHolder>>) {
    if let Some(inst) = instances.first() {
        let _: Option<String> = inst.storage.get_by_key("foo", None::<&str>).await.unwrap();
    }
}

async fn test_prefix(instances: &Vec<Arc<InstanceHolder>>) {
    if let Some(inst) = instances.first() {
        let _: Vec<(String, String)> = inst.storage.prefix("foo", None::<&str>).await.unwrap();
    }
}

async fn test_remove(instances: &Vec<Arc<InstanceHolder>>) {
    if let Some(inst) = instances.first() {
        inst.storage.remove("foo", None::<&str>).await.unwrap();
    }
}

fn bench_command_serde(c: &mut Criterion) {
    let delete_cmd = StoreCommand::Delete(DeleteCommand {
        key: "foo".into(),
        keyspace: "bar".into(),
    });
    let set_cmd = StoreCommand::Set(SetCommand {
        key: "foo".into(),
        keyspace: "bar".into(),
        value: "value".as_bytes().to_vec(),
    });
    let delete_packed = delete_cmd.pack().unwrap();
    let set_packed = set_cmd.pack().unwrap();
    let mut group = c.benchmark_group("Command_Serde");
    group.bench_with_input(BenchmarkId::new("serde", "set_pack"), &set_cmd, |b, cmd| {
        b.iter(|| cmd.pack());
    });
    group.bench_with_input(
        BenchmarkId::new("serde", "delete_pack"),
        &delete_cmd,
        |b, cmd| {
            b.iter(|| cmd.pack());
        },
    );
    group.bench_with_input(
        BenchmarkId::new("serde", "set_unpack"),
        &set_packed,
        |b, payload| {
            b.iter(|| StoreCommand::unpack(black_box(payload)));
        },
    );
    group.bench_with_input(
        BenchmarkId::new("serde", "delete_unpack"),
        &delete_packed,
        |b, payload| {
            b.iter(|| StoreCommand::unpack(black_box(payload)));
        },
    );
    group.finish();
}

fn bench_storage_cluster(c: &mut Criterion) {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    rustls::crypto::CryptoProvider::install_default(provider).unwrap();

    let rt = Runtime::new().unwrap();

    let instances = rt.block_on(build_cluster(1)).unwrap();

    let mut group = c.benchmark_group("Raft_1Node_Latency");

    group.bench_with_input(
        BenchmarkId::new("write", "1node"),
        &instances,
        |b, instances| {
            b.to_async(&rt).iter(|| test_write(instances));
        },
    );
    group.bench_with_input(
        BenchmarkId::new("read", "1node"),
        &instances,
        |b, instances| {
            b.to_async(&rt).iter(|| test_read(instances));
        },
    );
    group.bench_with_input(
        BenchmarkId::new("prefix", "1node"),
        &instances,
        |b, instances| {
            b.to_async(&rt).iter(|| test_prefix(instances));
        },
    );
    group.bench_with_input(
        BenchmarkId::new("remove", "1node"),
        &instances,
        |b, instances| {
            b.to_async(&rt).iter(|| test_remove(instances));
        },
    );
    group.finish();
}

criterion_group!(benches, bench_storage_cluster, bench_command_serde);
criterion_main!(benches);
