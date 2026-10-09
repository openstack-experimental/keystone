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
//! Shared test harness: PKI, node spawning and polling helpers.

use super::*;

pub use crate::common::*;

pub fn make_env<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<StoreDataEnvelope<Vec<u8>>, StoreError> {
    Ok(StoreDataEnvelope {
        data: rmp_serde::to_vec(value)?,
        metadata: Metadata::default(),
    })
}

/// Test-only KEK: 32 zero bytes encoded as hex.
pub const TEST_KEK_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[allow(dead_code)]
pub struct InstanceHolder {
    pub config: DistributedStorageConfiguration,
    pub node_id: u64,
    pub storage: Arc<Storage>,
    pub storage_dir: TempDir,
}

impl InstanceHolder {
    // from_env() removes KEYSTONE_DEV_KEK from the process environment after
    // reading (ADR 0016-v2 §2.1).  In production each node is a separate
    // process so removal happens once per process.  Here all test nodes share
    // one process, so we re-set the variable before each init_storage call.
    // SAFETY: nodes are initialised sequentially before any async tasks that
    // read the environment are spawned, so there are no concurrent readers.
    #[allow(unsafe_code)]
    pub async fn new(node_id: u64, tls_config: TlsConfiguration) -> Result<Self> {
        Self::new_with_port(node_id, 0, tls_config).await
    }

    pub async fn new_with_port(
        node_id: u64,
        port_base: u16,
        tls_config: TlsConfiguration,
    ) -> Result<Self> {
        Self::new_with_ds_config(node_id, |path| {
            get_ds_config_with_port(node_id, port_base, path, tls_config)
        })
        .await
    }

    /// Node whose peer roles derive from the URI SAN under
    /// [`ROLE_SAN_PREFIX`] (role-mode TLS, issue #1303).
    pub async fn new_role_mode(
        node_id: u64,
        port_base: u16,
        tls_config: TlsConfiguration,
    ) -> Result<Self> {
        Self::new_with_ds_config(node_id, |path| DistributedStorageConfiguration {
            tls_role_san_prefix: Some(ROLE_SAN_PREFIX.to_string()),
            ..get_ds_config_with_port(node_id, port_base, path, tls_config)
        })
        .await
    }

    // SAFETY: same as `new` above.
    #[allow(unsafe_code)]
    pub async fn new_with_ds_config(
        node_id: u64,
        make_ds_config: impl FnOnce(PathBuf) -> DistributedStorageConfiguration,
    ) -> Result<Self> {
        let storage_dir = tempfile::TempDir::new().unwrap();
        let config = make_ds_config(storage_dir.path().to_path_buf());

        unsafe {
            std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
            std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
        }
        let storage = init_storage(&config_manager(config.clone())).await?;
        Ok(Self {
            node_id,
            config,
            storage_dir,
            storage,
        })
    }
}

/// Polls `cond` every `interval` up to `attempts` times, returning `true` as
/// soon as it reports done, or `false` if it never does.
pub async fn poll_until(interval: Duration, attempts: u32, mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..attempts {
        if cond() {
            return true;
        }
        TypeConfig::sleep(interval).await;
    }
    false
}

pub async fn new_admin_client(
    addr: Uri,
    client_tls_config: &ClientTlsConfig,
) -> Result<ClusterAdminServiceClient<Channel>> {
    let endpoint = Channel::builder(addr).tls_config(client_tls_config.clone())?;
    let client = ClusterAdminServiceClient::new(endpoint.connect().await?);
    Ok(client)
}

pub fn new_node(node_id: u64) -> pb::raft::Node {
    new_node_with_port(node_id, 0)
}

pub fn new_node_with_port(node_id: u64, port_base: u16) -> pb::raft::Node {
    pb::raft::Node {
        node_id,
        rpc_addr: get_addr_with_port(node_id, port_base).to_string(),
    }
}

pub fn get_addr(node_id: u64) -> SocketAddr {
    get_addr_with_port(node_id, 0)
}

pub fn get_addr_with_port(node_id: u64, port_base: u16) -> SocketAddr {
    let port = port_base + 21000 + node_id as u16;
    format!("127.0.0.1:{}", port).parse().unwrap()
}

pub async fn wait_for_leader(
    client: &mut ClusterAdminServiceClient<Channel>,
    expected_leader: u64,
) {
    for _ in 0..50 {
        if let Ok(resp) = client.metrics(()).await
            && resp.into_inner().current_leader == Some(expected_leader)
        {
            return;
        }
        TypeConfig::sleep(Duration::from_millis(100)).await;
    }
    panic!("leader {expected_leader} not elected within 5 seconds");
}

pub async fn start_raft_app(
    ds_config: &DistributedStorageConfiguration,
    storage: &Storage,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let http_addr = ds_config.node_listener_addr;
    let node_id = ds_config.node_id;

    let tls_config = get_server_tls_config(ds_config)?;
    let mut server = tonic::transport::Server::builder().tls_config(tls_config)?;

    let server_future = server
        .add_routes(get_app_server(storage).await?)
        .serve(http_addr);

    println!("Node {node_id} starting server at {http_addr}");
    server_future.await?;

    Ok(())
}

pub fn get_ds_config(
    node_id: u64,
    db_path: PathBuf,
    tls_config: TlsConfiguration,
) -> DistributedStorageConfiguration {
    get_ds_config_with_port(node_id, 0, db_path, tls_config)
}

pub fn get_ds_config_with_port(
    node_id: u64,
    port_base: u16,
    db_path: PathBuf,
    tls_config: TlsConfiguration,
) -> DistributedStorageConfiguration {
    DistributedStorageConfiguration {
        node_cluster_addr: format!("https://{}", get_addr_with_port(node_id, port_base))
            .parse()
            .expect("valid address"),
        node_listener_addr: format!("{}", get_addr_with_port(node_id, port_base))
            .parse()
            .expect("valid address"),
        node_id,
        path: db_path,
        tls_configuration: RaftTlsConfiguration::Tls(tls_config.clone()),
        dev_mode: true,
        kek_provider: KekProvider::Env,
        ..Default::default()
    }
}

/// Spawns the node's gRPC server on its own runtime thread and gives its
/// listener a moment to bind.
pub async fn spawn_raft_app(instance: &Arc<InstanceHolder>) {
    let inst = instance.clone();
    let node_id = inst.node_id;
    let _handle = thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let x = rt.block_on(start_raft_app(&inst.config, &inst.storage));
        println!("node {node_id} raft app exit result: {:?}", x);
    });
    TypeConfig::sleep(Duration::from_millis(200)).await;
}

/// Starts node 1 as a single-node cluster and waits for it to lead.
pub async fn start_single_node_cluster(
    port_base: u16,
    tls_configuration: &TlsConfiguration,
) -> Result<(Arc<InstanceHolder>, ClusterAdminServiceClient<Channel>)> {
    let instance =
        Arc::new(InstanceHolder::new_with_port(1, port_base, tls_configuration.clone()).await?);
    spawn_raft_app(&instance).await;

    let tls_client_config = get_client_tls_config(&instance.config)?;
    let mut admin_client = new_admin_client(
        instance.config.node_cluster_addr.clone(),
        &tls_client_config,
    )
    .await?;
    admin_client
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, port_base)],
        })
        .await?;
    wait_for_leader(&mut admin_client, 1).await;
    Ok((instance, admin_client))
}

/// Brings up node 2 fresh, joins it through `join_cluster` (which adopts the
/// leader's DEK first) and promotes it to a voting member.
pub async fn join_node2_as_voter(
    port_base: u16,
    tls_configuration: &TlsConfiguration,
    admin_client1: &mut ClusterAdminServiceClient<Channel>,
) -> Result<Arc<InstanceHolder>> {
    let instance2 =
        Arc::new(InstanceHolder::new_with_port(2, port_base, tls_configuration.clone()).await?);
    spawn_raft_app(&instance2).await;
    instance2
        .storage
        .join_cluster(
            &get_addr_with_port(1, port_base).to_string(),
            &get_addr_with_port(2, port_base).to_string(),
        )
        .await?;
    admin_client1
        .change_membership(pb::raft::ChangeMembershipRequest {
            members: vec![1, 2],
            retain: false,
        })
        .await?;
    Ok(instance2)
}

/// Keyspace for the `i`-th test record: the default `data` keyspace plus two
/// custom ones, so every kind of keyspace has to survive the scenario.
pub fn test_keyspace(i: usize) -> Option<String> {
    match i % 3 {
        0 => None,
        1 => Some("ks_alpha".to_string()),
        _ => Some("ks_beta".to_string()),
    }
}

/// Writes `num` records (`k{i}` = `v{i}`, spread over [`test_keyspace`]) with
/// 32 concurrent writers so that many Raft log entries are produced quickly.
pub async fn write_records_concurrently(storage: &Arc<Storage>, num: usize) -> Result<()> {
    const WRITERS: usize = 32;
    let mut handles = Vec::new();
    for w in 0..WRITERS {
        let storage = storage.clone();
        handles.push(tokio::spawn(async move {
            for i in (w..num).step_by(WRITERS) {
                storage
                    .set_value(
                        format!("k{i}"),
                        make_env(&format!("v{i}"))?,
                        test_keyspace(i),
                        None,
                    )
                    .await?;
            }
            Ok::<_, eyre::Report>(())
        }));
    }
    for h in handles {
        h.await??;
    }
    Ok(())
}

/// `get_by_key` that retries transient errors (a follower read needs the
/// leader's ReadIndex quorum, which a 2-voter cluster can briefly miss);
/// the content of the answer is what callers assert on.
pub async fn get_by_key_retrying(
    storage: &Arc<Storage>,
    key: &[u8],
    keyspace: Option<&str>,
) -> Result<Option<StoreDataEnvelope<Vec<u8>>>> {
    let mut last_err = None;
    for _ in 0..50 {
        match storage.get_by_key(key, keyspace).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                last_err = Some(e);
                TypeConfig::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    Err(last_err.expect("at least one attempt").into())
}

/// Asserts that `storage` serves exactly the records written by
/// [`write_records_concurrently`] plus the fixed index/sensitive records of
/// the scenarios, in every keyspace.
pub async fn assert_serves_all_records(
    storage: &Arc<Storage>,
    num: usize,
    label: &str,
) -> Result<()> {
    // Exhaustive: one prefix listing per keyspace returns every record, so
    // every value is checked without paying one (forwarded, linearizable)
    // read per key -- thousands of those dominated the test's runtime.
    for ks in [None, Some("ks_alpha"), Some("ks_beta")] {
        let listed: BTreeMap<String, String> = storage
            .prefix("k".as_bytes(), ks)
            .await?
            .into_iter()
            .map(|(k, env)| Ok((k, env.try_deserialize::<String>()?.data)))
            .collect::<Result<_>>()?;
        let expected: BTreeMap<String, String> = (0..num)
            .filter(|i| test_keyspace(*i).as_deref() == ks)
            .map(|i| (format!("k{i}"), format!("v{i}")))
            .collect();
        assert_eq!(
            expected, listed,
            "{label}: contents of keyspace {ks:?} differ"
        );
    }
    // Point reads on a sample, to cover the `get_by_key` path as well.
    for i in (0..num).step_by(97) {
        let got = get_by_key_retrying(
            storage,
            format!("k{i}").as_bytes(),
            test_keyspace(i).as_deref(),
        )
        .await?
        .unwrap_or_else(|| panic!("{label}: k{i} missing in {:?}", test_keyspace(i)));
        assert_eq!(
            format!("v{i}"),
            got.try_deserialize::<String>()?.data,
            "{label}: wrong value for k{i}"
        );
    }
    let indexes = storage.prefix_index("idx:".as_bytes()).await?;
    assert_eq!(20, indexes.len(), "{label}: index entries differ");
    let sensitive = storage
        .get_by_key("sec:k1".as_bytes(), None)
        .await?
        .unwrap_or_else(|| panic!("{label}: sensitive record missing"));
    assert_eq!("secret", sensitive.try_deserialize::<String>()?.data);
    Ok(())
}

/// Writes the index entries and the sensitive record that
/// [`assert_serves_all_records`] expects.
pub async fn write_index_and_sensitive_records(storage: &Arc<Storage>) -> Result<()> {
    for i in 0..20 {
        storage.set_index_key(format!("idx:{i}")).await?;
    }
    storage
        .set_value(
            "sec:k1".to_string(),
            make_sensitive_env("secret")?,
            None,
            None,
        )
        .await?;
    Ok(())
}

/// Waits until the node's audit spool holds `expected` records of
/// `event_type` and returns the matching lines. Asserts the count is stable
/// afterwards so a duplicate record is caught too.
pub async fn audit_records(
    holder: &InstanceHolder,
    event_type: &str,
    expected: usize,
) -> Vec<String> {
    let spool = holder
        .storage_dir
        .path()
        .join("audit-spool")
        .join(format!("raft-audit-{}.jsonl", holder.node_id));
    let needle = format!(r#""event_type":"{event_type}""#);
    let read = || -> Vec<String> {
        std::fs::read_to_string(&spool)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains(&needle))
            .map(str::to_string)
            .collect()
    };
    for _ in 0..100 {
        if read().len() >= expected {
            break;
        }
        TypeConfig::sleep(Duration::from_millis(50)).await;
    }
    // Give a stray duplicate the time to be written.
    TypeConfig::sleep(Duration::from_millis(200)).await;
    let found = read();
    assert_eq!(
        expected,
        found.len(),
        "expected {expected} {event_type} audit record(s): {found:?}"
    );
    found
}

/// Role-mode TLS SAN prefix used by the issue #1303 authorization tests.
pub const ROLE_SAN_PREFIX: &str = "spiffe://keystone/storage/";

/// A cluster node that can be killed and restarted on the same data
/// directory, to exercise failover and crash recovery (GitHub #1307).
pub struct RestartableNode {
    pub _dir: TempDir,
    pub config: DistributedStorageConfiguration,
    pub node_id: u64,
    pub server: Option<(tokio::sync::oneshot::Sender<()>, thread::JoinHandle<()>)>,
    pub storage: Option<Arc<Storage>>,
}

impl RestartableNode {
    /// Creates the node's storage; call [`RestartableNode::start`] to serve.
    #[allow(unsafe_code)]
    pub async fn new(node_id: u64, port_base: u16, tls: &TlsConfiguration) -> Result<Self> {
        let dir = TempDir::new()?;
        let config =
            get_ds_config_with_port(node_id, port_base, dir.path().to_path_buf(), tls.clone());
        // SAFETY: tests using this harness are `#[serial]`.
        unsafe {
            std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
            std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
        }
        let storage = init_storage(&config_manager(config.clone())).await?;
        Ok(Self {
            node_id,
            config,
            _dir: dir,
            storage: Some(storage),
            server: None,
        })
    }

    pub fn storage(&self) -> &Arc<Storage> {
        self.storage.as_ref().expect("node is running")
    }

    /// Serves the node's gRPC API on its listener address.
    pub async fn start(&mut self) {
        let storage = self.storage().clone();
        let config = self.config.clone();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = thread::spawn(move || {
            let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
            rt.block_on(async {
                let Ok(tls) = get_server_tls_config(&config) else {
                    return;
                };
                let Ok(builder) = tonic::transport::Server::builder().tls_config(tls) else {
                    return;
                };
                let mut builder = builder;
                let Ok(routes) = get_app_server(&storage).await else {
                    return;
                };
                let serve = builder.add_routes(routes).serve(config.node_listener_addr);
                // Dropping the server future closes its connections at once
                // (a graceful shutdown would wait for the peers' pooled ones).
                tokio::select! {
                    _ = serve => {},
                    _ = stop_rx => {},
                }
            });
        });
        self.server = Some((stop_tx, handle));
        TypeConfig::sleep(Duration::from_millis(200)).await;
    }

    /// Stops the node without any cluster-level goodbye and releases its
    /// data directory lock.
    pub async fn kill(&mut self) {
        if let Some((stop, handle)) = self.server.take() {
            let _ = stop.send(());
            let _ = handle.join();
        }
        if let Some(storage) = self.storage.take() {
            storage.raft.shutdown().await.ok();
        }
        TypeConfig::sleep(Duration::from_millis(500)).await;
    }

    /// Starts the node again from its persisted state.
    #[allow(unsafe_code)]
    pub async fn restart(&mut self) -> Result<()> {
        // SAFETY: tests using this harness are `#[serial]`.
        unsafe {
            std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
            std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
        }
        self.storage = Some(init_storage(&config_manager(self.config.clone())).await?);
        self.start().await;
        Ok(())
    }

    pub async fn admin(&self) -> Result<ClusterAdminServiceClient<Channel>> {
        let tls = get_client_tls_config(&self.config)?;
        new_admin_client(self.config.node_cluster_addr.clone(), &tls).await
    }
}

/// `set_value` that retries while an election is still in progress.
pub async fn set_value_retrying(storage: &Arc<Storage>, key: &str, value: &str) -> Result<()> {
    let mut last_err = None;
    for _ in 0..100 {
        match storage
            .set_value(key.to_string(), make_env(value)?, None, None)
            .await
        {
            Ok(_) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                TypeConfig::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    Err(last_err.expect("at least one attempt").into())
}
