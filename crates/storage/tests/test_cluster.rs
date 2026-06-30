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
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use eyre::Result;
use openraft::async_runtime::AsyncRuntime;
use openraft::type_config::TypeConfigExt;
use openraft::type_config::alias::AsyncRuntimeOf;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use tempfile::TempDir;

use tonic::transport::{Channel, ClientTlsConfig, Uri};

use openstack_keystone_config::{
    Config, ConfigManager, DistributedStorageConfiguration, TlsConfiguration,
    TlsConfigurationBuilder,
};
use openstack_keystone_distributed_storage::app::{Storage, get_app_server, init_storage};
use openstack_keystone_distributed_storage::network::{
    get_client_tls_config, get_server_tls_config,
};
use openstack_keystone_distributed_storage::protobuf as pb;
use openstack_keystone_distributed_storage::protobuf::raft::cluster_admin_service_client::ClusterAdminServiceClient;
use openstack_keystone_distributed_storage::store_command::*;
use openstack_keystone_distributed_storage::{DataTier, Metadata, StoreDataEnvelope, StoreError};
use openstack_keystone_distributed_storage::{StorageApi, TypeConfig};

fn make_env<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<StoreDataEnvelope<Vec<u8>>, StoreError> {
    Ok(StoreDataEnvelope {
        data: rmp_serde::to_vec(value)?,
        metadata: Metadata::default(),
    })
}

fn make_sensitive_env<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<StoreDataEnvelope<Vec<u8>>, StoreError> {
    Ok(StoreDataEnvelope {
        data: rmp_serde::to_vec(value)?,
        metadata: Metadata::with_tier(DataTier::Sensitive),
    })
}

/// Test-only KEK: 32 zero bytes encoded as hex.
const TEST_KEK_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Set up a cluster of 3 nodes.
/// Write to it and read from it.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_cluster() {
    TypeConfig::run(test_cluster_inner()).unwrap();
}

/// pod-restart test: verifies check_node_id_uniqueness passes when the config
/// address format changes (bare "host:port" vs "https://host:port/").
///
/// Scenario:
/// 1. Node initializes with bare address "127.0.0.1:21001"
/// 2. Node reinitializes (simulating pod restart) with "https://127.0.0.1:21001/"
/// 3. check_node_id_uniqueness should NOT reject the restart — same logical address.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_node_restart_with_address_format_change() {
    TypeConfig::run(test_node_restart_inner()).unwrap();
}

#[allow(unsafe_code)]
async fn test_node_restart_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    // Crypto provider may already be installed by a parallel test
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let tls_configuration = make_certificates()?;

    // Step 1: Create node with bare address format
    let storage_dir = tempfile::TempDir::new().unwrap();
    let ds_config = DistributedStorageConfiguration {
        node_cluster_addr: "https://127.0.0.1:21005".parse().expect("valid address"),
        node_listener_addr: "127.0.0.1:21005".parse().expect("valid address"),
        node_id: 1,
        path: storage_dir.path().to_path_buf(),
        tls_configuration: openstack_keystone_config::RaftTlsConfiguration::Tls(
            tls_configuration.clone(),
        ),
        dev_mode: true,
        retry_join_nodes: vec![],
    };
    let mut config = Config::default();
    config.distributed_storage = Some(ds_config);

    // SAFETY: no concurrent env reads
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
        std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
    }
    let storage = Arc::new(init_storage(&ConfigManager::not_watched(config.clone())).await?);
    assert!(!storage.is_initialized().await?);

    // Initialize as single-node cluster

    // Start server in a thread with a shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let stg = storage.clone();
    let cfg = config.clone();
    let _srv = std::thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        rt.block_on(async {
            let ds = cfg.distributed_storage.as_ref().expect("ds config");
            let tls = get_server_tls_config(&cfg).unwrap();
            let mut s = tonic::transport::Server::builder().tls_config(tls).unwrap();
            let serve = s
                .add_routes(get_app_server(&stg).await.unwrap())
                .serve(ds.node_listener_addr);
            tokio::select! {
                _ = serve => {},
                _ = shutdown_rx => {},
            }
        });
    });

    TypeConfig::sleep(Duration::from_millis(200)).await;

    let tls_client_config = get_client_tls_config(&config)?;
    let mut admin_client = new_admin_client(
        config
            .distributed_storage
            .as_ref()
            .unwrap()
            .node_cluster_addr
            .clone(),
        &tls_client_config,
    )
    .await?;

    admin_client
        .init(pb::raft::InitRequest {
            nodes: vec![pb::raft::Node {
                node_id: 1,
                rpc_addr: "127.0.0.1:21005".to_string(),
            }],
        })
        .await?;

    // Verify node is initialized and committed
    wait_for_leader(&mut admin_client, 1).await;

    // Drop first storage (simulates pod going away)
    drop(storage);
    drop(admin_client);
    drop(tls_client_config);
    // Signal server thread to shut down so Fjall releases locks
    let _ = shutdown_tx.send(());
    _srv.join().ok();
    TypeConfig::sleep(Duration::from_millis(500)).await;

    // Step 2: Reinitialize the SAME storage dir but with schema prefix + trailing slash
    // This simulates pod restart where Uri::Display produces "https://host:port/"
    let ds_config_restart = DistributedStorageConfiguration {
        node_cluster_addr: "https://127.0.0.1:21005/".parse().expect("valid address"),
        node_listener_addr: "127.0.0.1:21005".parse().expect("valid address"),
        node_id: 1,
        path: storage_dir.path().to_path_buf(),
        tls_configuration: openstack_keystone_config::RaftTlsConfiguration::Tls(
            tls_configuration.clone(),
        ),
        dev_mode: true,
        retry_join_nodes: vec![],
    };
    let mut config_restart = Config::default();
    config_restart.distributed_storage = Some(ds_config_restart);

    // SAFETY: no concurrent env reads
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
        std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
    }

    // This must succeed — the address change is purely cosmetic.
    // If normalization is broken, this fails with:
    // "FATAL: node_id 1 already registered in cluster at 127.0.0.1:21005;
    //  refusing to start with address https://127.0.0.1:21005/"
    let storage_restart =
        Arc::new(init_storage(&ConfigManager::not_watched(config_restart.clone())).await?);

    // Verify the storage thinks it's initialized (persisted state is intact)
    assert!(
        storage_restart.is_initialized().await?,
        "storage should detect persisted cluster state"
    );

    // Write a value to verify the restarted node still functions as leader
    storage_restart
        .set_value("restart_test".to_string(), make_env("passed")?, None, None)
        .await?;

    let got = storage_restart
        .get_by_key("restart_test".as_bytes(), None)
        .await?
        .expect("value should be accessible after restart");
    assert_eq!("passed", got.try_deserialize::<String>()?.data);

    // Drop to stop cleanup
    drop(storage_restart);

    Ok(())
}

#[allow(dead_code)]
struct InstanceHolder {
    pub node_id: u64,
    pub config: Config,
    storage_dir: TempDir,
    pub storage: Storage,
}

impl InstanceHolder {
    // from_env() removes KEYSTONE_DEV_KEK from the process environment after
    // reading (ADR 0016-v2 §2.1).  In production each node is a separate
    // process so removal happens once per process.  Here all test nodes share
    // one process, so we re-set the variable before each init_storage call.
    // SAFETY: nodes are initialised sequentially before any async tasks that read
    // the environment are spawned, so there are no concurrent readers.
    #[allow(unsafe_code)]
    async fn new(node_id: u64, tls_config: TlsConfiguration) -> Result<Self> {
        Self::new_with_port(node_id, 0, tls_config).await
    }

    // SAFETY: same as `new` above.
    #[allow(unsafe_code)]
    async fn new_with_port(
        node_id: u64,
        port_base: u16,
        tls_config: TlsConfiguration,
    ) -> Result<Self> {
        let storage_dir = tempfile::TempDir::new().unwrap();
        let ds_config = get_ds_config_with_port(
            node_id,
            port_base,
            storage_dir.path().to_path_buf(),
            tls_config,
        );
        let mut config = Config::default();
        config.distributed_storage = Some(ds_config);
        unsafe {
            std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
            std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
        }
        let storage = init_storage(&ConfigManager::not_watched(config.clone())).await?;
        Ok(Self {
            node_id,
            config,
            storage_dir,
            storage,
        })
    }
}

async fn test_cluster_inner() -> Result<()> {
    // Crypto provider may already be installed by a parallel test
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let tls_configuration = make_certificates()?;

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

    let tls_client_config = get_client_tls_config(&instance1.config)?;

    let mut admin_client1 = new_admin_client(
        instance1
            .config
            .distributed_storage
            .as_ref()
            .unwrap()
            .node_cluster_addr
            .clone(),
        &tls_client_config,
    )
    .await?;

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
        // Wait until node 1 has committed the init membership and elected itself
        // leader.
        wait_for_leader(&mut admin_client1, 1).await;
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
        // Need to try to write to different nodes ensuring the write operation
        // distributes across the cluster
        instance1
            .storage
            .set_value("foo".to_string(), make_env("bar")?, None, None)
            .await?;
        instance2
            .storage
            .set_value(
                "foo1".to_string(),
                make_env("bar1")?,
                Some("another_keyspace".to_string()),
                None,
            )
            .await?;
        instance3
            .storage
            .set_index_key("idx:foo:1".to_string())
            .await?;
        instance3
            .storage
            .set_index_key("idx:foo:2".to_string())
            .await?;
        instance3
            .storage
            .set_index_key("idx:foo:3".to_string())
            .await?;
        //    // --- Wait for a while to let the replication get done.
        TypeConfig::sleep(Duration::from_millis(1_000)).await;

        // Write Sensitive-tier data so that `prefix` enters the ensure_linearizable
        // path and forwards to the leader for a linearizable read.
        let sensitive_meta = Metadata::with_tier(DataTier::Sensitive);
        let sensitive_val = StoreDataEnvelope {
            data: rmp_serde::to_vec("sensitive_value")?,
            metadata: sensitive_meta,
        };
        instance1
            .storage
            .set_value("sec:k1".to_string(), sensitive_val, None, None)
            .await?;
        let sensitive_meta2 = Metadata::with_tier(DataTier::Sensitive);
        let sensitive_val2 = StoreDataEnvelope {
            data: rmp_serde::to_vec("sensitive_value2")?,
            metadata: sensitive_meta2,
        };
        instance1
            .storage
            .set_value("sec:k2".to_string(), sensitive_val2, None, None)
            .await?;

        // Immediate re-read after write (no replication sleep) — this reproduces
        // the k8s_auth race condition pattern: `upsert_virtual_user_shadow` writes
        // then immediately reads the same key without waiting for Raft replication.
        let immediate_read = instance1
            .storage
            .get_by_key("sec:k1".as_bytes(), None)
            .await?
            .expect("immediate re-read must succeed on the leader");
        let immediate_read = immediate_read.try_deserialize::<String>()?;
        assert_eq!("sensitive_value", immediate_read.data);
    }

    println!("=== read `foo` on every node (including followers)");
    {
        // Verify the leader is node 1 (set by change-membership).
        // On a follower node, `get_by_key` calls `ensure_linearizable(ReadIndex)`
        // which returns `ForwardToLeader`. The storage code must catch this error
        // and fall back to a local FjallDB read. This regression test ensures that
        // reads on followers do NOT fail with "ReadIndex failed: ForwardToLeader".
        let current_leader = admin_client1.metrics(()).await?.into_inner().current_leader;
        assert_eq!(
            current_leader,
            Some(1),
            "leader must be node 1 for this verification"
        );

        for instance in &instances {
            if instance.node_id != 1 {
                println!(
                    "=== follower-read verification on node {} (leader={})",
                    instance.node_id,
                    current_leader.unwrap()
                );
            }

            let got = instance
                .storage
                .get_by_key("foo".as_bytes(), None)
                .await?
                .expect("must present");
            let got = got.try_deserialize::<String>()?;
            println!("the data is {:?}", got);
            assert_eq!("bar", got.data);
            assert!(
                instance
                    .storage
                    .contains_key("foo".as_bytes(), None)
                    .await?
            );

            let got = instance.storage.get_by_key("foo1".as_bytes(), None).await?;
            assert!(got.is_none());
            assert!(
                !instance
                    .storage
                    .contains_key("foo1".as_bytes(), None)
                    .await?
            );

            let got = instance
                .storage
                .get_by_key("foo1".as_bytes(), Some("another_keyspace"))
                .await?;
            let got = got.unwrap();
            assert_eq!("bar1", got.try_deserialize::<String>()?.data);
            let indexes = instance.storage.prefix_index("idx:foo".as_bytes()).await?;
            assert!(indexes.contains(&"idx:foo:1".to_string()));
            assert!(indexes.contains(&"idx:foo:2".to_string()));
            assert!(indexes.contains(&"idx:foo:3".to_string()));
            assert_eq!(indexes.len(), 3);

            // Prefix-read Sensitive-tier data from follower.
            // `prefix` only enters `ensure_linearizable(ReadIndex)` when any result
            // entry has `tier >= DataTier::Sensitive` (app.rs:461).
            // On a follower, ReadIndex returns `ForwardToLeader`. The storage code
            // must catch this and fall back to a local FjallDB read.
            let sensitive_prefix = instance.storage.prefix("sec:".as_bytes(), None).await?;
            assert_eq!(sensitive_prefix.len(), 2);
            let sec_keys: std::collections::HashSet<_> =
                sensitive_prefix.iter().map(|(k, _)| k.as_str()).collect();
            assert!(sec_keys.contains("sec:k1"));
            assert!(sec_keys.contains("sec:k2"));
            for (_k, val) in &sensitive_prefix {
                let val_str = StoreDataEnvelope {
                    data: val.data.clone(),
                    metadata: val.metadata.clone(),
                }
                .try_deserialize::<String>()?
                .data;
                assert!(
                    val_str == "sensitive_value" || val_str == "sensitive_value2",
                    "unexpected value: {val_str}"
                );
            }
        }
    }

    println!("=== delete `foo=bar`");
    {
        instance3.storage.remove("foo".to_string(), None).await?;
        instance2
            .storage
            .remove_index("idx:foo:1".to_string())
            .await?;

        // --- Wait for a while to let the replication get done.
        TypeConfig::sleep(Duration::from_millis(1_000)).await;
    }

    println!("=== read `foo` on every node");
    {
        for instance in &instances {
            println!("=== read `foo` on node {}", instance.node_id);

            let got = instance.storage.get_by_key("foo".as_bytes(), None).await?;
            assert!(got.is_none());

            let got = instance
                .storage
                .get_by_key("foo1".as_bytes(), Some("another_keyspace"))
                .await?;
            let got = got.unwrap();
            assert_eq!("bar1", got.try_deserialize::<String>()?.data);
            let indexes = instance.storage.prefix_index("idx:foo".as_bytes()).await?;
            assert!(indexes.contains(&"idx:foo:2".to_string()));
            assert!(indexes.contains(&"idx:foo:3".to_string()));
            assert_eq!(indexes.len(), 2);
        }
    }

    println!("=== Transaction test");

    let mutations = vec![
        Mutation::set("new_foo", "new_val", Metadata::new(), None::<&str>, None)?,
        Mutation::set("new_foo2", "new_val2", Metadata::new(), None::<&str>, None)?,
        Mutation::remove("foo1", Some("another_keyspace"), None),
    ];
    instance1.storage.transaction(mutations).await?;
    // wait for the log to be applied
    TypeConfig::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        "new_val",
        instance1
            .storage
            .get_by_key("new_foo".as_bytes(), None)
            .await?
            .expect("data should be there")
            .try_deserialize::<String>()?
            .data
    );
    assert_eq!(
        "new_val2",
        instance1
            .storage
            .get_by_key("new_foo2".as_bytes(), None)
            .await?
            .expect("data should be there")
            .try_deserialize::<String>()?
            .data
    );
    assert!(
        instance1
            .storage
            .get_by_key("foo1".as_bytes(), Some("another_keyspace"))
            .await?
            .is_none()
    );

    // Verify transaction results on followers — ensures Raft replication is
    // complete and that the forward-to-leader path works correctly on followers
    // for post-transaction reads.
    TypeConfig::sleep(Duration::from_millis(500)).await;
    for instance in &[instance2.clone(), instance3.clone()] {
        println!(
            "=== verify transaction on follower node {}",
            instance.node_id
        );
        assert_eq!(
            "new_val",
            instance
                .storage
                .get_by_key("new_foo".as_bytes(), None)
                .await?
                .expect("follower must have new_foo")
                .try_deserialize::<String>()?
                .data
        );
        assert!(
            instance
                .storage
                .get_by_key("foo1".as_bytes(), Some("another_keyspace"))
                .await?
                .is_none(),
            "follower must have removed foo1"
        );
    }

    println!("=== Remove node 1,2 by change-membership to {{3}}");
    {
        admin_client1
            .change_membership(pb::raft::ChangeMembershipRequest {
                members: vec![3],
                retain: false,
            })
            .await?;

        // Wait for node 1 to step down and node 3 to become the new leader.
        // The metrics check only verifies membership config, not leadership.
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

        // Verify that data is still accessible on the new single-node leader
        // after the cluster went from 3 members → 1.
        let got = instance3
            .storage
            .get_by_key("sec:k1".as_bytes(), None)
            .await?
            .expect("leader node 3 must have the sensitive data");
        assert_eq!("sensitive_value", got.try_deserialize::<String>()?.data);

        // Also verify old-follower nodes (1, 2) can still read locally.
        // These nodes are no longer part of the cluster but their FjallDB
        // still contains the committed state.
        for instance in &[instance1, instance2] {
            assert!(
                instance
                    .storage
                    .get_by_key("sec:k1".as_bytes(), None)
                    .await?
                    .is_some(),
                "old-follower node {} should still be able to read locally",
                instance.node_id
            );
        }
    }

    Ok(())
}

/// Regression test: write key-val to leader, read immediately from follower.
///
/// Reproduces the Raft replication race condition observed in k8s integration tests
/// (see `api_v4::mapping::ruleset::create` / `update` / `delete` failures).
///
/// Pattern:
/// 1. `set_value` on leader (node 1) — Raft proposal commits asynchronously
/// 2. `get_by_key` on follower (node 2) — local FjallDB may not have replicated yet
/// 3. Current mitigation: `ensure_linearizable(ReadIndex)` retry loop in `app.rs`
///    (3 retries, 14ms total) then fall back to local read
///
/// The test runs multiple iterations to increase the probability of catching
/// the race window. A passing run means the mitigation is working; a failing
/// run means the mitigation is insufficient for the given timing.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_replication_race_get_by_key() {
    TypeConfig::run(test_replication_race_get_by_key_inner()).unwrap();
}

// Port offset to avoid conflicts with other cluster tests.
const GET_BY_KEY_PORT_BASE: u16 = 100;

#[allow(unsafe_code)]
async fn test_replication_race_get_by_key_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let tls_configuration = make_certificates()?;

    let instance1 = Arc::new(
        InstanceHolder::new_with_port(1, GET_BY_KEY_PORT_BASE, tls_configuration.clone()).await?,
    );
    let instance2 = Arc::new(
        InstanceHolder::new_with_port(2, GET_BY_KEY_PORT_BASE, tls_configuration.clone()).await?,
    );
    let instance3 = Arc::new(
        InstanceHolder::new_with_port(3, GET_BY_KEY_PORT_BASE, tls_configuration.clone()).await?,
    );

    let inst1 = instance1.clone();
    let _h1 = thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let _ = rt.block_on(start_raft_app(&inst1.config, &inst1.storage));
    });

    let inst2 = instance2.clone();
    let _h2 = thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let _ = rt.block_on(start_raft_app(&inst2.config, &inst2.storage));
    });

    let inst3 = instance3.clone();
    let _h3 = thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let _ = rt.block_on(start_raft_app(&inst3.config, &inst3.storage));
    });

    TypeConfig::sleep(Duration::from_millis(200)).await;

    let tls_client_config = get_client_tls_config(&instance1.config)?;
    let mut admin_client1 = new_admin_client(
        instance1
            .config
            .distributed_storage
            .as_ref()
            .unwrap()
            .node_cluster_addr
            .clone(),
        &tls_client_config,
    )
    .await?;

    admin_client1
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, GET_BY_KEY_PORT_BASE)],
        })
        .await?;
    wait_for_leader(&mut admin_client1, 1).await;

    admin_client1
        .add_learner(pb::raft::AddLearnerRequest {
            node: Some(new_node_with_port(2, GET_BY_KEY_PORT_BASE)),
        })
        .await?;
    admin_client1
        .add_learner(pb::raft::AddLearnerRequest {
            node: Some(new_node_with_port(3, GET_BY_KEY_PORT_BASE)),
        })
        .await?;

    admin_client1
        .change_membership(pb::raft::ChangeMembershipRequest {
            members: vec![1, 2, 3],
            retain: false,
        })
        .await?;

    TypeConfig::sleep(Duration::from_millis(500)).await;

    let metrics = admin_client1.metrics(()).await?.into_inner();
    assert_eq!(
        metrics.current_leader,
        Some(1),
        "node 1 must be leader for this test"
    );

    let iterations = 20;
    let mut failures = 0;

    for i in 0..iterations {
        let key = format!("race:get:{}", i);
        let val = format!("value-{}", i);

        instance1
            .storage
            .set_value(key.clone(), make_sensitive_env(&val)?, None, None)
            .await?;

        let get_result = instance2.storage.get_by_key(key.as_bytes(), None).await?;

        match get_result {
            Some(envelope) => {
                let read_val = envelope.try_deserialize::<String>()?.data;
                if read_val != val {
                    failures += 1;
                    println!(
                        "ITER {} (get_by_key): value mismatch: expected '{}', got '{}'",
                        i, val, read_val
                    );
                }
            }
            None => {
                failures += 1;
                println!(
                    "ITER {} (get_by_key): key '{}' not found on follower (race confirmed)",
                    i, key
                );
            }
        }
    }

    for i in 0..iterations {
        let key = format!("race:prefix:{}", i);
        let val = format!("prefix-value-{}", i);

        instance1
            .storage
            .set_value(key.clone(), make_sensitive_env(&val)?, None, None)
            .await?;

        let prefix_results = instance3
            .storage
            .prefix("race:prefix:".as_bytes(), None)
            .await?;

        let found = prefix_results.iter().any(|(k, _)| k == &key);
        if !found {
            failures += 1;
            println!(
                "ITER {} (prefix): key '{}' not found in prefix scan on follower (race confirmed)",
                i, key
            );
        }
    }

    println!(
        "Replication race test complete: {} failures out of {} iterations ({} total operations)",
        failures,
        iterations,
        iterations * 2
    );

    if failures > 0 {
        panic!(
            "Replication race detected: {} failures out of {} total operations",
            failures,
            iterations * 2
        );
    }

    Ok(())
}

/// Regression test: write-then-delete race on follower reads.
///
/// Reproduces the pattern where a key is deleted on the leader but still
/// appears in a follower's local FjallDB (stale read returns deleted data).
///
/// This mirrors the `api_v4::mapping::ruleset::delete::test_delete_mapping_ruleset`
/// failure: DELETE returns 204 on leader, but subsequent GET on follower returns
/// 200 with the deleted data instead of 404.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_replication_race_delete_stale_read() {
    TypeConfig::run(test_replication_race_delete_stale_inner()).unwrap();
}

// Port offset to avoid conflicts with other cluster tests.
const DELETE_STALE_PORT_BASE: u16 = 200;

#[allow(unsafe_code)]
async fn test_replication_race_delete_stale_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let tls_configuration = make_certificates()?;

    let instance1 = Arc::new(
        InstanceHolder::new_with_port(1, DELETE_STALE_PORT_BASE, tls_configuration.clone()).await?,
    );
    let instance2 = Arc::new(
        InstanceHolder::new_with_port(2, DELETE_STALE_PORT_BASE, tls_configuration.clone()).await?,
    );
    let instance3 = Arc::new(
        InstanceHolder::new_with_port(3, DELETE_STALE_PORT_BASE, tls_configuration.clone()).await?,
    );

    let inst1 = instance1.clone();
    let _h1 = thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let _ = rt.block_on(start_raft_app(&inst1.config, &inst1.storage));
    });

    let inst2 = instance2.clone();
    let _h2 = thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let _ = rt.block_on(start_raft_app(&inst2.config, &inst2.storage));
    });

    let inst3 = instance3.clone();
    let _h3 = thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let _ = rt.block_on(start_raft_app(&inst3.config, &inst3.storage));
    });

    TypeConfig::sleep(Duration::from_millis(200)).await;

    let tls_client_config = get_client_tls_config(&instance1.config)?;
    let mut admin_client1 = new_admin_client(
        instance1
            .config
            .distributed_storage
            .as_ref()
            .unwrap()
            .node_cluster_addr
            .clone(),
        &tls_client_config,
    )
    .await?;

    admin_client1
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, DELETE_STALE_PORT_BASE)],
        })
        .await?;
    wait_for_leader(&mut admin_client1, 1).await;

    admin_client1
        .add_learner(pb::raft::AddLearnerRequest {
            node: Some(new_node_with_port(2, DELETE_STALE_PORT_BASE)),
        })
        .await?;
    admin_client1
        .add_learner(pb::raft::AddLearnerRequest {
            node: Some(new_node_with_port(3, DELETE_STALE_PORT_BASE)),
        })
        .await?;

    admin_client1
        .change_membership(pb::raft::ChangeMembershipRequest {
            members: vec![1, 2, 3],
            retain: false,
        })
        .await?;

    TypeConfig::sleep(Duration::from_millis(500)).await;

    let metrics = admin_client1.metrics(()).await?.into_inner();
    assert_eq!(
        metrics.current_leader,
        Some(1),
        "node 1 must be leader for this test"
    );

    let iterations = 20;
    let mut failures = 0;

    for i in 0..iterations {
        let key = format!("race:del:{}", i);
        let val = format!("del-value-{}", i);

        instance1
            .storage
            .set_value(key.clone(), make_env(&val)?, None, None)
            .await?;

        // Wait for replication so the key definitely exists on followers.
        TypeConfig::sleep(Duration::from_millis(500)).await;

        let pre_del = instance2.storage.get_by_key(key.as_bytes(), None).await?;
        assert!(
            pre_del.is_some(),
            "key '{}' must exist on follower before delete",
            key
        );

        instance1.storage.remove(key.clone(), None).await?;

        let post_del = instance2.storage.get_by_key(key.as_bytes(), None).await?;

        match post_del {
            Some(_) => {
                failures += 1;
                println!(
                    "ITER {} (delete race): key '{}' still exists on follower after delete (stale read)",
                    i, key
                );
            }
            None => {
                // Good — follower has caught up with the delete.
            }
        }

        let post_prefix = instance3
            .storage
            .prefix("race:del:".as_bytes(), None)
            .await?;
        let deleted_key_in_prefix = post_prefix.iter().any(|(k, _)| k == &key);
        if deleted_key_in_prefix {
            failures += 1;
            println!(
                "ITER {} (delete prefix race): key '{}' still in prefix on follower after delete",
                i, key
            );
        }
    }

    println!(
        "Delete-then-read race test complete: {} failures out of {} iterations ({} total operations)",
        failures,
        iterations,
        iterations * 2
    );

    if failures > 0 {
        panic!(
            "Delete stale-read race detected: {} failures out of {} total operations",
            failures,
            iterations * 2
        );
    }

    Ok(())
}

async fn new_admin_client(
    addr: Uri,
    client_tls_config: &ClientTlsConfig,
) -> Result<ClusterAdminServiceClient<Channel>> {
    let endpoint = Channel::builder(addr).tls_config(client_tls_config.clone())?;
    let client = ClusterAdminServiceClient::new(endpoint.connect().await?);
    Ok(client)
}

fn new_node(node_id: u64) -> pb::raft::Node {
    new_node_with_port(node_id, 0)
}

fn new_node_with_port(node_id: u64, port_base: u16) -> pb::raft::Node {
    pb::raft::Node {
        node_id,
        rpc_addr: get_addr_with_port(node_id, port_base).to_string(),
    }
}

fn get_addr(node_id: u64) -> SocketAddr {
    get_addr_with_port(node_id, 0)
}

fn get_addr_with_port(node_id: u64, port_base: u16) -> SocketAddr {
    let port = port_base + 21000 + node_id as u16;
    format!("127.0.0.1:{}", port).parse().unwrap()
}

async fn wait_for_leader(client: &mut ClusterAdminServiceClient<Channel>, expected_leader: u64) {
    for _ in 0..50 {
        if let Ok(resp) = client.metrics(()).await {
            if resp.into_inner().current_leader == Some(expected_leader) {
                return;
            }
        }
        TypeConfig::sleep(Duration::from_millis(100)).await;
    }
    panic!("leader {expected_leader} not elected within 5 seconds");
}

pub async fn start_raft_app(
    config: &Config,
    storage: &Storage,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ds_config = config
        .distributed_storage
        .as_ref()
        .expect("ds config must be present");
    let http_addr = ds_config.node_listener_addr;
    let node_id = ds_config.node_id;

    let tls_config = get_server_tls_config(config)?;
    let mut server = tonic::transport::Server::builder().tls_config(tls_config)?;

    let server_future = server
        .add_routes(get_app_server(storage).await?)
        .serve(http_addr);

    println!("Node {node_id} starting server at {http_addr}");
    server_future.await?;

    Ok(())
}

fn make_certificates() -> Result<TlsConfiguration> {
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

    Ok(TlsConfigurationBuilder::default()
        .tls_client_ca_content(ca_cert.pem().as_bytes().to_vec())
        .tls_cert_content(peer_cert.pem().as_bytes().to_vec())
        .tls_key_content(peer_key.serialize_pem().as_bytes().to_vec())
        .build()?)
}

fn get_ds_config(
    node_id: u64,
    db_path: PathBuf,
    tls_config: TlsConfiguration,
) -> DistributedStorageConfiguration {
    get_ds_config_with_port(node_id, 0, db_path, tls_config)
}

fn get_ds_config_with_port(
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
        tls_configuration: openstack_keystone_config::RaftTlsConfiguration::Tls(tls_config.clone()),
        dev_mode: true,
        retry_join_nodes: vec![],
    }
}
