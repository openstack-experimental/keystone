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
//! Basic cluster operation and node restart.

use super::harness::*;
use super::*;

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
/// 3. check_node_id_uniqueness should NOT reject the restart — same logical
///    address.
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
        tls_configuration: RaftTlsConfiguration::Tls(tls_configuration.clone()),
        dev_mode: true,
        kek_provider: KekProvider::Env,
        ..Default::default()
    };
    let config = ds_config;

    // SAFETY: no concurrent env reads
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
        std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
    }
    let storage = init_storage(&config_manager(config.clone())).await?;
    assert!(!storage.is_initialized().await?);

    // Initialize as single-node cluster

    // Start server in a thread with a shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let stg = storage.clone();
    let cfg = config.clone();
    let _srv = std::thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        rt.block_on(async {
            let ds = &cfg;
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
    let mut admin_client =
        new_admin_client(config.node_cluster_addr.clone(), &tls_client_config).await?;

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
    //
    // Dropping the `Storage` handle alone does NOT stop the RaftCore
    // background task: `Raft`'s Drop impl doesn't shut it down, so it keeps
    // running and holding its `Arc<Database>` clone, which keeps the Fjall
    // file lock held. `shutdown()` must be awaited explicitly (it joins the
    // RaftCore task) before the Fjall lock is actually released.
    storage.raft.shutdown().await.ok();
    drop(storage);
    drop(admin_client);
    drop(tls_client_config);
    // Signal server thread to shut down so Fjall releases locks
    let _ = shutdown_tx.send(());
    _srv.join().ok();
    TypeConfig::sleep(Duration::from_millis(500)).await;

    // Step 2: Reinitialize the SAME storage dir but with schema prefix +
    // trailing slash This simulates pod restart where Uri::Display produces "https://host:port/"
    let ds_config_restart = DistributedStorageConfiguration {
        node_cluster_addr: "https://127.0.0.1:21005/".parse().expect("valid address"),
        node_listener_addr: "127.0.0.1:21005".parse().expect("valid address"),
        node_id: 1,
        path: storage_dir.path().to_path_buf(),
        tls_configuration: RaftTlsConfiguration::Tls(tls_configuration.clone()),
        dev_mode: true,
        kek_provider: KekProvider::Env,
        ..Default::default()
    };
    let config_restart = ds_config_restart;

    // SAFETY: no concurrent env reads
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
        std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
    }

    // This must succeed — the address change is purely cosmetic.
    // If normalization is broken, this fails with:
    // "FATAL: node_id 1 already registered in cluster at 127.0.0.1:21005;
    //  refusing to start with address https://127.0.0.1:21005/"
    let storage_restart = init_storage(&config_manager(config_restart.clone())).await?;

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
        instance1.config.node_cluster_addr.clone(),
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
        // Wait until node 1 has committed the init membership and elected
        // itself leader.
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

        // Write Sensitive-tier data so that `prefix` enters the
        // ensure_linearizable path and forwards to the leader for a
        // linearizable read.
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

        // Immediate re-read after write (no replication sleep) — this
        // reproduces the k8s_auth race condition pattern:
        // `upsert_virtual_user_shadow` writes then immediately reads
        // the same key without waiting for Raft replication.
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
        // On a follower node, `get_by_key` calls
        // `ensure_linearizable(ReadIndex)` which returns
        // `ForwardToLeader`. The storage code must catch this error and
        // fall back to a local FjallDB read. This regression test ensures that
        // reads on followers do NOT fail with "ReadIndex failed:
        // ForwardToLeader".
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
            // `prefix` only enters `ensure_linearizable(ReadIndex)` when any
            // result entry has `tier >= DataTier::Sensitive`
            // (app.rs:461). On a follower, ReadIndex returns
            // `ForwardToLeader`. The storage code must catch this
            // and fall back to a local FjallDB read.
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

    println!("=== ephemeral data replicates across nodes without Fjall");
    {
        let ephemeral_env = StoreDataEnvelope {
            data: rmp_serde::to_vec("ephemeral_value")?,
            metadata: Metadata::ephemeral(),
        };
        instance1
            .storage
            .set_value(
                "eph:k1".to_string(),
                ephemeral_env,
                Some("webauthn_state_test".to_string()),
                None,
            )
            .await?;

        // --- Wait for a while to let the replication get done.
        TypeConfig::sleep(Duration::from_millis(1_000)).await;

        for instance in &instances {
            let got = instance
                .storage
                .get_by_key("eph:k1".as_bytes(), Some("webauthn_state_test"))
                .await?
                .expect("ephemeral value must be readable from every node");
            assert!(got.metadata.is_ephemeral);
            assert_eq!("ephemeral_value", got.try_deserialize::<String>()?.data);
        }

        // Remove on a different node than it was written from, and confirm
        // the delete also replicates.
        instance2
            .storage
            .remove(
                "eph:k1".to_string(),
                Some("webauthn_state_test".to_string()),
            )
            .await?;
        TypeConfig::sleep(Duration::from_millis(1_000)).await;
        for instance in &instances {
            let got = instance
                .storage
                .get_by_key("eph:k1".as_bytes(), Some("webauthn_state_test"))
                .await?;
            assert!(got.is_none());
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

        // Regression for issue #1302 part 1: nodes removed from the cluster
        // (1, 2) must NOT be able to serve reads from their local FjallDB
        // copy any more, even though it still physically contains the
        // committed state. They can no longer reach quorum to confirm
        // linearizability (ADR 0016-v2 §3 / security invariant 4 — no stale
        // reads for sensitive data), so `get_by_key` must fail rather than
        // silently return that possibly-stale copy.
        //
        // A removed node may legitimately still know leader 3 (it received
        // the membership entry and the leader's vote before being dropped).
        // In that case `ReadIndex` yields ForwardToLeader and the read is
        // served by the leader, which is linearizable. Whether that happens
        // depends on timing, so both outcomes are acceptable; what must never
        // happen is a read from the node's own stale copy. Distinguish the
        // two by reading a key written after removal: the removed nodes never
        // replicated it, so only a forwarded read can return it.
        let post_removal = StoreDataEnvelope {
            data: rmp_serde::to_vec("written_after_removal")?,
            metadata: Metadata::with_tier(DataTier::Sensitive),
        };
        instance3
            .storage
            .set_value("sec:post_removal".to_string(), post_removal, None, None)
            .await?;
        for instance in &[instance1, instance2] {
            let result = instance
                .storage
                .get_by_key("sec:post_removal".as_bytes(), None)
                .await;
            match result {
                Err(ApiStoreError::Unavailable(_)) => {}
                // Right after the removal the node can still be told by the
                // leader to forward to a leader that has just changed: a
                // refusal, not a stale read.
                Err(ref e) if format!("{e:?}").contains("not linearizable leader") => {}
                Ok(Some(env)) => assert_eq!(
                    "written_after_removal",
                    env.try_deserialize::<String>()?.data,
                    "removed node {} returned unexpected data",
                    instance.node_id
                ),
                other => panic!(
                    "removed node {} must refuse the read or forward it to the \
                     leader, never serve a stale local read, got {:?}",
                    instance.node_id, other
                ),
            }
        }
    }

    Ok(())
}
