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
//! Node join, snapshot catch-up and node-ID uniqueness checks.

use super::harness::*;
use super::*;

/// A node whose `node_id` is already live on a reachable peer under a
/// different address must refuse to start, even though its own local
/// (empty) Raft state has no record of the conflict — exercising
/// `verify_node_id_uniqueness_live` (ADR 0016-v2 §4.3 / F7).
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_live_uniqueness_check_detects_conflict() {
    TypeConfig::run(test_live_uniqueness_check_detects_conflict_inner()).unwrap();
}

#[allow(unsafe_code)]
async fn test_live_uniqueness_check_detects_conflict_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let tls_configuration = make_certificates()?;

    // SAFETY: no concurrent env reads; test is `#[serial_test::serial]`.
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
        std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
    }

    // Node A: bootstraps as a single-node cluster and stays live.
    let storage_dir_a = tempfile::TempDir::new().unwrap();
    let ds_config_a = get_ds_config(
        200,
        storage_dir_a.path().to_path_buf(),
        tls_configuration.clone(),
    );
    let config_a = ds_config_a;

    let storage_a = init_storage(&config_manager(config_a.clone())).await?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let stg_a = storage_a.clone();
    let cfg_a = config_a.clone();
    let _srv = std::thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        rt.block_on(async {
            let ds = &cfg_a;
            let tls = get_server_tls_config(&cfg_a).unwrap();
            let mut s = tonic::transport::Server::builder().tls_config(tls).unwrap();
            let serve = s
                .add_routes(get_app_server(&stg_a).await.unwrap())
                .serve(ds.node_listener_addr);
            tokio::select! {
                _ = serve => {},
                _ = shutdown_rx => {},
            }
        });
    });
    TypeConfig::sleep(Duration::from_millis(200)).await;

    let tls_client_config = get_client_tls_config(&config_a)?;
    let mut admin_client =
        new_admin_client(config_a.node_cluster_addr.clone(), &tls_client_config).await?;
    admin_client
        .init(pb::raft::InitRequest {
            nodes: vec![new_node(200)],
        })
        .await?;
    wait_for_leader(&mut admin_client, 200).await;

    // Node B: same node_id (200), different address, fresh (empty) local
    // storage — its own local check has nothing to compare against, but
    // retry_join_nodes points at node A's live, reachable address.
    let storage_dir_b = tempfile::TempDir::new().unwrap();
    let mut ds_config_b = get_ds_config_with_port(
        200,
        50,
        storage_dir_b.path().to_path_buf(),
        tls_configuration,
    );
    ds_config_b.retry_join_nodes = vec![(200, get_addr(200).to_string())];
    let config_b = ds_config_b;

    // from_env() removes KEYSTONE_DEV_KEK after reading it, so it must be
    // re-set before every init_storage call in this process.
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
        std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
    }
    let result = init_storage(&config_manager(config_b)).await;

    // Clean up node A's server before asserting, so a failure doesn't leak
    // the thread/port into subsequent tests.
    drop(admin_client);
    drop(tls_client_config);
    drop(storage_a);
    let _ = shutdown_tx.send(());
    _srv.join().ok();

    let Err(err) = result else {
        panic!(
            "init_storage must refuse to start when a live peer reports the same \
             node_id at a different address"
        );
    };
    assert!(
        format!("{err:?}").contains("already registered")
            || format!("{err:?}").contains("is registered at"),
        "unexpected error: {err:?}"
    );

    Ok(())
}

/// When `retry_join_nodes` is configured but every listed peer is
/// unreachable, `init_storage` must still start rather than refuse — a
/// strict fail-closed policy here would make it impossible to recover from
/// a full-cluster outage where every node restarts simultaneously with no
/// live peer to ask (ADR 0016-v2 §4.3 / F7, deliberate deviation
/// documented on `verify_node_id_uniqueness_live`).
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_live_uniqueness_check_proceeds_when_no_peer_reachable() {
    TypeConfig::run(test_live_uniqueness_check_proceeds_when_no_peer_reachable_inner()).unwrap();
}

#[allow(unsafe_code)]
async fn test_live_uniqueness_check_proceeds_when_no_peer_reachable_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let storage_dir = tempfile::TempDir::new().unwrap();
    let tls_configuration = make_certificates()?;
    let mut ds_config = get_ds_config(210, storage_dir.path().to_path_buf(), tls_configuration);
    // Points at an address with nothing listening — every contact attempt
    // must fail, exercising the "no peer reachable" branch.
    ds_config.retry_join_nodes = vec![(210, "127.0.0.1:21999".to_string())];

    let config = ds_config;

    // SAFETY: no concurrent env readers; test is `#[serial_test::serial]`.
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
        std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
    }

    init_storage(&config_manager(config)).await.map_err(|e| {
        eyre::eyre!(
            "init_storage must proceed (with a warning) when no configured peer is \
                 reachable, not refuse to start: {e}"
        )
    })?;

    Ok(())
}

/// GitHub issue #1298 regression test: a node joining a cluster that
/// already has data must adopt the leader's actual DEK instead of its own
/// first-boot, randomly generated one, so it can decrypt data it receives
/// via Raft.
///
/// Before the fix, `crate::new()` unconditionally bootstraps a fresh,
/// random per-node DEK at first boot; nothing distributed the cluster's
/// real DEK to a joining node, so its own epoch-1 key differs from the
/// leader's epoch-1 key. `Storage::join_cluster` now fetches the leader's
/// current DEK (`FetchDek`) and installs it locally before registering as
/// a learner, so the joining node's epoch matches the leader's exactly.
///
/// This test exercises `join_cluster` end to end (not a raw `add_learner`
/// call against an admin client, which every other test in this file
/// uses and which bypasses the fix entirely) and verifies decryption
/// directly against the leader's `Metadata`, rather than through
/// `StorageApi::get_by_key`, because `build_snapshot` does not carry the
/// per-key `Metadata` keyspace (a separate, already tracked gap: GitHub
/// issue #1293) -- so a snapshot-caught-up learner's `get_by_key` would
/// return `None` for reasons unrelated to this fix. Reproducing the
/// specific "learner catch-up via InstallSnapshot after log compaction"
/// scenario from the issue originally hit a further, separate bug (GitHub
/// issue #1329: a purged-log leader never resumed replicating to a newly
/// added learner, independent of `join_cluster`/DEKs -- confirmed by
/// bisecting to a raw `add_learner` call). That bug is now fixed and has
/// its own regression test,
/// `test_purge_then_join_learner_catches_up_via_snapshot`; this test still
/// joins before any compaction, since post-compaction catch-up is that
/// other test's concern and joining early is sufficient to exercise the
/// DEK-adoption logic this issue is about.
const JOIN_DEK_PORT_BASE: u16 = 400;

#[serial_test::serial]
#[test]
fn test_join_adopts_cluster_dek() {
    TypeConfig::run(async {
        test_join_adopts_cluster_dek_inner().await.unwrap();
    });
}

async fn test_join_adopts_cluster_dek_inner() -> Result<()> {
    // Crypto provider may already be installed by a parallel test.
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let tls_configuration = make_certificates()?;

    // --- Start node 1 alone and bootstrap a single-node cluster.
    let instance1 = Arc::new(
        InstanceHolder::new_with_port(1, JOIN_DEK_PORT_BASE, tls_configuration.clone()).await?,
    );
    let inst1 = instance1.clone();
    let _h1 = thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let x = rt.block_on(start_raft_app(&inst1.config, &inst1.storage));
        println!("raft app exit result: {:?}", x);
    });
    TypeConfig::sleep(Duration::from_millis(200)).await;

    let tls_client_config = get_client_tls_config(&instance1.config)?;
    let mut admin_client1 = new_admin_client(
        instance1.config.node_cluster_addr.clone(),
        &tls_client_config,
    )
    .await?;

    admin_client1
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, JOIN_DEK_PORT_BASE)],
        })
        .await?;
    wait_for_leader(&mut admin_client1, 1).await;

    // --- Write some keys before node 2 ever exists, so node 2's join has
    //     to catch up on data encrypted before it was around.
    const NUM_KEYS: usize = 20;
    for i in 0..NUM_KEYS {
        instance1
            .storage
            .set_value(format!("k{i}"), make_env(&format!("v{i}"))?, None, None)
            .await?;
    }
    TypeConfig::sleep(Duration::from_millis(500)).await;

    // --- Bring up node 2 completely fresh. By the time `InstanceHolder::new`
    //     returns, `crate::new()` has already bootstrapped node 2's own
    //     random, node-local placeholder DEK (lib.rs `bootstrap_dek`'s
    //     first-boot branch) -- before the fix, this is the DEK node 2 would
    //     keep forever, regardless of what the leader is using.
    let instance2 = Arc::new(
        InstanceHolder::new_with_port(2, JOIN_DEK_PORT_BASE, tls_configuration.clone()).await?,
    );
    let inst2 = instance2.clone();
    let _h2 = thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let x = rt.block_on(start_raft_app(&inst2.config, &inst2.storage));
        println!("raft app exit result: {:?}", x);
    });
    // Wait for node 2's own listener to bind before it registers as a
    // learner, mirroring `ensure_raft_initialized`'s `listener_bound` wait.
    TypeConfig::sleep(Duration::from_millis(200)).await;

    // Bare "host:port", matching `new_node()`'s convention (no scheme, no
    // trailing slash) -- this is the exact string that gets stored as this
    // node's `Node.rpc_addr` in the Raft membership config and later used
    // by the leader to dial back for replication, so it must match the
    // format every other node in this file registers under.
    let leader_addr = get_addr_with_port(1, JOIN_DEK_PORT_BASE).to_string();
    let my_addr = get_addr_with_port(2, JOIN_DEK_PORT_BASE).to_string();

    // This is the method under test: it calls `FetchDek` and installs the
    // returned DEK locally *before* calling `add_learner`, so node 2 never
    // holds its own bootstrap-generated placeholder DEK once the leader
    // starts replicating to it.
    instance2
        .storage
        .join_cluster(&leader_addr, &my_addr)
        .await?;

    // `add_learner`'s blocking wait only guarantees the leader has *some*
    // replication state for node 2 within its (generous, absolute)
    // replication-lag threshold -- not that node 2's log has actually
    // caught up (that threshold trivially passes for logs this short) --
    // so poll for real catch-up explicitly.
    let leader_index = instance1
        .storage
        .last_log_index()
        .expect("node 1 must have a non-empty log by now");
    let mut caught_up = false;
    for _ in 0..100 {
        if instance2.storage.last_log_index() >= Some(leader_index) {
            caught_up = true;
            break;
        }
        TypeConfig::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        caught_up,
        "node 2 did not catch up to leader's log index {leader_index} within 10s \
         (node 2's last_log_index: {:?})",
        instance2.storage.last_log_index()
    );

    // --- The key assertion: node 2 must decrypt every ciphertext value it
    //     received, using its own (now leader-adopted) DEK. Node 1 (the
    //     leader) still has the `Metadata` for tier/dek_version from its own
    //     write path; reading it from there and decrypting node 2's
    //     replicated ciphertext with it isolates exactly what issue #1298 is
    //     about: does node 2's own DEK epoch produce the same key bytes as
    //     the leader's.
    for i in 0..NUM_KEYS {
        let key = format!("k{i}");
        let metadata = instance1
            .storage
            .state_machine_store()
            .meta()
            .get(meta_key("data", key.as_bytes()))?
            .map(|raw| Metadata::unpack(raw.as_ref()))
            .transpose()?
            .unwrap_or_else(|| panic!("node 1 must have Metadata for {key}"));
        let ciphertext = instance2
            .storage
            .state_machine_store()
            .data()
            .get(key.as_bytes())?
            .unwrap_or_else(|| panic!("node 2 must have ciphertext for {key} after replication"));
        let plaintext = instance2
            .storage
            .state_machine_store()
            .decrypt_state(
                ciphertext.as_ref(),
                metadata.tier as u8,
                b"data",
                key.as_bytes(),
                metadata.dek_version,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "node 2 must decrypt {key} with its own DEK epoch, matching the leader's \
                     (GitHub issue #1298): {e}"
                )
            });
        let value: String = rmp_serde::from_slice(&plaintext)?;
        assert_eq!(format!("v{i}"), value);
    }

    Ok(())
}

/// GitHub issue #1329 regression test: after the leader's log is
/// snapshotted and purged, a learner added afterward must still catch up
/// (via `InstallSnapshot`, since the log entries it would need are gone).
///
/// Before the fix, `NetworkConnection::full_snapshot` (`network.rs`) awaited
/// the client-streaming `Snapshot` RPC's response *before* sending anything
/// into the channel backing its request stream. Since the server (see
/// `RaftServiceImpl::snapshot`) does not reply until it has read the whole
/// request stream, and nothing else drives that channel, the leader's
/// snapshot-transmitter task deadlocked against itself on every attempt to
/// install a snapshot -- silently, since the surrounding retry loop only
/// logs on `Err`, and a hung `.await` produces neither an `Err` nor any
/// further tracing. The purged learner then never left `RaftMetrics.snapshot
/// = None`, regardless of how long the leader kept retrying.
const PURGE_JOIN_PORT_BASE: u16 = 600;

#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_purge_then_join_learner_catches_up_via_snapshot() {
    TypeConfig::run(async {
        test_purge_then_join_learner_catches_up_via_snapshot_inner()
            .await
            .unwrap();
    });
}

async fn test_purge_then_join_learner_catches_up_via_snapshot_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let tls_configuration = make_certificates()?;

    let instance1 = Arc::new(
        InstanceHolder::new_with_port(1, PURGE_JOIN_PORT_BASE, tls_configuration.clone()).await?,
    );
    let inst1 = instance1.clone();
    let _h1 = thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let x = rt.block_on(start_raft_app(&inst1.config, &inst1.storage));
        println!("node 1 raft app exit result: {:?}", x);
    });
    TypeConfig::sleep(Duration::from_millis(200)).await;

    let tls_client_config = get_client_tls_config(&instance1.config)?;
    let mut admin_client1 = new_admin_client(
        instance1.config.node_cluster_addr.clone(),
        &tls_client_config,
    )
    .await?;

    admin_client1
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, PURGE_JOIN_PORT_BASE)],
        })
        .await?;
    wait_for_leader(&mut admin_client1, 1).await;

    const NUM_KEYS: usize = 20;
    for i in 0..NUM_KEYS {
        instance1
            .storage
            .set_value(format!("k{i}"), make_env(&format!("v{i}"))?, None, None)
            .await?;
    }
    TypeConfig::sleep(Duration::from_millis(200)).await;

    let upto = instance1
        .storage
        .last_log_index()
        .ok_or_else(|| eyre::eyre!("node 1 must have a non-empty log after writes"))?;
    println!("=== triggering snapshot at last_log_index={upto}");
    instance1.storage.raft.trigger().snapshot().await?;
    poll_until(Duration::from_millis(100), 100, || {
        instance1
            .storage
            .raft
            .metrics()
            .borrow_watched()
            .snapshot
            .is_some()
    })
    .await;
    let snapshot_log_id = instance1.storage.raft.metrics().borrow_watched().snapshot;
    println!("=== snapshot built: {:?}", snapshot_log_id);
    assert!(snapshot_log_id.is_some(), "snapshot never completed");

    println!("=== triggering purge_log upto={upto}");
    instance1.storage.raft.trigger().purge_log(upto).await?;
    poll_until(Duration::from_millis(100), 100, || {
        instance1
            .storage
            .raft
            .metrics()
            .borrow_watched()
            .purged
            .index()
            >= Some(upto)
    })
    .await;
    let purged = instance1.storage.raft.metrics().borrow_watched().purged;
    println!("=== purged: {:?}", purged);
    assert!(purged.index() >= Some(upto), "purge never completed");

    // --- Bring up node 2 fresh, after the leader's log is already purged.
    let instance2 = Arc::new(
        InstanceHolder::new_with_port(2, PURGE_JOIN_PORT_BASE, tls_configuration.clone()).await?,
    );
    let inst2 = instance2.clone();
    let _h2 = thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let x = rt.block_on(start_raft_app(&inst2.config, &inst2.storage));
        println!("node 2 raft app exit result: {:?}", x);
    });
    TypeConfig::sleep(Duration::from_millis(200)).await;

    println!("=== add-learner 2 (post-purge)");
    admin_client1
        .add_learner(pb::raft::AddLearnerRequest {
            node: Some(new_node_with_port(2, PURGE_JOIN_PORT_BASE)),
        })
        .await?;

    let caught_up = poll_until(Duration::from_millis(100), 100, || {
        instance2.storage.last_log_index() >= Some(upto)
    })
    .await;
    assert!(
        caught_up,
        "node 2 did not catch up to leader's log index {upto} within 10s \
         (node 2's last_log_index: {:?})",
        instance2.storage.last_log_index()
    );

    Ok(())
}

/// Brings up node 2 fresh and joins it the way `keystone-manage storage
/// join` does: node 2 is asked to adopt the leader's DEK over the admin RPC
/// (it is not a member yet), then registered as a learner and promoted.
async fn join_node2_through_admin_rpcs(
    port_base: u16,
    tls_configuration: &TlsConfiguration,
    admin_client1: &mut ClusterAdminServiceClient<Channel>,
) -> Result<Arc<InstanceHolder>> {
    let instance2 =
        Arc::new(InstanceHolder::new_with_port(2, port_base, tls_configuration.clone()).await?);
    spawn_raft_app(&instance2).await;
    let tls_client_config = get_client_tls_config(&instance2.config)?;
    let mut admin_client2 = new_admin_client(
        instance2.config.node_cluster_addr.clone(),
        &tls_client_config,
    )
    .await?;
    admin_client2
        .adopt_cluster_dek(pb::raft::AdoptClusterDekRequest {
            leader_addr: get_addr_with_port(1, port_base).to_string(),
        })
        .await?;
    admin_client1
        .add_learner(pb::raft::AddLearnerRequest {
            node: Some(new_node_with_port(2, port_base)),
        })
        .await?;
    admin_client1
        .change_membership(pb::raft::ChangeMembershipRequest {
            members: vec![1, 2],
            retain: false,
        })
        .await?;
    Ok(instance2)
}

/// M1 exit criterion (#1289): a node added via `join` after the log was
/// compacted by openraft's *default* snapshot policy
/// (`LogsSinceLast(5000)`, no manual trigger) must serve the same reads as
/// the leader for every keyspace.
const AUTO_SNAPSHOT_JOIN_PORT_BASE: u16 = 700;

#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_join_after_automatic_compaction_serves_all_keyspaces() {
    TypeConfig::run(async {
        test_join_after_automatic_compaction_serves_all_keyspaces_inner(
            AUTO_SNAPSHOT_JOIN_PORT_BASE,
            false,
        )
        .await
        .unwrap();
    });
}

/// The same scenario through the `keystone-manage storage join` path
/// (GitHub #1445): the CLI asks the not-yet-joined node to adopt the
/// cluster DEK over the admin RPC and then registers it as a learner; the
/// node never replicates under its own bootstrap DEK, so the snapshot it
/// receives after log compaction decrypts and every key is served.
const CLI_JOIN_PORT_BASE: u16 = 1550;

#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_cli_join_after_compaction_adopts_cluster_dek() {
    TypeConfig::run(async {
        test_join_after_automatic_compaction_serves_all_keyspaces_inner(CLI_JOIN_PORT_BASE, true)
            .await
            .unwrap();
    });
}

async fn test_join_after_automatic_compaction_serves_all_keyspaces_inner(
    port_base: u16,
    via_cli_path: bool,
) -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls_configuration = make_certificates()?;

    let (instance1, mut admin_client1) =
        start_single_node_cluster(port_base, &tls_configuration).await?;

    // Comfortably more than the 5000-entry default snapshot threshold.
    const NUM_RECORDS: usize = 5400;
    write_index_and_sensitive_records(&instance1.storage).await?;
    write_records_concurrently(&instance1.storage, NUM_RECORDS).await?;

    // The leader must have compacted on its own: no `trigger().snapshot()`
    // / `purge_log` anywhere in this test.
    let compacted = poll_until(Duration::from_millis(200), 150, || {
        let m = instance1.storage.raft.metrics();
        let m = m.borrow_watched();
        m.snapshot.index() >= Some(5000) && m.purged.index() > Some(0)
    })
    .await;
    let m = instance1.storage.raft.metrics().borrow_watched().clone();
    assert!(
        compacted,
        "leader never snapshotted and purged on its own (snapshot: {:?}, purged: {:?})",
        m.snapshot, m.purged
    );
    println!(
        "=== leader compacted: snapshot={:?} purged={:?}",
        m.snapshot, m.purged
    );

    assert_serves_all_records(&instance1.storage, NUM_RECORDS, "leader").await?;

    // --- The joiner's missing log prefix is gone: it can only catch up via
    //     InstallSnapshot.
    let instance2 = if via_cli_path {
        join_node2_through_admin_rpcs(port_base, &tls_configuration, &mut admin_client1).await?
    } else {
        join_node2_as_voter(port_base, &tls_configuration, &mut admin_client1).await?
    };
    let leader_index = instance1
        .storage
        .last_log_index()
        .ok_or_else(|| eyre::eyre!("leader must have a log"))?;
    let caught_up = poll_until(Duration::from_millis(200), 150, || {
        instance2.storage.last_log_index() >= Some(leader_index)
    })
    .await;
    assert!(
        caught_up,
        "node 2 did not catch up to {leader_index} (at {:?})",
        instance2.storage.last_log_index()
    );
    assert!(
        instance2
            .storage
            .raft
            .metrics()
            .borrow_watched()
            .snapshot
            .is_some(),
        "node 2 must have received a snapshot"
    );

    // Reads on a follower go through the leader's ReadIndex, which needs
    // node 2 to have acknowledged a heartbeat as a voter; wait until it has
    // also applied everything instead of racing that.
    let applied = poll_until(Duration::from_millis(200), 150, || {
        instance2
            .storage
            .raft
            .metrics()
            .borrow_watched()
            .last_applied
            .index()
            >= Some(leader_index)
    })
    .await;
    assert!(applied, "node 2 did not apply the leader's log");
    // The first linearizable read through node 2 can still fail briefly
    // while the leader has not yet seen node 2's heartbeat ack as a voter;
    // wait for readiness, then assert exact contents strictly.
    let mut ready = false;
    for _ in 0..100 {
        if instance2
            .storage
            .get_by_key("k0".as_bytes(), None)
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        TypeConfig::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        ready,
        "node 2 never became able to serve linearizable reads"
    );

    assert_serves_all_records(&instance2.storage, NUM_RECORDS, "joined node").await?;
    // Reads may be served by the leader: decrypt what node 2 itself stores
    // with node 2's own DEK, which only works when it adopted the leader's.
    assert_decrypts_locally(&instance1, &instance2, (0..30).step_by(3)).await?;
    if via_cli_path {
        // The adoption went through the admin RPC and was audited once.
        audit_records(&instance2, "CLUSTER_DEK_ADOPTED", 1).await;
    }
    Ok(())
}

/// Decrypts the default-keyspace records `k{i}` straight from `follower`'s
/// state machine, using the metadata the `leader` holds for them.
async fn assert_decrypts_locally(
    leader: &InstanceHolder,
    follower: &InstanceHolder,
    indices: impl Iterator<Item = usize>,
) -> Result<()> {
    for i in indices {
        let key = format!("k{i}");
        let metadata = leader
            .storage
            .state_machine_store()
            .meta()
            .get(meta_key("data", key.as_bytes()))?
            .map(|raw| Metadata::unpack(raw.as_ref()))
            .transpose()?
            .unwrap_or_else(|| panic!("leader must have Metadata for {key}"));
        let ciphertext = follower
            .storage
            .state_machine_store()
            .data()
            .get(key.as_bytes())?
            .unwrap_or_else(|| panic!("follower must have ciphertext for {key}"));
        let plaintext = follower
            .storage
            .state_machine_store()
            .decrypt_state(
                ciphertext.as_ref(),
                metadata.tier as u8,
                b"data",
                key.as_bytes(),
                metadata.dek_version,
            )
            .unwrap_or_else(|e| {
                panic!("follower must decrypt {key} with the leader's DEK (GitHub #1298): {e}")
            });
        let value: String = rmp_serde::from_slice(&plaintext)?;
        assert_eq!(format!("v{i}"), value);
    }
    Ok(())
}
