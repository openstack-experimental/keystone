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
//! Backup, live restore and disaster recovery.

use super::harness::*;
use super::*;

/// Like [`spawn_raft_app`], but the returned sender stops the gRPC server and
/// frees its port, so another node can later take over the same address.
async fn spawn_stoppable_raft_app(
    instance: &Arc<InstanceHolder>,
) -> tokio::sync::oneshot::Sender<()> {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let inst = instance.clone();
    let _handle = thread::spawn(move || {
        let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
        let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = rt.block_on(async {
            let ds_config = &inst.config;
            let tls_config = get_server_tls_config(&inst.config)?;
            let mut server = tonic::transport::Server::builder().tls_config(tls_config)?;
            server
                .add_routes(get_app_server(&inst.storage).await?)
                .serve_with_shutdown(ds_config.node_listener_addr, async {
                    stop_rx.await.ok();
                })
                .await?;
            Ok(())
        });
        println!("stoppable raft app exit result: {:?}", result);
    });
    TypeConfig::sleep(Duration::from_millis(200)).await;
    stop_tx
}

/// M1 exit criterion (#1289): a `backup` / `restore` round trip into a fresh
/// (uninitialized) node -- disaster recovery -- yields identical reads for
/// every keyspace and brings back the backup's Raft membership.
const BACKUP_RESTORE_SRC_PORT_BASE: u16 = 800;

const BACKUP_RESTORE_DST_PORT_BASE: u16 = 850;

#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_backup_restore_round_trip_on_fresh_cluster() {
    TypeConfig::run(async {
        test_backup_restore_round_trip_on_fresh_cluster_inner()
            .await
            .unwrap();
    });
}

async fn test_backup_restore_round_trip_on_fresh_cluster_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls_configuration = make_certificates()?;

    // --- Source cluster with data in every keyspace.
    let (src, mut src_admin) =
        start_single_node_cluster(BACKUP_RESTORE_SRC_PORT_BASE, &tls_configuration).await?;
    const NUM_RECORDS: usize = 300;
    write_index_and_sensitive_records(&src.storage).await?;
    write_records_concurrently(&src.storage, NUM_RECORDS).await?;
    assert_serves_all_records(&src.storage, NUM_RECORDS, "source").await?;

    let mut stream = src_admin
        .backup(pb::raft::BackupRequest {})
        .await?
        .into_inner();
    let mut chunks = Vec::new();
    while let Some(chunk) = stream.message().await? {
        chunks.push(pb::raft::RestoreChunk {
            data: chunk.data,
            elect: false,
            total_len: 0,
        });
    }
    assert!(!chunks.is_empty(), "backup stream was empty");

    // --- Fresh node with its own bootstrap DEK, never initialized: restore
    // installs the backup's Raft state, `elect` starts the election.
    let dst = Arc::new(
        InstanceHolder::new_with_port(1, BACKUP_RESTORE_DST_PORT_BASE, tls_configuration.clone())
            .await?,
    );
    spawn_raft_app(&dst).await;
    let dst_tls_client_config = get_client_tls_config(&dst.config)?;
    let mut dst_admin =
        new_admin_client(dst.config.node_cluster_addr.clone(), &dst_tls_client_config).await?;

    // A blob that is not a backup is refused and audited as a failed
    // disaster recovery attempt.
    let err = dst_admin
        .restore(futures::stream::iter(vec![pb::raft::RestoreChunk {
            data: vec![0xA5; 4096],
            elect: true,
            total_len: 4096,
        }]))
        .await
        .expect_err("a garbage backup must be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
    let failures = audit_records(&dst, "BACKUP_RESTORED_FAILED", 1).await;
    assert!(
        failures[0].contains(r#""mode":"disaster_recovery""#),
        "{}",
        failures[0]
    );
    audit_records(&dst, "BACKUP_RESTORED", 0).await;

    chunks[0].elect = true;
    dst_admin.restore(futures::stream::iter(chunks)).await?;
    audit_records(&dst, "BACKUP_RESTORED", 1).await;
    audit_records(&dst, "BACKUP_RESTORED_FAILED", 1).await;
    wait_for_leader(&mut dst_admin, 1).await;
    let voters: Vec<u64> = dst
        .storage
        .raft
        .metrics()
        .borrow_watched()
        .membership_config
        .membership()
        .voter_ids()
        .collect();
    assert_eq!(vec![1], voters, "the backup's membership must be restored");

    assert_serves_all_records(&dst.storage, NUM_RECORDS, "restored").await?;
    // The restored cluster keeps working: new writes are readable and old
    // records can be overwritten.
    dst.storage
        .set_value("after".to_string(), make_env("restore")?, None, None)
        .await?;
    dst.storage
        .set_value(
            "k1".to_string(),
            make_env("overwritten")?,
            test_keyspace(1),
            None,
        )
        .await?;
    assert_eq!(
        "restore",
        dst.storage
            .get_by_key("after".as_bytes(), None)
            .await?
            .expect("post-restore write must be readable")
            .try_deserialize::<String>()?
            .data
    );
    assert_eq!(
        "overwritten",
        dst.storage
            .get_by_key("k1".as_bytes(), test_keyspace(1).as_deref())
            .await?
            .expect("overwritten record must be readable")
            .try_deserialize::<String>()?
            .data
    );
    Ok(())
}

/// Restore into a running two-node cluster (OpenBao style): the backup of
/// another cluster -- with a different DEK -- goes through the Raft log, both
/// nodes end up with the backup's contents and DEKs, and the membership is
/// untouched.
const LIVE_RESTORE_SRC_PORT_BASE: u16 = 950;

const LIVE_RESTORE_DST_PORT_BASE: u16 = 1000;

#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_restore_into_running_cluster() {
    TypeConfig::run(async {
        test_restore_into_running_cluster_inner().await.unwrap();
    });
}

async fn test_restore_into_running_cluster_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls_configuration = make_certificates()?;

    // --- Source cluster: data in every keyspace, then a backup.
    let (src, mut src_admin) =
        start_single_node_cluster(LIVE_RESTORE_SRC_PORT_BASE, &tls_configuration).await?;
    const NUM_RECORDS: usize = 300;
    write_index_and_sensitive_records(&src.storage).await?;
    write_records_concurrently(&src.storage, NUM_RECORDS).await?;
    let mut stream = src_admin
        .backup(pb::raft::BackupRequest {})
        .await?
        .into_inner();
    let mut chunks = Vec::new();
    while let Some(chunk) = stream.message().await? {
        chunks.push(pb::raft::RestoreChunk {
            data: chunk.data,
            elect: false,
            total_len: 0,
        });
    }
    assert!(!chunks.is_empty(), "backup stream was empty");

    // --- Running destination cluster with its own DEK and different data.
    let (dst1, mut dst_admin) =
        start_single_node_cluster(LIVE_RESTORE_DST_PORT_BASE, &tls_configuration).await?;
    let dst2 = join_node2_as_voter(
        LIVE_RESTORE_DST_PORT_BASE,
        &tls_configuration,
        &mut dst_admin,
    )
    .await?;
    dst1.storage
        .set_value("stale".to_string(), make_env("stale")?, None, None)
        .await?;
    dst1.storage
        .set_value(
            "k1".to_string(),
            make_env("stale-overwritten")?,
            test_keyspace(1),
            None,
        )
        .await?;

    // A declared size over the live limit is rejected before anything is
    // proposed: the stale data stays.
    let mut oversized = chunks.clone();
    oversized[0].total_len = 2 * 1024 * 1024 * 1024;
    let err = dst_admin
        .restore(futures::stream::iter(oversized))
        .await
        .expect_err("oversized restore must be rejected");
    assert_eq!(err.code(), tonic::Code::ResourceExhausted, "{err}");
    assert!(
        get_by_key_retrying(&dst1.storage, "stale".as_bytes(), None)
            .await?
            .is_some(),
        "a rejected upload must leave the existing data alone"
    );

    // An upload shorter than it declared is rejected and cleaned up.
    let mut short = chunks.clone();
    short[0].total_len += 1;
    let err = dst_admin
        .restore(futures::stream::iter(short))
        .await
        .expect_err("a short upload must be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
    assert!(
        get_by_key_retrying(&dst1.storage, "stale".as_bytes(), None)
            .await?
            .is_some(),
        "a rejected upload must leave the existing data alone"
    );

    // A restore sent to a follower is a redirect, not an attempt: the
    // operator retries against the leader and nothing is audited.
    let dst2_client_config = get_client_tls_config(&dst2.config)?;
    let mut follower_admin =
        new_admin_client(dst2.config.node_cluster_addr.clone(), &dst2_client_config).await?;
    follower_admin
        .restore(futures::stream::iter(chunks.clone()))
        .await
        .expect_err("a follower must redirect the restore");
    audit_records(&dst2, "BACKUP_RESTORED_FAILED", 0).await;

    // `--elect` is refused on an initialized cluster.
    let mut elect = chunks.clone();
    elect[0].elect = true;
    let err = dst_admin
        .restore(futures::stream::iter(elect))
        .await
        .expect_err("--elect on an initialized cluster must be rejected");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");

    // A blob that is not a backup passes the upload checks and is rejected
    // by the cluster when it is applied.
    let garbage = vec![pb::raft::RestoreChunk {
        data: vec![0xA5; 4096],
        elect: false,
        total_len: 4096,
    }];
    let err = dst_admin
        .restore(futures::stream::iter(garbage))
        .await
        .expect_err("a garbage backup must be rejected");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");

    // Each rejected attempt left exactly one failure record and nothing
    // claims a restore succeeded.
    let failures = audit_records(&dst1, "BACKUP_RESTORED_FAILED", 4).await;
    audit_records(&dst1, "BACKUP_RESTORED", 0).await;
    for (line, code) in failures.iter().zip([
        "ResourceExhausted",
        "InvalidArgument",
        "FailedPrecondition",
        "FailedPrecondition",
    ]) {
        assert!(line.contains(r#""mode":"cluster""#), "{line}");
        assert!(line.contains(&format!(r#""code":"{code}""#)), "{line}");
    }

    dst_admin.restore(futures::stream::iter(chunks)).await?;
    // The successful restore is still recorded once, with no new failure.
    audit_records(&dst1, "BACKUP_RESTORED", 1).await;
    audit_records(&dst1, "BACKUP_RESTORED_FAILED", 4).await;

    // Both nodes serve the backup, the stale data is gone.
    for (storage, label) in [(&dst1.storage, "leader"), (&dst2.storage, "follower")] {
        let ok = poll_until(Duration::from_millis(100), 100, || {
            // Replication of the restore entry to the follower is async.
            storage.raft.metrics().borrow_watched().last_applied
                >= dst1.storage.raft.metrics().borrow_watched().last_applied
        })
        .await;
        assert!(ok, "{label} did not apply the restore entry");
        assert_serves_all_records(storage, NUM_RECORDS, label).await?;
        assert!(
            get_by_key_retrying(storage, "stale".as_bytes(), None)
                .await?
                .is_none(),
            "{label}: data written after the backup must be gone"
        );
    }

    // Membership is the destination's own, not the backup's.
    for storage in [&dst1.storage, &dst2.storage] {
        let mut voters: Vec<u64> = storage
            .raft
            .metrics()
            .borrow_watched()
            .membership_config
            .membership()
            .voter_ids()
            .collect();
        voters.sort_unstable();
        assert_eq!(vec![1, 2], voters, "membership must be unchanged");
    }

    // The cluster keeps replicating on top of the restored state.
    dst1.storage
        .set_value("after".to_string(), make_env("restore")?, None, None)
        .await?;
    let replicated = get_by_key_retrying(&dst2.storage, "after".as_bytes(), None)
        .await?
        .expect("post-restore write must replicate");
    assert_eq!("restore", replicated.try_deserialize::<String>()?.data);
    Ok(())
}

/// Disaster recovery of a two-node cluster: the same backup is installed on
/// two fresh nodes and only one is told to elect. After the election exactly
/// one leader exists, both nodes agree on it, and only it takes writes.
const DR_UNIQUE_PORT_BASE: u16 = 1050;

#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_disaster_recovery_elects_exactly_one_leader() {
    TypeConfig::run(async {
        test_disaster_recovery_elects_exactly_one_leader_inner()
            .await
            .unwrap();
    });
}

async fn test_disaster_recovery_elects_exactly_one_leader_inner() -> Result<()> {
    use openraft::ServerState;

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls_configuration = make_certificates()?;

    // --- Source: a two-node cluster, then a backup of it. Its servers are
    // stopped afterwards: the restored membership carries the source's node
    // addresses, so the destination nodes must take over the same ones.
    let base = DR_UNIQUE_PORT_BASE;
    let src1 = Arc::new(InstanceHolder::new_with_port(1, base, tls_configuration.clone()).await?);
    let stop1 = spawn_stoppable_raft_app(&src1).await;
    let mut src_admin = new_admin_client(
        src1.config.node_cluster_addr.clone(),
        &get_client_tls_config(&src1.config)?,
    )
    .await?;
    src_admin
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, base)],
        })
        .await?;
    wait_for_leader(&mut src_admin, 1).await;
    let src2 = Arc::new(InstanceHolder::new_with_port(2, base, tls_configuration.clone()).await?);
    let stop2 = spawn_stoppable_raft_app(&src2).await;
    src2.storage
        .join_cluster(
            &get_addr_with_port(1, base).to_string(),
            &get_addr_with_port(2, base).to_string(),
        )
        .await?;
    src_admin
        .change_membership(pb::raft::ChangeMembershipRequest {
            members: vec![1, 2],
            retain: false,
        })
        .await?;
    const NUM_RECORDS: usize = 50;
    write_index_and_sensitive_records(&src1.storage).await?;
    write_records_concurrently(&src1.storage, NUM_RECORDS).await?;
    let mut stream = src_admin
        .backup(pb::raft::BackupRequest {})
        .await?
        .into_inner();
    let mut chunks = Vec::new();
    while let Some(chunk) = stream.message().await? {
        chunks.push(pb::raft::RestoreChunk {
            data: chunk.data,
            elect: false,
            total_len: 0,
        });
    }
    assert!(!chunks.is_empty(), "backup stream was empty");
    drop(stream);
    drop(src_admin);
    src1.storage.raft.shutdown().await.ok();
    src2.storage.raft.shutdown().await.ok();
    stop1.send(()).ok();
    stop2.send(()).ok();
    TypeConfig::sleep(Duration::from_secs(1)).await;

    // --- Two fresh, uninitialized nodes with the source's node ids.
    let mut dst = Vec::new();
    let mut admins = Vec::new();
    for node_id in [1u64, 2] {
        let instance = Arc::new(
            InstanceHolder::new_with_port(node_id, DR_UNIQUE_PORT_BASE, tls_configuration.clone())
                .await?,
        );
        spawn_raft_app(&instance).await;
        let tls_client_config = get_client_tls_config(&instance.config)?;
        admins.push(
            new_admin_client(
                instance.config.node_cluster_addr.clone(),
                &tls_client_config,
            )
            .await?,
        );
        dst.push(instance);
    }
    let state_of = |i: usize| dst[i].storage.raft.metrics().borrow_watched().state;

    // Restore node 2 first, without `elect`. Installing the snapshot commits
    // a vote for the node itself at the backup's term (OpenRaft's documented
    // recipe), so until the election the node reports itself as leader of a
    // term it cannot commit in: node 1 is not restored yet and the
    // membership needs both. That window must not commit anything.
    admins[1]
        .restore(futures::stream::iter(chunks.clone()))
        .await?;
    let applied_before = dst[1].storage.raft.metrics().borrow_watched().last_applied;
    TypeConfig::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        dst[1].storage.raft.metrics().borrow_watched().last_applied,
        applied_before,
        "nothing may commit before the election"
    );

    // Restore node 1 with `elect`.
    let mut with_elect = chunks;
    with_elect[0].elect = true;
    admins[0].restore(futures::stream::iter(with_elect)).await?;
    let elected = poll_until(Duration::from_millis(250), 120, || {
        dst[0].storage.current_leader() == Some(1)
    })
    .await;
    assert!(elected, "node 1 must win the election");
    let converged = poll_until(Duration::from_millis(100), 100, || {
        dst[1].storage.current_leader() == Some(1)
    })
    .await;
    assert!(converged, "node 2 must follow node 1");

    // Exactly one leader, and the same term on both nodes.
    assert_eq!(state_of(0), ServerState::Leader);
    assert_ne!(state_of(1), ServerState::Leader);
    let term = |i: usize| dst[i].storage.raft.metrics().borrow_watched().current_term;
    assert_eq!(term(0), term(1), "both nodes must agree on the term");

    // Only the leader takes writes, and they replicate.
    dst[0]
        .storage
        .set_value("after".to_string(), make_env("dr")?, None, None)
        .await?;
    let replicated = get_by_key_retrying(&dst[1].storage, "after".as_bytes(), None)
        .await?
        .expect("write must replicate to the follower");
    assert_eq!("dr", replicated.try_deserialize::<String>()?.data);
    // A write sent to the follower is forwarded to the leader.
    dst[1]
        .storage
        .set_value("forwarded".to_string(), make_env("dr")?, None, None)
        .await?;
    assert!(
        get_by_key_retrying(&dst[0].storage, "forwarded".as_bytes(), None)
            .await?
            .is_some()
    );
    assert_serves_all_records(&dst[1].storage, NUM_RECORDS, "follower").await?;
    Ok(())
}

/// A live restore displaces the node's DEKs; its Raft log is still encrypted
/// under them, and the backup may reuse the same version number for a
/// different key. After a restart the node must reload the displaced epochs
/// to read its own log, and keep serving the restored data.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_restart_after_live_restore_keeps_displaced_deks() {
    TypeConfig::run(async {
        test_restart_after_live_restore_keeps_displaced_deks_inner()
            .await
            .unwrap();
    });
}

#[allow(unsafe_code)]
async fn test_restart_after_live_restore_keeps_displaced_deks_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls_configuration = make_certificates()?;

    let set_kek_env = || {
        // SAFETY: no concurrent env readers; test is `#[serial_test::serial]`.
        // `EnvKek::from_env()` removes the variable after reading it, so it
        // is re-set before every `init_storage`.
        unsafe {
            std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
            std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
        }
    };
    let start = |node_id: u64, config: &DistributedStorageConfiguration| {
        let config = config.clone();
        async move {
            let storage = init_storage(&config_manager(config)).await?;
            for _ in 0..50 {
                if storage.current_leader() == Some(node_id) {
                    break;
                }
                TypeConfig::sleep(Duration::from_millis(50)).await;
            }
            assert_eq!(storage.current_leader(), Some(node_id));
            Result::<_>::Ok(storage)
        }
    };
    let node = |node_id: u64| {
        [(
            node_id,
            openstack_keystone_storage_api::Node {
                node_id,
                rpc_addr: get_addr(node_id).to_string(),
            },
        )]
        .into_iter()
        .collect()
    };

    // --- Source: a backup under its own (version 1) DEK.
    let src_dir = tempfile::TempDir::new()?;
    let src_config = get_ds_config(107, src_dir.path().to_path_buf(), tls_configuration.clone());
    set_kek_env();
    let src = init_storage(&config_manager(src_config)).await?;
    src.initialize(node(107)).await?;
    for _ in 0..50 {
        if src.current_leader() == Some(107) {
            break;
        }
        TypeConfig::sleep(Duration::from_millis(50)).await;
    }
    src.set_value("k1".to_string(), make_env("from-backup")?, None, None)
        .await?;
    src.raft.trigger().snapshot().await?;
    poll_until(Duration::from_millis(50), 100, || {
        src.raft.metrics().borrow_watched().snapshot.is_some()
    })
    .await;
    let backup = std::fs::read(
        src.state_machine_store()
            .latest_snapshot_path()?
            .ok_or_else(|| eyre::eyre!("source produced no snapshot"))?,
    )?;
    src.raft.shutdown().await.ok();
    drop(src);

    // --- Destination: a different version 1 DEK and some local history.
    let dst_dir = tempfile::TempDir::new()?;
    let dst_config = get_ds_config(108, dst_dir.path().to_path_buf(), tls_configuration.clone());
    set_kek_env();
    let dst = init_storage(&config_manager(dst_config.clone())).await?;
    dst.initialize(node(108)).await?;
    for _ in 0..50 {
        if dst.current_leader() == Some(108) {
            break;
        }
        TypeConfig::sleep(Duration::from_millis(50)).await;
    }
    dst.set_value("stale".to_string(), make_env("stale")?, None, None)
        .await?;
    let (dst_version, dst_wrapped) = dst.state_machine_store().current_dek_wrapped()?;

    // Restore through the Raft log, as the admin service does.
    let restore_id = "restart-test".to_string();
    let mut chunks = 0u32;
    for (seq, data) in backup.chunks(4096).enumerate() {
        dst.raft
            .client_write(pb::api::CommandRequest::try_from(
                StoreCommand::RestoreChunk {
                    restore_id: restore_id.clone(),
                    seq: seq as u32,
                    data: data.to_vec(),
                },
            )?)
            .await?;
        chunks = seq as u32 + 1;
    }
    let response = dst
        .raft
        .client_write(pb::api::CommandRequest::try_from(
            StoreCommand::RestoreApply {
                restore_id,
                chunks,
                total_len: backup.len() as u64,
            },
        )?)
        .await?;
    assert!(
        response.data.violations.is_empty(),
        "restore rejected: {:?}",
        response.data.violations
    );

    // The restore replaced the DEK but kept the one it displaced.
    let (restored_version, restored_wrapped) = dst.state_machine_store().current_dek_wrapped()?;
    assert_eq!(restored_version, dst_version, "versions are meant to clash");
    assert_ne!(
        restored_wrapped, dst_wrapped,
        "the restore must swap the key"
    );
    assert_eq!(
        dst.state_machine_store()
            .shadow_deks()
            .lock()
            .unwrap()
            .len(),
        1
    );

    // --- Restart: the node reads its pre-restore log through the displaced
    //     epoch and serves the restored data.
    dst.raft.shutdown().await.ok();
    drop(dst);
    set_kek_env();
    let dst = start(108, &dst_config).await?;

    assert_eq!(
        dst.state_machine_store()
            .shadow_deks()
            .lock()
            .unwrap()
            .len(),
        1,
        "the displaced DEK must be reloaded from disk"
    );
    let restored = dst
        .get_by_key("k1".as_bytes(), None)
        .await?
        .expect("restored record must survive the restart");
    assert_eq!("from-backup", restored.try_deserialize::<String>()?.data);
    assert!(dst.get_by_key("stale".as_bytes(), None).await?.is_none());

    // The restarted node still takes writes, and a second restart keeps
    // working (log entries written after the restore use the restored DEK).
    dst.set_value("after".to_string(), make_env("restart")?, None, None)
        .await?;
    dst.raft.shutdown().await.ok();
    drop(dst);
    set_kek_env();
    let dst = start(108, &dst_config).await?;
    let after = dst
        .get_by_key("after".as_bytes(), None)
        .await?
        .expect("post-restore write must survive a second restart");
    assert_eq!("restart", after.try_deserialize::<String>()?.data);

    dst.raft.shutdown().await.ok();
    drop(dst);
    Ok(())
}
