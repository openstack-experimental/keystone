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
//! Readiness, metrics, admin RPC redirection, leadership transfer and failover.

use super::harness::*;
use super::*;

/// `/ready` checks and `/metrics` series against a live cluster (GitHub
/// #1306): a single-voter leader stays ready while idle (openraft never
/// refreshes its quorum-ack time), every member of a three-voter cluster is
/// ready once it has caught up, and the operational `keystone_raft_*`
/// series are rendered.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_readiness_and_metrics() {
    TypeConfig::run(test_readiness_and_metrics_inner()).unwrap();
}

const READINESS_PORT_BASE: u16 = 1300;

async fn wait_until_ready(storage: &Storage) -> Vec<String> {
    let mut issues = Vec::new();
    for _ in 0..100 {
        let readiness = storage.readiness().await.expect("readiness");
        if readiness.is_ready() {
            return Vec::new();
        }
        issues = readiness.issues;
        TypeConfig::sleep(Duration::from_millis(100)).await;
    }
    issues
}

async fn test_readiness_and_metrics_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let tls_configuration = make_certificates()?;

    let mut instances = Vec::new();
    for node_id in 1..=3 {
        let instance = Arc::new(
            InstanceHolder::new_with_port(node_id, READINESS_PORT_BASE, tls_configuration.clone())
                .await?,
        );
        let inst = instance.clone();
        thread::spawn(move || {
            let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
            let _ = rt.block_on(start_raft_app(&inst.config, &inst.storage));
        });
        instances.push(instance);
    }

    TypeConfig::sleep(Duration::from_millis(200)).await;

    // Uninitialized: not ready, reported as such rather than as an issue.
    let readiness = instances[0].storage.readiness().await?;
    assert!(!readiness.initialized);
    assert!(!readiness.is_ready());

    let tls_client_config = get_client_tls_config(&instances[0].config)?;
    let mut admin_client1 = new_admin_client(
        instances[0].config.node_cluster_addr.clone(),
        &tls_client_config,
    )
    .await?;
    admin_client1
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, READINESS_PORT_BASE)],
        })
        .await?;
    wait_for_leader(&mut admin_client1, 1).await;

    // A single-voter leader must stay ready past the quorum-ack window.
    assert_eq!(
        wait_until_ready(&instances[0].storage).await,
        Vec::<String>::new()
    );
    TypeConfig::sleep(Duration::from_secs(7)).await;
    let readiness = instances[0].storage.readiness().await?;
    assert!(
        readiness.is_ready(),
        "idle single-voter leader must stay ready: {:?}",
        readiness.issues
    );

    for node_id in [2, 3] {
        admin_client1
            .add_learner(pb::raft::AddLearnerRequest {
                node: Some(new_node_with_port(node_id, READINESS_PORT_BASE)),
            })
            .await?;
    }
    admin_client1
        .change_membership(pb::raft::ChangeMembershipRequest {
            members: vec![1, 2, 3],
            retain: false,
        })
        .await?;

    instances[0]
        .storage
        .set_value("readiness".to_string(), make_env("value")?, None, None)
        .await?;

    for instance in &instances {
        assert_eq!(
            wait_until_ready(&instance.storage).await,
            Vec::<String>::new(),
            "node {} must become ready",
            instance.node_id
        );
    }
    // The leader keeps receiving quorum acknowledgements while idle.
    TypeConfig::sleep(Duration::from_secs(7)).await;
    let readiness = instances[0].storage.readiness().await?;
    assert!(
        readiness.is_ready(),
        "idle multi-voter leader must stay ready: {:?}",
        readiness.issues
    );

    // The nodes of this test share one process, and so one metrics
    // pipeline: check that the series are exposed, not their per-node
    // values.
    let text = openstack_keystone_telemetry::metrics::render_prometheus();
    for name in [
        "keystone_raft_is_leader ",
        "keystone_raft_current_leader_id ",
        "keystone_raft_membership_voters ",
        "keystone_raft_quarantined_partitions_count ",
        "keystone_raft_dek_pending_rotation ",
        "keystone_raft_gcm_failures_total ",
        "keystone_raft_dek_version ",
        "keystone_raft_log_nonce_counter ",
        "keystone_raft_log_nonce_remaining ",
        "keystone_raft_disk_space_bytes ",
        "keystone_raft_write_rate_version_max ",
        "keystone_raft_audit_channel_depth ",
    ] {
        assert!(text.contains(name), "missing {name:?} in:\n{text}");
    }

    Ok(())
}

const ADMIN_LEADER_REDIRECT_PORT_BASE: u16 = 1450;

/// Leader-only admin RPCs sent to a follower answer with the leader hint
/// instead of an internal error, while `StorageStatus` is served by any node
/// (issue #1305).
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_admin_rpcs_redirect_to_leader() {
    TypeConfig::run(test_admin_rpcs_redirect_to_leader_inner()).unwrap();
}

async fn test_admin_rpcs_redirect_to_leader_inner() -> Result<()> {
    use openstack_keystone_distributed_storage::app::{LEADER_ENDPOINT_HEADER, LEADER_ID_HEADER};

    const PORT: u16 = ADMIN_LEADER_REDIRECT_PORT_BASE;

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls_configuration = make_certificates()?;

    let (instance1, mut leader) = start_single_node_cluster(PORT, &tls_configuration).await?;
    let instance2 = join_node2_as_voter(PORT, &tls_configuration, &mut leader).await?;
    let tls_client_config = get_client_tls_config(&instance1.config)?;
    let mut follower = new_admin_client(
        instance2.config.node_cluster_addr.clone(),
        &tls_client_config,
    )
    .await?;
    wait_for_leader(&mut follower, 1).await;

    // Every address is registered in the canonical `host:port` form.
    let membership = leader
        .metrics(())
        .await?
        .into_inner()
        .membership
        .unwrap_or_default();
    for node in membership.nodes.values() {
        assert!(!node.rpc_addr.contains("://"), "{node:?}");
    }

    let leader_addr = get_addr_with_port(1, PORT).to_string();
    let assert_redirect = |result: std::result::Result<(), tonic::Status>, what: &str| {
        let status = result.expect_err(&format!("{what} must not succeed on a follower"));
        assert_eq!(
            status.code(),
            tonic::Code::Unavailable,
            "{what}: {status:?}"
        );
        assert_eq!(
            status
                .metadata()
                .get(LEADER_ID_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("1"),
            "{what}"
        );
        assert_eq!(
            status
                .metadata()
                .get(LEADER_ENDPOINT_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some(leader_addr.as_str()),
            "{what}"
        );
    };

    assert_redirect(
        follower
            .clear_quarantine(pb::raft::ClearQuarantineRequest {
                partition: "data".into(),
            })
            .await
            .map(drop),
        "ClearQuarantine",
    );
    assert_redirect(
        follower
            .rotate_dek(pb::raft::RotateDekRequest { emergency: false })
            .await
            .map(drop),
        "RotateDek",
    );
    // Redirected before the pending-rotation lookup, which only the leader
    // can answer authoritatively.
    assert_redirect(
        follower
            .confirm_rotate_dek(pb::raft::ConfirmRotateDekRequest {
                rotation_id: "unknown".into(),
            })
            .await
            .map(drop),
        "ConfirmRotateDek",
    );
    assert_redirect(
        follower
            .change_membership(pb::raft::ChangeMembershipRequest {
                members: vec![1, 2],
                retain: false,
            })
            .await
            .map(drop),
        "ChangeMembership",
    );
    assert_redirect(
        follower
            .add_learner(pb::raft::AddLearnerRequest {
                node: Some(new_node_with_port(3, PORT)),
            })
            .await
            .map(drop),
        "AddLearner",
    );
    assert_redirect(
        follower.backup(pb::raft::BackupRequest {}).await.map(drop),
        "Backup",
    );

    let initial_dek = leader.storage_status(()).await?.into_inner().dek_version;

    // The redirect cost no rate-limit token: the leader still accepts the
    // rotation (2/hour per identity).
    leader
        .rotate_dek(pb::raft::RotateDekRequest { emergency: false })
        .await?;
    leader
        .rotate_dek(pb::raft::RotateDekRequest { emergency: false })
        .await?;

    // The nonce counter is per DEK epoch and the log encryptor only moves to
    // the new epoch on the next append, so write once to start its counter.
    instance1
        .storage
        .set_value("k".into(), make_env("v")?, None, None)
        .await?;

    let leader_status = leader.storage_status(()).await?.into_inner();
    assert_eq!(leader_status.node_id, 1);
    assert_eq!(leader_status.state, "Leader");
    assert_eq!(
        leader_status.dek_version,
        initial_dek + 2,
        "{leader_status:?}"
    );
    assert!(
        leader_status
            .retired_dek_versions
            .contains(&(initial_dek + 1)),
        "{leader_status:?}"
    );
    assert!(leader_status.nonce_counter > 0);
    assert_eq!(leader_status.nonce_threshold, 1 << 31);

    let follower_index = leader_status.last_log_index;
    assert!(
        poll_until(Duration::from_millis(100), 50, || {
            instance2.storage.last_log_index() >= follower_index
        })
        .await,
        "node 2 never caught up"
    );
    let follower_status = follower.storage_status(()).await?.into_inner();
    assert_eq!(follower_status.node_id, 2);
    assert_eq!(follower_status.state, "Follower");
    assert_eq!(follower_status.current_leader, Some(1));
    assert!(follower_status.quarantined_partitions.is_empty());

    Ok(())
}

const TRANSFER_LEADER_PORT_BASE: u16 = 1500;

/// Leadership transfer (issue #1444): the admin RPC hands leadership to a
/// chosen voter without waiting for an election timeout, writes keep working
/// through the new leader, and bad targets are refused. Demoting the old
/// leader afterwards (what `keystone-manage storage demote` does once it has
/// handed leadership over) leaves the cluster with a leader throughout.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_transfer_leader_before_demoting_the_leader() {
    TypeConfig::run(test_transfer_leader_before_demoting_the_leader_inner()).unwrap();
}

async fn test_transfer_leader_before_demoting_the_leader_inner() -> Result<()> {
    const PORT: u16 = TRANSFER_LEADER_PORT_BASE;

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls_configuration = make_certificates()?;

    let (instance1, mut admin1) = start_single_node_cluster(PORT, &tls_configuration).await?;
    let instance2 = join_node2_as_voter(PORT, &tls_configuration, &mut admin1).await?;
    let tls_client_config = get_client_tls_config(&instance1.config)?;
    let mut admin2 = new_admin_client(
        instance2.config.node_cluster_addr.clone(),
        &tls_client_config,
    )
    .await?;

    // Targets that cannot take over are refused and change nothing.
    let err = admin1
        .transfer_leader(pb::raft::TransferLeaderAdminRequest { node_id: 1 })
        .await
        .expect_err("the leader is already the leader");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");
    let err = admin1
        .transfer_leader(pb::raft::TransferLeaderAdminRequest { node_id: 99 })
        .await
        .expect_err("an unknown node cannot take over");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");
    // A follower answers with a leader redirect instead of transferring.
    let err = admin2
        .transfer_leader(pb::raft::TransferLeaderAdminRequest { node_id: 2 })
        .await
        .expect_err("only the leader transfers leadership");
    assert_eq!(err.code(), tonic::Code::Unavailable, "{err}");

    // The transfer is immediate: far below the 1.5 s minimum election
    // timeout a leaderless cluster would have to sit out.
    let started = std::time::Instant::now();
    admin1
        .transfer_leader(pb::raft::TransferLeaderAdminRequest { node_id: 2 })
        .await?;
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "transfer took {:?}, an election timeout would have been needed",
        started.elapsed()
    );
    wait_for_leader(&mut admin1, 2).await;
    wait_for_leader(&mut admin2, 2).await;

    // Writes go through the new leader and replicate to the old one.
    instance2
        .storage
        .set_value("after-transfer".to_string(), make_env("v")?, None, None)
        .await?;
    let replicated = get_by_key_retrying(&instance1.storage, "after-transfer".as_bytes(), None)
        .await?
        .expect("write through the new leader must replicate");
    assert_eq!("v", replicated.try_deserialize::<String>()?.data);

    // The old leader is now a follower and can be demoted through the
    // current leader without an election.
    admin2
        .change_membership(pb::raft::ChangeMembershipRequest {
            members: vec![2],
            retain: true,
        })
        .await?;
    wait_for_leader(&mut admin2, 2).await;
    instance2
        .storage
        .set_value("after-demote".to_string(), make_env("v")?, None, None)
        .await?;
    Ok(())
}

/// Waits until `node` reports a leader other than `not` and returns it.
async fn wait_for_new_leader(node: &RestartableNode, not: u64) -> u64 {
    for _ in 0..300 {
        if let Some(leader) = node.storage().current_leader()
            && leader != not
        {
            return leader;
        }
        TypeConfig::sleep(Duration::from_millis(100)).await;
    }
    panic!("no leader other than {not} elected within 30 seconds");
}

const FAILOVER_PORT_BASE: u16 = 1600;

/// The leader of a three-node cluster is killed while data exists: the
/// survivors elect a new leader, keep serving the old data and take new
/// writes, and the old leader restarts from its persisted log (crash
/// recovery), catches up and serves both the old and the new data.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_leader_failover_and_rejoin() {
    TypeConfig::run(test_leader_failover_and_rejoin_inner()).unwrap();
}

async fn test_leader_failover_and_rejoin_inner() -> Result<()> {
    const PORT: u16 = FAILOVER_PORT_BASE;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls = make_certificates()?;

    let mut nodes = Vec::new();
    for id in 1..=3 {
        let mut node = RestartableNode::new(id, PORT, &tls).await?;
        node.start().await;
        nodes.push(node);
    }
    let mut admin1 = nodes[0].admin().await?;
    admin1
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, PORT)],
        })
        .await?;
    wait_for_leader(&mut admin1, 1).await;
    for id in [2u64, 3] {
        nodes[id as usize - 1]
            .storage()
            .join_cluster(
                &get_addr_with_port(1, PORT).to_string(),
                &get_addr_with_port(id, PORT).to_string(),
            )
            .await?;
    }
    admin1
        .change_membership(pb::raft::ChangeMembershipRequest {
            members: vec![1, 2, 3],
            retain: false,
        })
        .await?;

    const NUM_RECORDS: usize = 100;
    write_index_and_sensitive_records(nodes[0].storage()).await?;
    write_records_concurrently(nodes[0].storage(), NUM_RECORDS).await?;
    let leader_index = nodes[0]
        .storage()
        .last_log_index()
        .ok_or_else(|| eyre::eyre!("leader must have a log"))?;
    for node in &nodes[1..] {
        assert!(
            poll_until(Duration::from_millis(100), 100, || {
                node.storage().last_log_index() >= Some(leader_index)
            })
            .await,
            "node {} did not replicate before the failover",
            node.node_id
        );
    }

    // --- Kill the leader.
    nodes[0].kill().await;
    let new_leader = wait_for_new_leader(&nodes[1], 1).await;
    assert!(new_leader == 2 || new_leader == 3, "leader {new_leader}");
    let survivor = if new_leader == 2 {
        &nodes[2]
    } else {
        &nodes[1]
    };

    // Old data stays readable from both survivors, new writes succeed.
    for node in &nodes[1..] {
        let got = get_by_key_retrying(node.storage(), "k0".as_bytes(), None)
            .await?
            .expect("pre-failover record must survive");
        assert_eq!("v0", got.try_deserialize::<String>()?.data);
    }
    set_value_retrying(
        nodes[new_leader as usize - 1].storage(),
        "after",
        "failover",
    )
    .await?;
    let got = get_by_key_retrying(survivor.storage(), "after".as_bytes(), None)
        .await?
        .expect("post-failover write must replicate");
    assert_eq!("failover", got.try_deserialize::<String>()?.data);

    // --- The old leader restarts from its persisted state and catches up.
    nodes[0].restart().await?;
    let new_index = nodes[new_leader as usize - 1]
        .storage()
        .last_log_index()
        .ok_or_else(|| eyre::eyre!("new leader must have a log"))?;
    assert!(
        poll_until(Duration::from_millis(100), 200, || {
            nodes[0].storage().last_log_index() >= Some(new_index)
        })
        .await,
        "restarted node did not catch up to {new_index} (at {:?})",
        nodes[0].storage().last_log_index()
    );
    assert_ne!(
        nodes[0].storage().current_leader(),
        Some(1),
        "the restarted node must follow the new leader"
    );
    assert_serves_all_records(nodes[0].storage(), NUM_RECORDS, "restarted old leader").await?;
    let got = get_by_key_retrying(nodes[0].storage(), "after".as_bytes(), None)
        .await?
        .expect("restarted node must serve the post-failover write");
    assert_eq!("failover", got.try_deserialize::<String>()?.data);

    for node in &mut nodes {
        node.kill().await;
    }
    Ok(())
}
