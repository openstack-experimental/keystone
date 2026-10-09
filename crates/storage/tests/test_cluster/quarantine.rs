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
//! Partition quarantine: Raft commit, forwarding, role checks, restart.

use super::harness::*;
use super::*;

/// A `Quarantine` mutation committed via Raft blocks reads on the affected
/// partition, and `ClearQuarantine` restores them — exercising the real
/// apply() path end-to-end (ADR 0016-v2 §10 invariant 5).
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_quarantine_committed_via_raft() {
    TypeConfig::run(test_quarantine_committed_via_raft_inner()).unwrap();
}

#[allow(unsafe_code)]
async fn test_quarantine_committed_via_raft_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let storage_dir = tempfile::TempDir::new().unwrap();
    let tls_configuration = make_certificates()?;
    let ds_config = get_ds_config(103, storage_dir.path().to_path_buf(), tls_configuration);

    let config = ds_config;

    // SAFETY: no concurrent env readers; test is `#[serial_test::serial]`.
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
        std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
    }

    let storage = init_storage(&config_manager(config)).await?;

    // Bootstrap as a single-node cluster (no gRPC server needed — the Raft
    // handle is local).
    storage
        .initialize(
            [(
                103u64,
                openstack_keystone_storage_api::Node {
                    node_id: 103,
                    rpc_addr: "127.0.0.1:0".to_string(),
                },
            )]
            .into_iter()
            .collect(),
        )
        .await?;
    for _ in 0..50 {
        if storage.current_leader() == Some(103) {
            break;
        }
        TypeConfig::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(storage.current_leader(), Some(103));

    // Write a key so there is something to be blocked from reading.
    let key = "quarantine-test-key".to_string();
    storage
        .set_value(key.clone(), make_env(&"hello")?, None, None)
        .await?;
    assert!(storage.get_by_key(key.as_bytes(), None).await?.is_some());

    // Issue a raw Quarantine command for this node's own partition, exactly
    // as FjallStateMachine::decrypt_state does on GCM failure.
    let cmd = StoreCommand::Transaction(vec![MutationInner::Quarantine {
        node_id: 103,
        partition: "data".to_string(),
    }]);
    let payload = pb::api::CommandRequest::try_from(cmd)?;
    storage.raft.client_write(payload).await?;

    // Reads against the quarantined partition must now fail.
    let err = storage
        .get_by_key(key.as_bytes(), None)
        .await
        .expect_err("quarantined partition must refuse reads");
    assert!(
        format!("{err:?}").to_lowercase().contains("quarantin"),
        "unexpected error: {err:?}"
    );

    // ClearQuarantine restores reads.
    let clear_cmd = StoreCommand::Transaction(vec![MutationInner::ClearQuarantine {
        partition: "data".to_string(),
    }]);
    let clear_payload = pb::api::CommandRequest::try_from(clear_cmd)?;
    storage.raft.client_write(clear_payload).await?;

    assert!(
        storage.get_by_key(key.as_bytes(), None).await?.is_some(),
        "read should succeed again after ClearQuarantine"
    );

    Ok(())
}

const REPORT_QUARANTINE_PORT_BASE: u16 = 1100;

/// `ReportQuarantine` (issue #1303): a follower answers with the leader
/// hint headers, the leader validates membership and commits the
/// quarantine, which then blocks reads on the reporting node.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_report_quarantine_follower_hint_and_leader_commit() {
    TypeConfig::run(test_report_quarantine_follower_hint_and_leader_commit_inner()).unwrap();
}

async fn test_report_quarantine_follower_hint_and_leader_commit_inner() -> Result<()> {
    use openstack_keystone_distributed_storage::app::{LEADER_ENDPOINT_HEADER, LEADER_ID_HEADER};
    use openstack_keystone_distributed_storage::protobuf::api::storage_service_client::StorageServiceClient;

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls_configuration = make_certificates()?;

    let (instance1, mut admin_client1) =
        start_single_node_cluster(REPORT_QUARANTINE_PORT_BASE, &tls_configuration).await?;
    let instance2 = join_node2_as_voter(
        REPORT_QUARANTINE_PORT_BASE,
        &tls_configuration,
        &mut admin_client1,
    )
    .await?;

    let key = "report-quarantine-key".to_string();
    instance1
        .storage
        .set_value(key.clone(), make_env(&"hello")?, None, None)
        .await?;
    let leader_index = instance1
        .storage
        .last_log_index()
        .ok_or_else(|| eyre::eyre!("leader must have a log"))?;
    assert!(
        poll_until(Duration::from_millis(100), 100, || {
            instance2.storage.last_log_index() >= Some(leader_index)
        })
        .await,
        "node 2 never caught up"
    );

    let tls_client_config = get_client_tls_config(&instance1.config)?;
    let connect = |node_id: u64| {
        let tls = tls_client_config.clone();
        async move {
            let uri: Uri = format!(
                "https://{}",
                get_addr_with_port(node_id, REPORT_QUARANTINE_PORT_BASE)
            )
            .parse()?;
            let channel = Channel::builder(uri).tls_config(tls)?.connect().await?;
            Ok::<_, eyre::Report>(StorageServiceClient::new(channel))
        }
    };

    // Follower: Unavailable + leader hint pointing at node 1.
    let mut follower = connect(2).await?;
    let status = follower
        .report_quarantine(pb::api::ReportQuarantineRequest {
            node_id: 2,
            partition: "data".into(),
        })
        .await
        .expect_err("follower must not commit a quarantine report");
    assert_eq!(status.code(), tonic::Code::Unavailable, "{status:?}");
    assert_eq!(
        status
            .metadata()
            .get(LEADER_ID_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );
    let hinted_addr = status
        .metadata()
        .get(LEADER_ENDPOINT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| eyre::eyre!("missing leader endpoint header"))?;
    assert_eq!(
        hinted_addr,
        get_addr_with_port(1, REPORT_QUARANTINE_PORT_BASE).to_string()
    );

    // Leader: unknown node rejected, member report committed.
    let mut leader = connect(1).await?;
    let status = leader
        .report_quarantine(pb::api::ReportQuarantineRequest {
            node_id: 9,
            partition: "data".into(),
        })
        .await
        .expect_err("non-member report must be rejected");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);

    leader
        .report_quarantine(pb::api::ReportQuarantineRequest {
            node_id: 2,
            partition: "data".into(),
        })
        .await?;

    // The committed quarantine is enforced on the reporting node (2) only.
    assert!(
        poll_until(Duration::from_millis(100), 50, || {
            instance2
                .storage
                .state_machine_store()
                .is_quarantined("data")
        })
        .await,
        "node 2 must quarantine its partition after the committed report"
    );
    assert!(
        !instance1
            .storage
            .state_machine_store()
            .is_quarantined("data"),
        "leader is not the reporting node and must not quarantine"
    );

    Ok(())
}

const ROGUE_IDENTITIES_PORT_BASE: u16 = 1150;

const QUARANTINE_FORWARD_PORT_BASE: u16 = 1200;

/// Connect to node `node_id` presenting `leaf` as the client certificate.
async fn connect_as(
    pki: &TestPki,
    leaf: &TestLeaf,
    node_id: u64,
    port_base: u16,
) -> Result<Channel> {
    let uri: Uri = format!("https://{}", get_addr_with_port(node_id, port_base)).parse()?;
    Ok(Channel::builder(uri)
        .tls_config(pki.client_tls(leaf))?
        .connect()
        .await?)
}

/// `command` payload carrying an admin-only `ClearQuarantine` mutation.
fn clear_quarantine_payload() -> pb::api::CommandRequest {
    pb::api::CommandRequest::try_from(StoreCommand::Transaction(vec![
        MutationInner::ClearQuarantine {
            partition: "data".into(),
        },
    ]))
    .unwrap()
}

/// `command` payload carrying an admin-only `Quarantine` mutation.
fn quarantine_payload() -> pb::api::CommandRequest {
    pb::api::CommandRequest::try_from(StoreCommand::Transaction(vec![MutationInner::Quarantine {
        node_id: 1,
        partition: "data".into(),
    }]))
    .unwrap()
}

/// `command` payload carrying an empty (no-op) data transaction.
fn empty_data_payload() -> pb::api::CommandRequest {
    pb::api::CommandRequest::try_from(StoreCommand::Transaction(vec![])).unwrap()
}

fn forwarded_get_req() -> pb::api::ForwardedGetRequest {
    pb::api::ForwardedGetRequest {
        key: b"rogue-identities-key".to_vec(),
        keyspace: None,
    }
}

#[track_caller]
fn assert_denied<T: std::fmt::Debug>(res: Result<T, tonic::Status>, what: &str) {
    match res {
        Err(s) if s.code() == tonic::Code::PermissionDenied => {}
        other => panic!("{what}: expected PermissionDenied, got {other:?}"),
    }
}

#[track_caller]
fn assert_not_denied<T: std::fmt::Debug>(res: &Result<T, tonic::Status>, what: &str) {
    assert!(
        !matches!(res, Err(s) if s.code() == tonic::Code::PermissionDenied),
        "{what}: role must be authorised: {res:?}"
    );
}

/// Role-mode TLS (issue #1303): peer roles derive from the client
/// certificate's URI SAN under `tls_role_san_prefix`. Operator, rogue
/// workload, unknown-role and SAN-less certificates are denied on the data
/// plane; the node role is denied on operator-only RPCs and may not smuggle
/// admin mutations through `command`; `ReportQuarantine` is rate limited
/// per reporter identity.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_rogue_identities_rejected_tls_roles() {
    TypeConfig::run(test_rogue_identities_rejected_tls_roles_inner()).unwrap();
}

async fn test_rogue_identities_rejected_tls_roles_inner() -> Result<()> {
    use openstack_keystone_distributed_storage::protobuf::api::storage_service_client::StorageServiceClient;
    use openstack_keystone_distributed_storage::protobuf::raft::raft_service_client::RaftServiceClient;

    const PORT: u16 = ROGUE_IDENTITIES_PORT_BASE;

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let pki = TestPki::new()?;
    let node_cert = pki.leaf(Some(&format!("{ROLE_SAN_PREFIX}node")))?;
    let op_cert = pki.leaf(Some(&format!("{ROLE_SAN_PREFIX}storage-operator")))?;
    let rogue_cert = pki.leaf(Some("spiffe://keystone/ns/default/sa/x"))?;
    let unknown_role_cert = pki.leaf(Some(&format!("{ROLE_SAN_PREFIX}backup")))?;
    // CA-signed but without any URI SAN (the pre-#1303 cert shape).
    let no_uri_cert = pki.leaf(None)?;

    let instance =
        Arc::new(InstanceHolder::new_role_mode(1, PORT, pki.tls_configuration(&node_cert)?).await?);
    spawn_raft_app(&instance).await;

    let node_ch = connect_as(&pki, &node_cert, 1, PORT).await?;
    let op_ch = connect_as(&pki, &op_cert, 1, PORT).await?;
    let rogue_ch = connect_as(&pki, &rogue_cert, 1, PORT).await?;
    let unknown_ch = connect_as(&pki, &unknown_role_cert, 1, PORT).await?;
    let no_uri_ch = connect_as(&pki, &no_uri_cert, 1, PORT).await?;
    let storage_client = |ch: &Channel| StorageServiceClient::new(ch.clone());
    let admin_client = |ch: &Channel| ClusterAdminServiceClient::new(ch.clone());
    let raft_client = |ch: &Channel| RaftServiceClient::new(ch.clone());
    let init_req = || pb::raft::InitRequest {
        nodes: vec![new_node_with_port(1, PORT)],
    };

    // --- Init is operator-only.
    assert_denied(admin_client(&node_ch).init(init_req()).await, "node Init");
    assert_denied(admin_client(&rogue_ch).init(init_req()).await, "rogue Init");
    assert_denied(
        admin_client(&no_uri_ch).init(init_req()).await,
        "no-URI Init",
    );
    admin_client(&op_ch).init(init_req()).await?;
    wait_for_leader(&mut admin_client(&op_ch), 1).await;

    // --- Data plane (brief assertions).
    // operator cert: forbidden on data plane
    let err = storage_client(&op_ch)
        .forwarded_get(forwarded_get_req())
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    let err = storage_client(&op_ch)
        .command(clear_quarantine_payload())
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    // unrelated workload cert (SAN spiffe://keystone/ns/default/sa/x):
    // forbidden
    let err = storage_client(&rogue_ch)
        .forwarded_get(forwarded_get_req())
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    // node cert: allowed on forwarded_get; command with ClearQuarantine
    // still denied (a missing key is NotFound/Ok depending on the handler;
    // the point is that the node role is NOT denied)
    let res = storage_client(&node_ch)
        .forwarded_get(forwarded_get_req())
        .await;
    assert!(
        !matches!(&res, Err(s) if s.code() == tonic::Code::PermissionDenied),
        "node role must be authorised on forwarded_get: {res:?}"
    );
    let err = storage_client(&node_ch)
        .command(clear_quarantine_payload())
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // --- Data plane, extended matrix.
    for (who, ch) in [
        ("operator", &op_ch),
        ("rogue", &rogue_ch),
        ("unknown-role", &unknown_ch),
        ("no-URI", &no_uri_ch),
    ] {
        let mut sc = storage_client(ch);
        assert_denied(
            sc.forwarded_get(forwarded_get_req()).await,
            &format!("{who} ForwardedGet"),
        );
        // An empty transaction passes the data-command filter, so a denial
        // here is the role gate itself.
        assert_denied(
            sc.command(empty_data_payload()).await,
            &format!("{who} Command"),
        );
        assert_denied(
            sc.forwarded_prefix(pb::api::ForwardedPrefixRequest {
                prefix: b"x".to_vec(),
                keyspace: None,
            })
            .await,
            &format!("{who} ForwardedPrefix"),
        );
        assert_denied(
            sc.forwarded_prefix_index(pb::api::ForwardedPrefixIndexRequest {
                prefix: b"x".to_vec(),
            })
            .await,
            &format!("{who} ForwardedPrefixIndex"),
        );
        assert_denied(
            sc.report_quarantine(pb::api::ReportQuarantineRequest {
                node_id: 1,
                partition: "data".into(),
            })
            .await,
            &format!("{who} ReportQuarantine"),
        );
        assert_denied(
            raft_client(ch).vote(pb::raft::VoteRequest::default()).await,
            &format!("{who} Raft Vote"),
        );
        assert_denied(
            admin_client(ch).fetch_dek(()).await,
            &format!("{who} FetchDek"),
        );
    }
    // Non-operator, non-node identities get nothing on the admin plane.
    for (who, ch) in [
        ("rogue", &rogue_ch),
        ("unknown-role", &unknown_ch),
        ("no-URI", &no_uri_ch),
    ] {
        assert_denied(
            admin_client(ch).metrics(()).await,
            &format!("{who} Metrics"),
        );
    }

    // Node role: the data-command filter rejects every admin mutation.
    assert_denied(
        storage_client(&node_ch).command(quarantine_payload()).await,
        "node Command(Quarantine)",
    );
    assert_not_denied(
        &storage_client(&node_ch).command(empty_data_payload()).await,
        "node Command(empty transaction)",
    );
    assert_not_denied(&admin_client(&node_ch).fetch_dek(()).await, "node FetchDek");

    // --- Admin plane role matrix.
    // Metrics: node or operator.
    assert_not_denied(&admin_client(&node_ch).metrics(()).await, "node Metrics");
    assert_not_denied(&admin_client(&op_ch).metrics(()).await, "operator Metrics");
    // ChangeMembership and ClearQuarantine: operator only.
    assert_denied(
        admin_client(&node_ch)
            .change_membership(pb::raft::ChangeMembershipRequest {
                members: vec![1],
                retain: false,
            })
            .await,
        "node ChangeMembership",
    );
    assert_denied(
        admin_client(&node_ch)
            .clear_quarantine(pb::raft::ClearQuarantineRequest {
                partition: "data".into(),
            })
            .await,
        "node ClearQuarantine",
    );
    assert_denied(
        admin_client(&node_ch)
            .rotate_dek(pb::raft::RotateDekRequest { emergency: false })
            .await,
        "node RotateDek",
    );

    // --- ReportQuarantine rate limit: 30 per reporter identity per hour.
    // An empty partition fails validation *after* the limiter, so the
    // first 30 calls consume the bucket without committing anything.
    // Earlier denied calls from other identities never reached the limiter.
    let mut node_sc = storage_client(&node_ch);
    let bad_report = || pb::api::ReportQuarantineRequest {
        node_id: 1,
        partition: String::new(),
    };
    for i in 0..30 {
        let err = node_sc
            .report_quarantine(bad_report())
            .await
            .expect_err("empty partition must be rejected");
        assert_eq!(
            err.code(),
            tonic::Code::InvalidArgument,
            "report {}: {err:?}",
            i + 1
        );
    }
    let err = node_sc
        .report_quarantine(bad_report())
        .await
        .expect_err("31st report within the hour must be rate limited");
    assert_eq!(err.code(), tonic::Code::ResourceExhausted, "{err:?}");

    Ok(())
}

/// A follower's locally-triggered quarantine reaches the leader through
/// `Storage::propose_quarantine` -> `ReportQuarantine` (not the data-plane
/// `command` RPC, which rejects `Quarantine`), with role-mode TLS
/// enforcing the node role on the forwarded call (issue #1303).
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_follower_quarantine_forwarded_to_leader() {
    TypeConfig::run(test_follower_quarantine_forwarded_to_leader_inner()).unwrap();
}

async fn test_follower_quarantine_forwarded_to_leader_inner() -> Result<()> {
    const PORT: u16 = QUARANTINE_FORWARD_PORT_BASE;

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let pki = TestPki::new()?;
    let node_cert = pki.leaf(Some(&format!("{ROLE_SAN_PREFIX}node")))?;
    let op_cert = pki.leaf(Some(&format!("{ROLE_SAN_PREFIX}storage-operator")))?;
    let node_tls = pki.tls_configuration(&node_cert)?;

    let instance1 = Arc::new(InstanceHolder::new_role_mode(1, PORT, node_tls.clone()).await?);
    spawn_raft_app(&instance1).await;
    let mut op_admin = ClusterAdminServiceClient::new(connect_as(&pki, &op_cert, 1, PORT).await?);
    op_admin
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, PORT)],
        })
        .await?;
    wait_for_leader(&mut op_admin, 1).await;

    // Node 2 joins with its node certificate (AddLearner/FetchDek are
    // node-role RPCs); promotion is operator-only.
    let instance2 = Arc::new(InstanceHolder::new_role_mode(2, PORT, node_tls).await?);
    spawn_raft_app(&instance2).await;
    instance2
        .storage
        .join_cluster(
            &get_addr_with_port(1, PORT).to_string(),
            &get_addr_with_port(2, PORT).to_string(),
        )
        .await?;
    op_admin
        .change_membership(pb::raft::ChangeMembershipRequest {
            members: vec![1, 2],
            retain: false,
        })
        .await?;

    let key = "follower-quarantine-key".to_string();
    instance1
        .storage
        .set_value(key.clone(), make_env(&"hello")?, None, None)
        .await?;
    let leader_index = instance1
        .storage
        .last_log_index()
        .ok_or_else(|| eyre::eyre!("leader must have a log"))?;
    assert!(
        poll_until(Duration::from_millis(100), 100, || {
            instance2.storage.last_log_index() >= Some(leader_index)
                && instance2.storage.current_leader() == Some(1)
                && matches!(
                    instance2
                        .storage
                        .state_machine_store()
                        .data()
                        .get(key.as_bytes()),
                    Ok(Some(_))
                )
        })
        .await,
        "node 2 never caught up with leader 1"
    );

    // Tamper with node 2's replicated ciphertext and read it three times:
    // the GCM failure threshold quarantines the partition locally and the
    // background task calls `Storage::propose_quarantine` on the follower.
    let metadata = instance1
        .storage
        .state_machine_store()
        .meta()
        .get(meta_key("data", key.as_bytes()))?
        .map(|raw| Metadata::unpack(raw.as_ref()))
        .transpose()?
        .ok_or_else(|| eyre::eyre!("leader must have Metadata for {key}"))?;
    let mut tampered = instance2
        .storage
        .state_machine_store()
        .data()
        .get(key.as_bytes())?
        .ok_or_else(|| eyre::eyre!("node 2 must have ciphertext for {key}"))?
        .to_vec();
    // Flip a bit inside the GCM tag (layout: nonce | ct | tag | version).
    let tag_byte = tampered.len() - 5;
    tampered[tag_byte] ^= 0x01;
    let sm2 = instance2.storage.state_machine_store();
    for _ in 0..3 {
        sm2.decrypt_state(
            &tampered,
            metadata.tier as u8,
            b"data",
            key.as_bytes(),
            metadata.dek_version,
        )
        .expect_err("tampered ciphertext must not decrypt");
    }
    assert!(sm2.is_quarantined("data"), "node 2 must quarantine locally");

    // The leader commits the forwarded report: its replicated marker for
    // reporting node 2 appears, while its own reads stay unblocked.
    let marker = b"_meta:quarantine:data:2";
    assert!(
        poll_until(Duration::from_millis(100), 100, || {
            matches!(
                instance1.storage.state_machine_store().meta().get(marker),
                Ok(Some(_))
            )
        })
        .await,
        "leader never committed the follower's quarantine report"
    );
    assert!(
        !instance1
            .storage
            .state_machine_store()
            .is_quarantined("data"),
        "leader is not the reporting node and must not quarantine"
    );
    assert!(
        instance1
            .storage
            .get_by_key(key.as_bytes(), None)
            .await?
            .is_some(),
        "leader reads must keep working"
    );

    Ok(())
}

const QUARANTINE_RESTART_PORT_BASE: u16 = 1650;

/// A quarantine marker survives a restart: the partition stays blocked after
/// the node comes back, and `clear-quarantine` over the admin API unblocks it
/// (GitHub #1307).
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_quarantine_survives_restart_and_is_cleared() {
    TypeConfig::run(test_quarantine_survives_restart_and_is_cleared_inner()).unwrap();
}

async fn test_quarantine_survives_restart_and_is_cleared_inner() -> Result<()> {
    const PORT: u16 = QUARANTINE_RESTART_PORT_BASE;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls = make_certificates()?;

    let mut node = RestartableNode::new(1, PORT, &tls).await?;
    node.start().await;
    let mut admin = node.admin().await?;
    admin
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, PORT)],
        })
        .await?;
    wait_for_leader(&mut admin, 1).await;

    set_value_retrying(node.storage(), "guarded", "secret").await?;
    node.storage()
        .raft
        .client_write(quarantine_payload_for(1))
        .await?;
    let err = node
        .storage()
        .get_by_key("guarded".as_bytes(), None)
        .await
        .expect_err("quarantined partition must refuse reads");
    assert!(
        format!("{err:?}").to_lowercase().contains("quarantin"),
        "{err:?}"
    );

    // --- Restart: the persisted marker keeps blocking reads.
    drop(admin);
    node.kill().await;
    node.restart().await?;
    let mut admin = node.admin().await?;
    wait_for_leader(&mut admin, 1).await;
    let err = node
        .storage()
        .get_by_key("guarded".as_bytes(), None)
        .await
        .expect_err("the quarantine must survive the restart");
    assert!(
        format!("{err:?}").to_lowercase().contains("quarantin"),
        "{err:?}"
    );
    let status = admin.storage_status(()).await?.into_inner();
    assert_eq!(vec!["data".to_string()], status.quarantined_partitions);

    // --- Clearing after the restart unblocks the partition.
    admin
        .clear_quarantine(pb::raft::ClearQuarantineRequest {
            partition: "data".to_string(),
        })
        .await?;
    let got = get_by_key_retrying(node.storage(), "guarded".as_bytes(), None)
        .await?
        .expect("record must be readable after the quarantine is cleared");
    assert_eq!("secret", got.try_deserialize::<String>()?.data);
    assert!(
        admin
            .storage_status(())
            .await?
            .into_inner()
            .quarantined_partitions
            .is_empty()
    );

    node.kill().await;
    Ok(())
}

/// A Raft command quarantining the `data` partition on `node_id`, as the
/// state machine commits it after repeated GCM failures.
fn quarantine_payload_for(node_id: u64) -> pb::api::CommandRequest {
    let cmd = StoreCommand::Transaction(vec![MutationInner::Quarantine {
        node_id,
        partition: "data".to_string(),
    }]);
    pb::api::CommandRequest::try_from(cmd).expect("quarantine command encodes")
}
