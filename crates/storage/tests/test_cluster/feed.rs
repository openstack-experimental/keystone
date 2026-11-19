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
//! Feed outbox (ADR 0045 section 3, M4).

use super::common::TestPki;
use super::harness::*;
use super::quarantine::connect_as;
use super::*;
use openstack_keystone_distributed_storage::FeedOp;

const FEED_PORT_BASE: u16 = 2600;

fn emit(kind: &str, domain: &str, key: &str, tier: DataTier) -> Mutation {
    Mutation::Emit {
        kind: kind.into(),
        domain_id: Some(domain.into()),
        key: key.as_bytes().to_vec(),
        op: FeedOp::Set,
        value: Some(key.as_bytes().to_vec()),
        tier,
    }
}

#[serial_test::serial]
#[test]
fn test_emit_writes_outbox_and_refuses_unknown_kind_and_secret_tier() {
    TypeConfig::run(async {
        test_emit_inner().await.unwrap();
    });
}

async fn test_emit_inner() -> Result<()> {
    let provider = openstack_keystone_tls_provider::provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls = make_certificates()?;
    let node = Arc::new(
        InstanceHolder::new_with_ds_config(1, |path| DistributedStorageConfiguration {
            feed_kinds: vec!["registry".into()],
            ..get_ds_config_with_port(1, FEED_PORT_BASE, path, tls.clone())
        })
        .await?,
    );
    spawn_raft_app(&node).await;
    let tls_client = get_client_tls_config(&node.config)?;
    let mut admin = new_admin_client(node.config.node_cluster_addr.clone(), &tls_client).await?;
    admin
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, FEED_PORT_BASE)],
        })
        .await?;
    wait_for_leader(&mut admin, 1).await;
    let sm = node.storage.state_machine_store();

    node.storage
        .transaction(vec![
            emit("registry", "d1", "a", DataTier::Internal),
            emit("registry", "d2", "b", DataTier::Public),
        ])
        .await?;
    let events = sm.outbox_events_after(None, 10)?;
    assert_eq!(2, events.len());
    assert_eq!(events[0].0.index, events[1].0.index);
    assert_eq!((0, 1), (events[0].0.position, events[1].0.position));
    assert_eq!(Some("d1"), events[0].1.domain_id.as_deref());
    assert_eq!(b"b".to_vec(), events[1].1.key);

    // A cursor skips what the consumer already holds.
    let rest = sm.outbox_events_after(Some(events[0].0), 10)?;
    assert_eq!(1, rest.len());
    assert_eq!(events[1].0, rest[0].0);

    // A disabled kind and Tier 2 data are refused, and nothing else of the
    // transaction is written.
    let err = node
        .storage
        .transaction(vec![emit("revocation", "d1", "c", DataTier::Internal)])
        .await
        .expect_err("a disabled kind must be refused");
    assert!(err.to_string().contains("FEED_KIND_DISABLED"), "{err}");
    let err = node
        .storage
        .transaction(vec![emit("registry", "d1", "c", DataTier::Sensitive)])
        .await
        .expect_err("Tier 2 must be refused");
    assert!(err.to_string().contains("FEED_TIER_REFUSED"), "{err}");
    assert_eq!(2, sm.outbox_events_after(None, 10)?.len());

    // The epoch is the index of the first event, and nothing is pruned yet.
    assert_eq!(Some(events[0].0.index), sm.feed_epoch()?);
    assert_eq!(0, sm.feed_floor()?);

    // Pruning drops the events up to the index on the voter and moves the
    // floor past it; later events survive.
    node.storage
        .transaction(vec![emit("registry", "d1", "later", DataTier::Internal)])
        .await?;
    let upto = events[1].0.index;
    let cmd = StoreCommand::Transaction(vec![MutationInner::PruneOutbox { upto_index: upto }]);
    node.storage
        .raft
        .client_write(pb::api::CommandRequest::try_from(cmd)?)
        .await?;
    let left = sm.outbox_events_after(None, 10)?;
    assert_eq!(1, left.len());
    assert_eq!(b"later".to_vec(), left[0].1.key);
    assert_eq!(upto + 1, sm.feed_floor()?);
    assert_eq!(Some(events[0].0.index), sm.feed_epoch()?);
    Ok(())
}

/// A restore drops the restored outbox and starts a new epoch.
#[serial_test::serial]
#[test]
fn test_restore_resets_the_feed() {
    TypeConfig::run(async {
        test_restore_resets_the_feed_inner().await.unwrap();
    });
}

async fn test_restore_resets_the_feed_inner() -> Result<()> {
    let provider = openstack_keystone_tls_provider::provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls = make_certificates()?;
    let feed_node = |id: u64, port_base: u16| {
        let tls = tls.clone();
        async move {
            Ok::<_, eyre::Report>(Arc::new(
                InstanceHolder::new_with_ds_config(id, |path| DistributedStorageConfiguration {
                    feed_kinds: vec!["registry".into()],
                    ..get_ds_config_with_port(id, port_base, path, tls)
                })
                .await?,
            ))
        }
    };
    let src = feed_node(1, FEED_PORT_BASE + 20).await?;
    spawn_raft_app(&src).await;
    let tls_client = get_client_tls_config(&src.config)?;
    let mut src_admin = new_admin_client(src.config.node_cluster_addr.clone(), &tls_client).await?;
    src_admin
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, FEED_PORT_BASE + 20)],
        })
        .await?;
    wait_for_leader(&mut src_admin, 1).await;
    src.storage
        .transaction(vec![emit("registry", "d1", "a", DataTier::Internal)])
        .await?;
    let src_epoch = src.storage.state_machine_store().feed_epoch()?;
    assert!(src_epoch.is_some());

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
    chunks[0].elect = true;

    let dst = feed_node(1, FEED_PORT_BASE + 40).await?;
    spawn_raft_app(&dst).await;
    let tls_client = get_client_tls_config(&dst.config)?;
    let mut dst_admin = new_admin_client(dst.config.node_cluster_addr.clone(), &tls_client).await?;
    dst_admin.restore(futures::stream::iter(chunks)).await?;
    wait_for_leader(&mut dst_admin, 1).await;
    let sm = dst.storage.state_machine_store();
    assert!(sm.outbox_events_after(None, 10)?.is_empty());
    assert_ne!(src_epoch, sm.feed_epoch()?);
    assert!(sm.feed_epoch()?.is_some());
    Ok(())
}

/// Retention prunes the oldest events beyond `feed_max_events`, and an
/// emergency DEK rotation removes the events under the revoked epoch and
/// starts a new feed epoch.
#[serial_test::serial]
#[test]
fn test_retention_and_emergency_rotation() {
    TypeConfig::run(async {
        test_retention_and_emergency_rotation_inner().await.unwrap();
    });
}

#[allow(unsafe_code)]
async fn test_retention_and_emergency_rotation_inner() -> Result<()> {
    use openstack_keystone_storage_crypto::{EnvKek, KekProvider, generate_dek};

    const PORT_BASE: u16 = FEED_PORT_BASE + 60;
    let provider = openstack_keystone_tls_provider::provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls = make_certificates()?;
    let node = Arc::new(
        InstanceHolder::new_with_ds_config(1, |path| DistributedStorageConfiguration {
            feed_kinds: vec!["registry".into()],
            feed_max_events: 2,
            ..get_ds_config_with_port(1, PORT_BASE, path, tls.clone())
        })
        .await?,
    );
    spawn_raft_app(&node).await;
    let tls_client = get_client_tls_config(&node.config)?;
    let mut admin = new_admin_client(node.config.node_cluster_addr.clone(), &tls_client).await?;
    admin
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, PORT_BASE)],
        })
        .await?;
    wait_for_leader(&mut admin, 1).await;
    let sm = node.storage.state_machine_store();

    for key in ["a", "b", "c"] {
        node.storage
            .transaction(vec![emit("registry", "d1", key, DataTier::Internal)])
            .await?;
    }
    let pruned = node.storage.prune_feed_outbox().await?;
    assert!(pruned.is_some());
    let keys: Vec<_> = sm
        .outbox_events_after(None, 10)?
        .into_iter()
        .map(|(_, e)| e.key)
        .collect();
    assert_eq!(vec![b"b".to_vec(), b"c".to_vec()], keys);
    assert_eq!(None, node.storage.prune_feed_outbox().await?);

    // Emergency rotation: the events under the revoked epoch go.
    let epoch_before = sm.feed_epoch()?;
    // SAFETY: the test is `#[serial_test::serial]`.
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
    }
    let kek = EnvKek::from_env()?;
    let cmd = StoreCommand::Transaction(vec![MutationInner::InstallDek {
        wrapped_dek: kek.wrap_dek(generate_dek().as_bytes()).await?,
        dek_version: sm.current_dek_wrapped()?.0 + 1,
        is_emergency: true,
    }]);
    node.storage
        .raft
        .client_write(pb::api::CommandRequest::try_from(cmd)?)
        .await?;
    assert!(sm.outbox_events_after(None, 10)?.is_empty());
    assert_ne!(epoch_before, sm.feed_epoch()?);
    Ok(())
}

/// The feed stream: identity-bound filters, resume, and reset.
#[serial_test::serial]
#[test]
fn test_subscribe_filters_resumes_and_resets() {
    TypeConfig::run(async {
        test_subscribe_inner().await.unwrap();
    });
}

/// Serves the feed on `port` for a subscriber holding the `feed-consumer`
/// role. The node's TLS mode cannot grant that role by certificate name, so
/// the listener authorises the subscriber by an explicit SVID binding, as a
/// SPIFFE deployment does with `peers`.
async fn serve_feed(node: &Arc<InstanceHolder>, port: u16, svid: &str) -> Result<()> {
    use openstack_keystone_distributed_storage::grpc::authz::{PeerAuthz, PeerRole};
    use openstack_keystone_distributed_storage::protobuf::raft::feed_service_server::FeedServiceServer;

    let authz = Arc::new(
        PeerAuthz::spiffe(
            vec!["keystone".into()],
            "/storage/".into(),
            "storage-operator".into(),
            vec![],
        )
        .with_peer_roles(std::collections::HashMap::from([(
            svid.to_owned(),
            vec![PeerRole::FeedConsumer],
        )])),
    );
    let svc = FeedServiceServer::new(node.storage.feed_service_with_authz(authz));
    let addr = get_addr_with_port(1, port);
    let tls = openstack_keystone_distributed_storage::network::get_server_tls_config(&node.config)?;
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .tls_config(tls)
            .expect("tls")
            .add_service(svc)
            .serve(addr)
            .await;
    });
    wait_for_listener(addr).await;
    Ok(())
}

async fn next_message(
    stream: &mut tonic::Streaming<pb::raft::FeedMessage>,
) -> Result<pb::raft::feed_message::Message> {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(10), stream.message())
            .await??
            .ok_or_else(|| eyre::eyre!("feed stream ended"))?;
        match msg.message {
            Some(pb::raft::feed_message::Message::Head(_)) => continue,
            Some(m) => return Ok(m),
            None => continue,
        }
    }
}

async fn test_subscribe_inner() -> Result<()> {
    use openstack_keystone_distributed_storage::protobuf::raft::feed_service_client::FeedServiceClient;
    use pb::raft::feed_message::Message;

    const PORT: u16 = FEED_PORT_BASE + 80;
    let provider = openstack_keystone_tls_provider::provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let pki = TestPki::new()?;
    let node_cert = pki.leaf(Some(&format!("{ROLE_SAN_PREFIX}node")))?;
    let op_cert = pki.leaf(Some(&format!("{ROLE_SAN_PREFIX}storage-operator")))?;
    let feed_cert = pki.leaf(Some(&format!("{ROLE_SAN_PREFIX}feed-consumer")))?;

    let node = Arc::new(
        InstanceHolder::new_with_ds_config(1, |path| DistributedStorageConfiguration {
            tls_role_san_prefix: Some(ROLE_SAN_PREFIX.to_string()),
            feed_kinds: vec!["registry".into(), "revocation".into()],
            feed_subscribers: vec![format!("{ROLE_SAN_PREFIX}feed-consumer=registry@d1")],
            feed_heartbeat_secs: 1,
            ..get_ds_config_with_port(
                1,
                PORT,
                path,
                pki.tls_configuration(&node_cert)
                    .expect("tls configuration"),
            )
        })
        .await?,
    );
    spawn_raft_app(&node).await;
    let op_ch = connect_as(&pki, &op_cert, 1, PORT).await?;
    ClusterAdminServiceClient::new(op_ch.clone())
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, PORT)],
        })
        .await?;
    wait_for_leader(&mut ClusterAdminServiceClient::new(op_ch), 1).await;

    node.storage
        .transaction(vec![
            emit("registry", "d1", "a", DataTier::Internal),
            emit("registry", "d2", "b", DataTier::Internal),
            emit("revocation", "d1", "r", DataTier::Internal),
        ])
        .await?;

    // Other roles and an unlisted identity get nothing.
    let node_ch = connect_as(&pki, &node_cert, 1, PORT).await?;
    let err = FeedServiceClient::new(node_ch)
        .subscribe(pb::raft::SubscribeRequest::default())
        .await
        .expect_err("a node is not a feed consumer");
    assert_eq!(tonic::Code::PermissionDenied, err.code());

    // The subscriber sees only registry events of d1, even if it asks for more.
    serve_feed(&node, PORT + 10, &format!("{ROLE_SAN_PREFIX}feed-consumer")).await?;
    let feed_ch = connect_as(&pki, &feed_cert, 1, PORT + 10).await?;
    let mut client = FeedServiceClient::new(feed_ch);
    let mut stream = client
        .subscribe(pb::raft::SubscribeRequest {
            kinds: vec!["registry".into(), "revocation".into()],
            domains: vec!["d1".into(), "d2".into()],
            ..Default::default()
        })
        .await?
        .into_inner();
    let Message::Events(first) = next_message(&mut stream).await? else {
        panic!("expected events");
    };
    assert_eq!(1, first.events.len());
    assert_eq!(b"a".to_vec(), first.events[0].key);
    let epoch = first.epoch;
    let last = (first.events[0].index, first.events[0].position);

    // A later event is pushed on the open stream.
    node.storage
        .transaction(vec![emit("registry", "d1", "later", DataTier::Internal)])
        .await?;
    let Message::Events(pushed) = next_message(&mut stream).await? else {
        panic!("expected events");
    };
    assert_eq!(b"later".to_vec(), pushed.events[0].key);
    drop(stream);

    // Resuming from the first cursor yields only what follows it.
    let mut resumed = client
        .subscribe(pb::raft::SubscribeRequest {
            epoch,
            has_cursor: true,
            cursor_index: last.0,
            cursor_position: last.1,
            ..Default::default()
        })
        .await?
        .into_inner();
    let Message::Events(rest) = next_message(&mut resumed).await? else {
        panic!("expected events");
    };
    assert_eq!(b"later".to_vec(), rest.events[0].key);
    drop(resumed);

    // A cursor of another epoch is reset.
    let mut stale = client
        .subscribe(pb::raft::SubscribeRequest {
            epoch: epoch + 1,
            has_cursor: true,
            cursor_index: last.0,
            ..Default::default()
        })
        .await?
        .into_inner();
    assert!(matches!(next_message(&mut stale).await?, Message::Reset(_)));
    Ok(())
}

struct Mirror;

impl openstack_keystone_distributed_storage::feed_consumer::FeedSink for Mirror {
    fn mutations(
        &self,
        event: &openstack_keystone_distributed_storage::feed_consumer::FeedEventData,
    ) -> Result<Vec<Mutation>, openstack_keystone_distributed_storage::ApiStoreError> {
        Ok(vec![if event.removed {
            Mutation::Remove {
                key: event.key.clone(),
                keyspace: "mirror".into(),
                expected_revision: None,
            }
        } else {
            Mutation::Set {
                expected_revision: None,
                key: event.key.clone(),
                keyspace: "mirror".into(),
                metadata: Metadata::new(),
                value: event.value.clone().unwrap_or_default(),
            }
        }])
    }
}

/// A consumer mirrors a source's events into its own storage, applies each
/// once, resumes from its stored cursor, and starts over after a reset.
#[serial_test::serial]
#[test]
fn test_consumer_mirrors_resumes_and_reseeds() {
    TypeConfig::run(async {
        test_consumer_inner().await.unwrap();
    });
}

async fn test_consumer_inner() -> Result<()> {
    use openstack_keystone_distributed_storage::feed_consumer::{FeedConsumer, RunOutcome};

    const SRC: u16 = FEED_PORT_BASE + 100;
    const DST: u16 = FEED_PORT_BASE + 120;
    let provider = openstack_keystone_tls_provider::provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let pki = TestPki::new()?;
    let node_cert = pki.leaf(Some(&format!("{ROLE_SAN_PREFIX}node")))?;
    let op_cert = pki.leaf(Some(&format!("{ROLE_SAN_PREFIX}storage-operator")))?;
    let feed_cert = pki.leaf(Some(&format!("{ROLE_SAN_PREFIX}feed-consumer")))?;

    let src = Arc::new(
        InstanceHolder::new_with_ds_config(1, |path| DistributedStorageConfiguration {
            tls_role_san_prefix: Some(ROLE_SAN_PREFIX.to_string()),
            feed_kinds: vec!["registry".into()],
            feed_subscribers: vec![format!("{ROLE_SAN_PREFIX}feed-consumer=registry")],
            ..get_ds_config_with_port(
                1,
                SRC,
                path,
                pki.tls_configuration(&node_cert)
                    .expect("tls configuration"),
            )
        })
        .await?,
    );
    spawn_raft_app(&src).await;
    // The consumer is its own single-node cluster that presents the
    // feed-consumer identity.
    let dst = Arc::new(
        InstanceHolder::new_with_ds_config(1, |path| DistributedStorageConfiguration {
            tls_role_san_prefix: Some(ROLE_SAN_PREFIX.to_string()),
            ..get_ds_config_with_port(
                1,
                DST,
                path,
                pki.tls_configuration(&feed_cert)
                    .expect("tls configuration"),
            )
        })
        .await?,
    );
    spawn_raft_app(&dst).await;
    for (port, ch_cert) in [(SRC, &op_cert), (DST, &op_cert)] {
        let ch = connect_as(&pki, ch_cert, 1, port).await?;
        let mut admin = ClusterAdminServiceClient::new(ch);
        admin
            .init(pb::raft::InitRequest {
                nodes: vec![new_node_with_port(1, port)],
            })
            .await?;
        wait_for_leader(&mut admin, 1).await;
    }

    src.storage
        .transaction(vec![
            emit("registry", "d1", "a", DataTier::Internal),
            emit("registry", "d2", "b", DataTier::Internal),
        ])
        .await?;

    serve_feed(&src, SRC + 10, &format!("{ROLE_SAN_PREFIX}feed-consumer")).await?;
    let consumer = Arc::new(FeedConsumer::new(
        "src",
        get_addr_with_port(1, SRC + 10).to_string(),
        dst.storage.tls_client.clone(),
        dst.storage.clone(),
        Arc::new(Mirror),
        vec!["registry".into()],
        vec![],
    ));
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let runner = {
        let consumer = consumer.clone();
        tokio::spawn(async move {
            consumer
                .run(async {
                    let _ = stop_rx.await;
                })
                .await;
        })
    };

    let mirrored = |key: &'static str| {
        let dst = dst.clone();
        async move {
            for _ in 0..100 {
                if dst
                    .storage
                    .get_by_key(key.as_bytes(), Some("mirror"))
                    .await
                    .ok()
                    .flatten()
                    .is_some()
                {
                    return true;
                }
                TypeConfig::sleep(Duration::from_millis(100)).await;
            }
            false
        }
    };
    assert!(mirrored("a").await, "event a was not mirrored");
    assert!(mirrored("b").await, "event b was not mirrored");
    src.storage
        .transaction(vec![emit("registry", "d1", "c", DataTier::Internal)])
        .await?;
    assert!(mirrored("c").await, "a later event was not streamed");
    let (cursor, _) = consumer.load_cursor().await?.expect("a stored cursor");
    assert_eq!(
        Some(cursor.epoch),
        src.storage.state_machine_store().feed_epoch()?
    );

    // Applying a covered event again changes nothing.
    let before = consumer.load_cursor().await?;
    consumer
        .apply(
            cursor.epoch,
            vec![
                openstack_keystone_distributed_storage::feed_consumer::FeedEventData {
                    index: cursor.index,
                    position: cursor.position,
                    kind: "registry".into(),
                    domain_id: None,
                    key: b"zz".to_vec(),
                    removed: false,
                    value: None,
                },
            ],
        )
        .await?;
    assert_eq!(before, consumer.load_cursor().await?);
    assert!(
        dst.storage
            .get_by_key(b"zz", Some("mirror"))
            .await?
            .is_none()
    );

    let _ = stop_tx.send(());
    let _ = runner.await;

    // A cursor of another epoch is reset by the source: one run reseeds and
    // clears it, the next starts from the beginning.
    let (record, _) = consumer.load_cursor().await?.expect("cursor");
    dst.storage
        .transaction(vec![Mutation::Set {
            expected_revision: Some(consumer.load_cursor().await?.expect("cursor").1),
            key: b"src".to_vec(),
            keyspace: "feed_cursor".into(),
            metadata: Metadata::new(),
            value: rmp_serde::to_vec(
                &openstack_keystone_distributed_storage::feed_consumer::CursorRecord {
                    epoch: record.epoch + 1,
                    ..record
                },
            )?,
        }])
        .await?;
    assert_eq!(RunOutcome::Reset, consumer.run_once().await?);
    assert!(consumer.load_cursor().await?.is_none());
    Ok(())
}
