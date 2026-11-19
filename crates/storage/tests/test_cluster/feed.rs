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

use super::harness::*;
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
