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
    Ok(())
}
