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
//! Replicated keyspace drop and keyspace listing (ADR 0044 §3).
//!
//! `DropKeyspace` is committed through Raft, so a drop proposed on the leader
//! removes the allow-listed keyspace, with data, on every node, while
//! unrelated keyspaces are refused and left untouched.

use super::harness::*;
use super::*;

const SINGLE_USE_PORT_BASE: u16 = 2400;

/// Waits until every node lists exactly `expected` single-use keyspaces.
async fn expect_listing(nodes: &[RestartableNode], expected: &[&str]) -> bool {
    for _ in 0..100 {
        let mut all = true;
        for node in nodes {
            let got = node.storage().list_keyspaces("single_use_").await;
            all &= got.is_ok_and(|g| g == expected);
        }
        if all {
            return true;
        }
        TypeConfig::sleep(Duration::from_millis(100)).await;
    }
    false
}

fn create(keyspace: &str, key: &str) -> Result<Mutation> {
    Ok(Mutation::create_if_absent(
        key.as_bytes().to_vec(),
        Vec::<u8>::new(),
        Metadata::new(),
        Some(keyspace),
    )?)
}

#[serial_test::serial]
#[test]
fn test_drop_keyspace_is_replicated_and_allow_listed() {
    TypeConfig::run(test_drop_keyspace_is_replicated_and_allow_listed_inner()).unwrap();
}

async fn test_drop_keyspace_is_replicated_and_allow_listed_inner() -> Result<()> {
    let nodes = start_three_node_cluster_with(SINGLE_USE_PORT_BASE, |_| {}).await?;
    let leader = nodes[0].storage().clone();

    // A create, and its replay, in a bucket keyspace.
    let first = leader
        .transaction(vec![create("single_use_assertion_100", "k1")?])
        .await?;
    assert!(first.violations.is_empty());
    let replay = leader
        .transaction(vec![create("single_use_assertion_100", "k1")?])
        .await;
    assert!(
        matches!(replay, Err(ApiStoreError::Conflict { .. })),
        "{replay:?}"
    );
    leader
        .transaction(vec![create("single_use_totp_100", "k2")?])
        .await?;
    assert!(
        expect_listing(&nodes, &["single_use_assertion_100", "single_use_totp_100"]).await,
        "every node lists the bucket keyspaces"
    );

    // Unrelated state, which a drop must never reach.
    set_value_retrying(&leader, "keep", "me").await?;

    // Refused names leave everything in place. The refusal is a `Rejected`
    // error, not a `Conflict`: a replay check must not read it as one.
    for name in ["data", "meta", "index", "webauthn_state_1", "single_use_x"] {
        let res = leader
            .transaction(vec![Mutation::drop_keyspace(name)])
            .await;
        assert!(
            matches!(
                &res,
                Err(ApiStoreError::Rejected { violation_type, .. })
                    if violation_type == "KEYSPACE_DROP_REFUSED"
            ),
            "{name}: {res:?}"
        );
    }
    assert!(leader.get_by_key(b"keep", None).await?.is_some());

    // A drop sharing a transaction with other mutations is refused and rolls the
    // whole batch back.
    let mixed = leader
        .transaction(vec![
            create("single_use_assertion_100", "k3")?,
            Mutation::drop_keyspace("single_use_assertion_100"),
        ])
        .await;
    assert!(matches!(mixed, Err(ApiStoreError::Rejected { .. })));
    assert!(
        leader
            .get_by_key(b"k3", Some("single_use_assertion_100"))
            .await?
            .is_none()
    );

    // The allowed drop removes the keyspace and its data everywhere and
    // leaves the other bucket alone.
    let dropped = leader
        .transaction(vec![Mutation::drop_keyspace("single_use_assertion_100")])
        .await?;
    assert!(dropped.violations.is_empty());
    assert!(
        expect_listing(&nodes, &["single_use_totp_100"]).await,
        "the drop reached every node"
    );
    assert!(!leader.keyspace_exists("single_use_assertion_100").await?);
    assert!(
        leader
            .get_by_key(b"k1", Some("single_use_assertion_100"))
            .await?
            .is_none()
    );

    // Idempotent: dropping a missing keyspace is a no-op.
    let again = leader
        .transaction(vec![Mutation::drop_keyspace("single_use_assertion_100")])
        .await?;
    assert!(again.violations.is_empty());

    // A dropped credential can be created again (new bucket life).
    let recreated = leader
        .transaction(vec![create("single_use_assertion_100", "k1")?])
        .await?;
    assert!(recreated.violations.is_empty());
    Ok(())
}
