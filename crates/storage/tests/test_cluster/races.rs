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
//! Replication and leader races.

use super::harness::*;
use super::*;

/// Regression test for GitHub #1135: intermittent false-negative prefix_index
/// reads under concurrent load on the leader.
///
/// Even when `ensure_linearizable(ReadPolicy::ReadIndex)` succeeds directly on
/// the leader (no ForwardToLeader), `prefix_index` can return an empty result
/// for index entries that have already been committed via Raft.  This happens
/// when OpenRaft's read-index check passes before the Fjall batch for that
/// entry has finished committing and become visible to the index() iterator.
///
/// The test creates a 3-node cluster and hammers the leader with concurrent
/// set_index_key + prefix_index operations using many parallel tasks.  A
/// passing run means the race window has been closed or is too narrow to hit;
/// a failing run means the mitigation is insufficient.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_prefix_index_leader_race_concurrent() {
    TypeConfig::run(test_prefix_index_leader_race_concurrent_inner()).unwrap();
}

// Port offset to avoid conflicts with other cluster tests.
const PREFIX_INDEX_RACE_PORT_BASE: u16 = 300;

#[allow(unsafe_code)]
async fn test_prefix_index_leader_race_concurrent_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let tls_configuration = make_certificates()?;

    // --- Start 3 nodes in threads.
    let instance1 = Arc::new(
        InstanceHolder::new_with_port(1, PREFIX_INDEX_RACE_PORT_BASE, tls_configuration.clone())
            .await?,
    );
    let instance2 = Arc::new(
        InstanceHolder::new_with_port(2, PREFIX_INDEX_RACE_PORT_BASE, tls_configuration.clone())
            .await?,
    );
    let instance3 = Arc::new(
        InstanceHolder::new_with_port(3, PREFIX_INDEX_RACE_PORT_BASE, tls_configuration.clone())
            .await?,
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
        instance1.config.node_cluster_addr.clone(),
        &tls_client_config,
    )
    .await?;

    admin_client1
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, PREFIX_INDEX_RACE_PORT_BASE)],
        })
        .await?;
    wait_for_leader(&mut admin_client1, 1).await;

    admin_client1
        .add_learner(pb::raft::AddLearnerRequest {
            node: Some(new_node_with_port(2, PREFIX_INDEX_RACE_PORT_BASE)),
        })
        .await?;
    admin_client1
        .add_learner(pb::raft::AddLearnerRequest {
            node: Some(new_node_with_port(3, PREFIX_INDEX_RACE_PORT_BASE)),
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

    // --- Phase 1: Sequential write + immediate prefix_index read on same node.
    //
    // This exercises the apply-order-vs-batch-commit race: `set_index_key`
    // writes to the leader's Raft log and waits for commit, but the local
    // prefix_index scan may execute before the state machine's batch.commit()
    // for that entry has finished.
    // Sequential write + immediate prefix_index read on leader (phase 1).
    // Uses 100 iterations to increase chance of hitting the narrow race window.
    let phase1_iterations = 100;
    let mut phase1_failures = 0;

    for i in 0..phase1_iterations {
        let idx_key = format!("race:idx:seq:{}", i);

        // Write the index key via Raft (goes through leader's apply path).
        instance1.storage.set_index_key(idx_key.clone()).await?;

        // Immediately read using prefix_index on the SAME leader node — this
        // avoids any follower replication delay and isolates the apply-vs-read
        // race within a single node.
        let results = instance1
            .storage
            .prefix_index("race:idx:seq:".as_bytes())
            .await?;

        if !results.iter().any(|k| k == &idx_key) {
            phase1_failures += 1;
            println!(
                "PHASE1 ITER {}: prefix_index missing key '{}', found {} entries",
                i,
                idx_key,
                results.len()
            );
        }
    }

    // Drop sequential keys before phase 2 to reduce index size for concurrent
    // hammering.
    for i in 0..phase1_iterations {
        let idx_key = format!("race:idx:seq:{}", i);
        instance1.storage.remove_index(idx_key).await?;
    }
    TypeConfig::sleep(Duration::from_millis(500)).await;

    // --- Phase 2: Concurrent writes + reads on the leader.
    //
    // Multiple tasks concurrently create index keys and query prefix_index via
    // the leader node.  This reproduces the loadtest scenario from #1135 where
    // many parallelauthenticated API requests each create + look up mapping
    // rulesets.
    // Concurrent writes + reads on leader (phase 2).
    let phase2_iterations = 80;
    let leader_storage = instance1.storage.clone();
    let phase2_prefix = "race:idx:conc:";
    let (phase2_tx, mut phase2_rx) = tokio::sync::mpsc::channel::<bool>(phase2_iterations);

    let mut handles = Vec::with_capacity(phase2_iterations);
    for i in 0..phase2_iterations {
        let storage = leader_storage.clone();
        let prefix = phase2_prefix.to_string();
        let tx = phase2_tx.clone();

        let handle = tokio::spawn(async move {
            let idx_key = format!("{}{}", prefix, i);
            let mut ok = true;

            // Write the index key.
            if let Err(e) = storage.set_index_key(idx_key.clone()).await {
                eprintln!("set_index_key failed for {}: {}", idx_key, e);
                ok = false;
            }

            // Immediately read via prefix_index on the leader.
            match storage.prefix_index(prefix.as_bytes()).await {
                Ok(results) => {
                    if !results.iter().any(|k| k == &idx_key) {
                        println!(
                            "PHASE2 TASK {}: prefix_index missing key '{}', found {} entries",
                            i,
                            idx_key,
                            results.len()
                        );
                        ok = false;
                    }
                }
                Err(e) => {
                    eprintln!("prefix_index failed {}: {}", i, e);
                    ok = false;
                }
            }

            let _ = tx.send(ok).await;
        });
        handles.push(handle);
    }
    drop(phase2_tx);

    // Await all tasks and count failures.
    let mut phase2_failures = 0;
    for handle in handles {
        let _ = handle.await;
    }
    while let Some(task_ok) = phase2_rx.recv().await {
        if !task_ok {
            phase2_failures += 1;
        }
    }

    drop(admin_client1);
    drop(tls_client_config);

    let total_failures = phase1_failures + phase2_failures;
    let total_ops = phase1_iterations + phase2_iterations;

    println!(
        "prefix_index leader-race test complete: phase1={}/{} failures, \
         phase2={}/{} failures, total={}/{} failures",
        phase1_failures,
        phase1_iterations,
        phase2_failures,
        phase2_iterations,
        total_failures,
        total_ops
    );

    if total_failures > 0 {
        panic!(
            "prefix_index false-negative detected: {total_failures} failures out of \
             {total_ops} total operations (phase1={phase1_failures}, phase2={phase2_failures})"
        );
    }

    Ok(())
}

/// Regression test: write key-val to leader, read immediately from follower.
///
/// Reproduces the Raft replication race condition observed in k8s integration
/// tests (see `api_v4::mapping::ruleset::create` / `update` / `delete`
/// failures).
///
/// Pattern:
/// 1. `set_value` on leader (node 1) — Raft proposal commits asynchronously
/// 2. `get_by_key` on follower (node 2) — local FjallDB may not have replicated
///    yet
/// 3. Current mitigation: `ensure_linearizable(ReadIndex)` retry loop in
///    `app.rs` (3 retries, 14ms total) then fall back to local read
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
        instance1.config.node_cluster_addr.clone(),
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
/// This mirrors the
/// `api_v4::mapping::ruleset::delete::test_delete_mapping_ruleset`
/// failure: DELETE returns 204 on leader, but subsequent GET on follower
/// returns 200 with the deleted data instead of 404.
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
        instance1.config.node_cluster_addr.clone(),
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
