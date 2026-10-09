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
//! Crash-consistency, leader-change read and keyspace-collision scenarios
//! (GitHub #1307).

use std::sync::Mutex;

use super::harness::*;
use super::*;

const CRASH_FOLLOWER_PORT_BASE: u16 = 1700;
const CRASH_LEADER_PORT_BASE: u16 = 1750;
const LEADER_CHANGE_READ_PORT_BASE: u16 = 1800;
const KEYSPACE_COLLISION_PORT_BASE: u16 = 1850;

/// Starts three restartable nodes on `port`+id and forms a three-voter
/// cluster led by node 1.
async fn start_three_node_cluster(port: u16) -> Result<Vec<RestartableNode>> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
    let tls = make_certificates()?;

    let mut nodes = Vec::new();
    for id in 1..=3 {
        let mut node = RestartableNode::new(id, port, &tls).await?;
        node.start().await;
        nodes.push(node);
    }
    let mut admin1 = nodes[0].admin().await?;
    admin1
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, port)],
        })
        .await?;
    wait_for_leader(&mut admin1, 1).await;
    for id in [2u64, 3] {
        nodes[id as usize - 1]
            .storage()
            .join_cluster(
                &get_addr_with_port(1, port).to_string(),
                &get_addr_with_port(id, port).to_string(),
            )
            .await?;
    }
    admin1
        .change_membership(pb::raft::ChangeMembershipRequest {
            members: vec![1, 2, 3],
            retain: false,
        })
        .await?;
    Ok(nodes)
}

async fn wait_for_leader_not(node: &RestartableNode, not: u64) -> u64 {
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

/// Runs `writers` concurrent writers against `target` until `stop` is set,
/// recording every write the cluster acknowledged as `(key, value)`.
fn spawn_acked_writers(
    target: Arc<Storage>,
    writers: usize,
    stop: Arc<std::sync::atomic::AtomicBool>,
    acked: Arc<Mutex<Vec<(String, String)>>>,
) -> Vec<tokio::task::JoinHandle<()>> {
    use std::sync::atomic::Ordering;
    (0..writers)
        .map(|w| {
            let target = target.clone();
            let stop = stop.clone();
            let acked = acked.clone();
            tokio::spawn(async move {
                let mut i = 0usize;
                while !stop.load(Ordering::Relaxed) {
                    let key = format!("crash-{w}-{i}");
                    let value = format!("val-{w}-{i}");
                    let Ok(env) = make_env(&value) else { return };
                    let res = tokio::time::timeout(
                        Duration::from_secs(5),
                        target.set_value(key.clone(), env, test_keyspace(i), None),
                    )
                    .await;
                    // Only a positive acknowledgement is a durability promise.
                    if let Ok(Ok(_)) = res {
                        if let Ok(mut guard) = acked.lock() {
                            guard.push((key, value));
                        }
                        i += 1;
                    } else {
                        // Failed or timed out: unknown outcome, never asserted
                        // on. Use a fresh key for the next attempt.
                        i += 1;
                        TypeConfig::sleep(Duration::from_millis(50)).await;
                    }
                }
            })
        })
        .collect()
}

/// Asserts that `node` serves every acknowledged write with its value.
async fn assert_serves_acked(node: &RestartableNode, acked: &[(String, String)]) -> Result<()> {
    for (key, value) in acked {
        // `acked` keys carry their keyspace index in the trailing counter.
        let i: usize = key
            .rsplit('-')
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| eyre::eyre!("malformed key {key}"))?;
        let ks = test_keyspace(i);
        let got = get_by_key_retrying(node.storage(), key.as_bytes(), ks.as_deref())
            .await?
            .ok_or_else(|| eyre::eyre!("node {} lost acknowledged write {key}", node.node_id))?;
        assert_eq!(
            value,
            &got.try_deserialize::<String>()?.data,
            "node {} serves a wrong value for {key}",
            node.node_id
        );
    }
    Ok(())
}

async fn wait_converged(nodes: &[RestartableNode], leader: usize) -> Result<()> {
    let index = nodes[leader]
        .storage()
        .last_log_index()
        .ok_or_else(|| eyre::eyre!("leader must have a log"))?;
    for node in nodes {
        assert!(
            poll_until(Duration::from_millis(100), 300, || {
                node.storage().last_log_index() >= Some(index)
            })
            .await,
            "node {} did not converge to log index {index}",
            node.node_id
        );
    }
    Ok(())
}

/// A follower is killed (no goodbye) while a write stream is in flight and
/// restarted from its persisted log: it replays/catches up, and every node
/// serves every acknowledged write.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_follower_crash_during_writes_recovers() {
    TypeConfig::run(test_follower_crash_during_writes_recovers_inner()).unwrap();
}

async fn test_follower_crash_during_writes_recovers_inner() -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut nodes = start_three_node_cluster(CRASH_FOLLOWER_PORT_BASE).await?;

    let stop = Arc::new(AtomicBool::new(false));
    let acked = Arc::new(Mutex::new(Vec::new()));
    let handles = spawn_acked_writers(nodes[0].storage().clone(), 8, stop.clone(), acked.clone());

    TypeConfig::sleep(Duration::from_millis(1500)).await;
    nodes[2].kill().await;
    TypeConfig::sleep(Duration::from_millis(1500)).await;
    nodes[2].restart().await?;
    TypeConfig::sleep(Duration::from_millis(1500)).await;

    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.await?;
    }
    let acked = acked.lock().map_err(|_| eyre::eyre!("poisoned"))?.clone();
    assert!(acked.len() > 20, "only {} writes acknowledged", acked.len());

    wait_converged(&nodes, 0).await?;
    for node in &nodes {
        assert_serves_acked(node, &acked).await?;
    }
    Ok(())
}

/// The leader is killed mid-stream: no acknowledged write is lost on the
/// survivors, and the old leader rejoins from its log and serves them too.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_leader_crash_during_writes_loses_no_acked_write() {
    TypeConfig::run(test_leader_crash_during_writes_loses_no_acked_write_inner()).unwrap();
}

async fn test_leader_crash_during_writes_loses_no_acked_write_inner() -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut nodes = start_three_node_cluster(CRASH_LEADER_PORT_BASE).await?;

    let stop = Arc::new(AtomicBool::new(false));
    let acked = Arc::new(Mutex::new(Vec::new()));
    let handles = spawn_acked_writers(nodes[0].storage().clone(), 8, stop.clone(), acked.clone());

    TypeConfig::sleep(Duration::from_millis(1500)).await;
    nodes[0].kill().await;
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.await?;
    }
    let acked = acked.lock().map_err(|_| eyre::eyre!("poisoned"))?.clone();
    assert!(acked.len() > 20, "only {} writes acknowledged", acked.len());

    let new_leader = wait_for_leader_not(&nodes[1], 1).await;
    for node in &nodes[1..] {
        assert_serves_acked(node, &acked).await?;
    }

    nodes[0].restart().await?;
    wait_converged(&nodes, new_leader as usize - 1).await?;
    assert_serves_acked(&nodes[0], &acked).await?;
    Ok(())
}

/// Reads issued on the survivors while the leader dies must never return
/// stale data: each answer is either an error or the last acknowledged
/// value (GitHub #1302 / #1135).
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_reads_never_stale_across_leader_change() {
    TypeConfig::run(test_reads_never_stale_across_leader_change_inner()).unwrap();
}

async fn test_reads_never_stale_across_leader_change_inner() -> Result<()> {
    let mut nodes = start_three_node_cluster(LEADER_CHANGE_READ_PORT_BASE).await?;

    for round in 0..20 {
        set_value_retrying(nodes[0].storage(), "hot", &format!("v{round}")).await?;
    }
    // Last acknowledged value.
    let last = "v19";

    nodes[0].kill().await;
    let mut ok_reads = 0;
    for _ in 0..200 {
        for node in &nodes[1..] {
            match node.storage().get_by_key(b"hot", None).await {
                Ok(Some(v)) => {
                    assert_eq!(last, v.try_deserialize::<String>()?.data, "stale read");
                    ok_reads += 1;
                }
                Ok(None) => panic!("node {} reported an acknowledged key missing", node.node_id),
                // Unavailable during the election is acceptable.
                Err(_) => {}
            }
        }
        if ok_reads > 20 {
            break;
        }
        TypeConfig::sleep(Duration::from_millis(50)).await;
    }
    assert!(ok_reads > 0, "no read succeeded after the leader change");
    Ok(())
}

/// Engine-internal names must not collide with user data: bare keys that look
/// like `_meta:*` system keys, and the same key in several keyspaces, stay
/// independent across replication and restart; reserved keyspaces are
/// refused (GitHub #1294).
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_user_keys_never_collide_with_system_keys() {
    TypeConfig::run(test_user_keys_never_collide_with_system_keys_inner()).unwrap();
}

async fn test_user_keys_never_collide_with_system_keys_inner() -> Result<()> {
    let mut nodes = start_three_node_cluster(KEYSPACE_COLLISION_PORT_BASE).await?;
    let leader = nodes[0].storage().clone();

    const SYSTEM_LIKE: [&str; 3] = [
        "_meta:dek:current",
        "_meta:quarantine:data:1",
        "last_applied_log",
    ];
    for key in SYSTEM_LIKE {
        for (ks, value) in [(None, "in-data"), (Some("ks_alpha"), "in-alpha")] {
            leader
                .set_value(
                    key.to_string(),
                    make_env(value)?,
                    ks.map(str::to_string),
                    None,
                )
                .await?;
        }
    }

    // Reserved keyspaces are refused.
    for reserved in ["meta", "logs", "index"] {
        assert!(
            leader
                .set_value(
                    "k".to_string(),
                    make_env("x")?,
                    Some(reserved.to_string()),
                    None,
                )
                .await
                .is_err(),
            "write into reserved keyspace {reserved} must be rejected"
        );
    }

    // Removing the key in one keyspace keeps its twin (and metadata).
    leader
        .remove(
            "_meta:dek:current".to_string(),
            Some("ks_alpha".to_string()),
        )
        .await?;

    wait_converged(&nodes, 0).await?;
    nodes[1].kill().await;
    nodes[1].restart().await?;
    wait_converged(&nodes, 0).await?;

    for node in &nodes {
        let twin = get_by_key_retrying(node.storage(), b"_meta:dek:current", None)
            .await?
            .ok_or_else(|| eyre::eyre!("node {} lost the data-keyspace key", node.node_id))?;
        assert_eq!("in-data", twin.try_deserialize::<String>()?.data);
        assert!(
            get_by_key_retrying(node.storage(), b"_meta:dek:current", Some("ks_alpha"))
                .await?
                .is_none(),
            "removed key still visible on node {}",
            node.node_id
        );
        for key in &SYSTEM_LIKE[1..] {
            for (ks, want) in [(None, "in-data"), (Some("ks_alpha"), "in-alpha")] {
                let got = get_by_key_retrying(node.storage(), key.as_bytes(), ks)
                    .await?
                    .ok_or_else(|| eyre::eyre!("node {} lost {key}", node.node_id))?;
                assert_eq!(want, got.try_deserialize::<String>()?.data);
            }
        }
    }
    Ok(())
}
