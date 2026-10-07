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
//! # Raft node readiness (GitHub #1306)
//!
//! Decides whether this node should receive traffic, based on the live
//! `openraft` metrics and the state machine's quarantine set. Used by the
//! `/ready` probe through [`crate::StorageApi::readiness`].

use std::time::Duration;

use crate::types::RaftMetrics;

/// Maximum number of committed-but-not-applied log entries before a node is
/// reported as not ready. A node beyond this is installing a snapshot or
/// catching up after a partition, and would serve stale reads (including a
/// stale DEK epoch, since `InstallDek` travels through the log).
pub const READINESS_MAX_APPLY_LAG: u64 = 1000;

/// Maximum time a leader may go without a quorum acknowledgement before it
/// is reported as not ready: well above the election timeout, so a leader
/// beyond it has most likely been partitioned away from its followers.
pub const READINESS_MAX_QUORUM_ACK_AGE: Duration = Duration::from_secs(6);

/// Reasons why a node with the given Raft state should not receive traffic
/// (GitHub #1306). Empty when the node is ready.
///
/// A Raft core that has stopped (fatal storage error, panic, or shutdown) is
/// deliberately *not* an issue: `Storage::readiness` queries
/// `is_initialized()` first, which fails once the core task is down, so the
/// condition surfaces as an `Err` — reported as `error` by the health
/// endpoint and handled by the liveness probe (restart) — not as a readiness
/// issue.
///
/// `quorum_ack_age` is the time since the leader's last quorum
/// acknowledgement (`RaftMetrics::last_quorum_acked`); only consulted when
/// this node is the leader of a multi-voter cluster. A single-voter leader
/// is its own quorum and openraft never refreshes its acknowledgement time.
pub fn readiness_issues(
    metrics: &RaftMetrics,
    node_id: u64,
    quorum_ack_age: Option<Duration>,
    quarantined_partitions: &[String],
) -> Vec<String> {
    let mut issues = Vec::new();
    match metrics.current_leader {
        None => issues.push("no raft leader known".to_string()),
        Some(leader) if leader == node_id && !is_self_quorum(metrics, node_id) => {
            match quorum_ack_age {
                Some(age) if age <= READINESS_MAX_QUORUM_ACK_AGE => {}
                Some(age) => issues.push(format!(
                    "leader not acknowledged by a quorum for {}s",
                    age.as_secs()
                )),
                None => issues.push("leader not yet acknowledged by a quorum".to_string()),
            }
        }
        Some(_) => {}
    }
    if let Some(lag) = crate::prometheus_metrics::apply_lag(metrics)
        && lag > READINESS_MAX_APPLY_LAG
    {
        issues.push(format!(
            "applied index lags the cluster commit index by {lag} entries"
        ));
    }
    if !quarantined_partitions.is_empty() {
        issues.push(format!(
            "quarantined partitions: {}",
            quarantined_partitions.join(", ")
        ));
    }
    issues
}

/// Whether `node_id` is the only voter of the effective membership.
fn is_self_quorum(metrics: &RaftMetrics, node_id: u64) -> bool {
    let mut voters = metrics.membership_config.membership().voter_ids();
    voters.next() == Some(node_id) && voters.next().is_none()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use openraft::{Membership, RaftMetrics, StoredMembership};

    use super::*;
    use crate::TypeConfig;
    use crate::types::LogId;

    /// Metrics for a three-voter cluster `{1, 2, 3}`.
    fn metrics(
        node_id: u64,
        current_leader: Option<u64>,
        cluster_committed: Option<u64>,
        last_applied: Option<u64>,
    ) -> RaftMetrics<TypeConfig> {
        metrics_with_voters(
            node_id,
            &[1, 2, 3],
            current_leader,
            cluster_committed,
            last_applied,
        )
    }

    fn metrics_with_voters(
        node_id: u64,
        voters: &[u64],
        current_leader: Option<u64>,
        cluster_committed: Option<u64>,
        last_applied: Option<u64>,
    ) -> RaftMetrics<TypeConfig> {
        let mut m = RaftMetrics::<TypeConfig>::new_initial(node_id);
        m.current_leader = current_leader;
        m.cluster_committed = cluster_committed.map(|i| LogId::new(1, i));
        m.last_applied = last_applied.map(|i| LogId::new(1, i));
        m.membership_config = Arc::new(StoredMembership::new(
            None,
            Membership::new_with_defaults(
                vec![voters.iter().copied().collect()],
                BTreeSet::<u64>::new(),
            ),
        ));
        m
    }

    #[test]
    fn follower_caught_up_is_ready() {
        let m = metrics(2, Some(1), Some(100), Some(95));
        assert!(readiness_issues(&m, 2, None, &[]).is_empty());
    }

    #[test]
    fn no_leader_is_not_ready() {
        let m = metrics(2, None, Some(100), Some(100));
        assert_eq!(
            readiness_issues(&m, 2, None, &[]),
            vec!["no raft leader known".to_string()]
        );
    }

    #[test]
    fn lagging_follower_is_not_ready() {
        let m = metrics(2, Some(1), Some(5000), Some(10));
        let issues = readiness_issues(&m, 2, None, &[]);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("4990 entries"), "{issues:?}");
    }

    #[test]
    fn lag_at_threshold_is_ready() {
        let m = metrics(2, Some(1), Some(READINESS_MAX_APPLY_LAG), None);
        assert!(readiness_issues(&m, 2, None, &[]).is_empty());
    }

    #[test]
    fn leader_with_recent_quorum_ack_is_ready() {
        let m = metrics(1, Some(1), Some(10), Some(10));
        assert!(readiness_issues(&m, 1, Some(Duration::from_millis(200)), &[]).is_empty());
    }

    #[test]
    fn leader_without_quorum_ack_is_not_ready() {
        let m = metrics(1, Some(1), Some(10), Some(10));
        assert_eq!(
            readiness_issues(&m, 1, None, &[]),
            vec!["leader not yet acknowledged by a quorum".to_string()]
        );
        let stale = READINESS_MAX_QUORUM_ACK_AGE + Duration::from_secs(4);
        assert_eq!(
            readiness_issues(&m, 1, Some(stale), &[]),
            vec!["leader not acknowledged by a quorum for 10s".to_string()]
        );
    }

    #[test]
    fn single_voter_leader_is_ready_without_quorum_ack() {
        let m = metrics_with_voters(1, &[1], Some(1), Some(10), Some(10));
        assert!(readiness_issues(&m, 1, None, &[]).is_empty());
        let stale = READINESS_MAX_QUORUM_ACK_AGE * 10;
        assert!(readiness_issues(&m, 1, Some(stale), &[]).is_empty());
    }

    #[test]
    fn quarantined_partition_is_not_ready() {
        let m = metrics(2, Some(1), Some(10), Some(10));
        assert_eq!(
            readiness_issues(&m, 2, None, &["data".to_string(), "other".to_string()]),
            vec!["quarantined partitions: data, other".to_string()]
        );
    }

    #[test]
    fn stopped_core_is_not_an_issue() {
        // A stopped/fatal core is surfaced as an `Err` by
        // `Storage::readiness` (via `is_initialized`) and handled by the
        // liveness probe, not as a readiness issue.
        let mut m = metrics(2, Some(1), Some(10), Some(10));
        m.running_state = Err(openraft::errors::Fatal::Stopped);
        assert!(readiness_issues(&m, 2, None, &[]).is_empty());
    }
}
