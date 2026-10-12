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

//! Cluster health and growth invariants evaluated on every scrape cycle.
//!
//! Time is passed in as a `Duration` since the start of the run so the logic
//! stays deterministic and unit-testable.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use serde::Serialize;

use crate::prom::Scrape;

/// What was observed on one node during a scrape cycle.
#[derive(Clone, Debug)]
pub struct NodeObservation {
    /// `host:port` of the node's metrics endpoint.
    pub addr: String,
    /// `None` when the node could not be scraped.
    pub scrape: Option<Scrape>,
    /// Result of `GET /ready`; `None` when the request failed.
    pub ready: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct Thresholds {
    pub expected_voters: u64,
    /// A condition must hold this long before it is a violation. Absorbs
    /// elections and rolling restarts.
    pub grace: Duration,
    /// Learners may exist while a node joins, but not forever.
    pub learner_grace: Duration,
    pub max_applied_spread: u64,
    pub max_apply_lag: u64,
    pub max_replication_lag: u64,
    /// Ignore growth trends for this long after start.
    pub warmup: Duration,
    /// Window over which log growth is judged.
    pub growth_window: Duration,
    /// Allowed relative growth of the log size between the first and the
    /// last quarter of the window.
    pub max_log_growth_ratio: f64,
    /// Allowed `max/min` of `disk_space_bytes` across nodes.
    pub max_disk_spread_ratio: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Violation {
    pub at_secs: u64,
    pub check: &'static str,
    pub detail: String,
}

/// Cluster-wide totals exported as the soak controller's own metrics.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Summary {
    pub nodes: usize,
    pub nodes_scraped: usize,
    pub nodes_ready: usize,
    pub leaders: usize,
    pub voters: u64,
    pub learners: u64,
    pub applied_spread: u64,
    pub max_apply_lag: u64,
    pub max_replication_lag: u64,
    pub disk_bytes_total: f64,
    pub log_disk_bytes_total: f64,
    pub snapshot_bytes_total: f64,
    pub disk_spread_ratio: f64,
    pub quarantined_total: f64,
}

pub struct Evaluator {
    th: Thresholds,
    /// First time each condition was seen failing in a row.
    failing_since: HashMap<String, Duration>,
    last_gcm: HashMap<String, f64>,
    /// `(time, total log bytes)` samples inside the growth window.
    log_series: VecDeque<(Duration, f64)>,
}

impl Evaluator {
    pub fn new(th: Thresholds) -> Self {
        Self {
            th,
            failing_since: HashMap::new(),
            last_gcm: HashMap::new(),
            log_series: VecDeque::new(),
        }
    }

    /// Track `key`; returns true once `cond` has been failing for `grace`.
    fn persistent(&mut self, key: &str, failing: bool, now: Duration, grace: Duration) -> bool {
        if !failing {
            self.failing_since.remove(key);
            return false;
        }
        let since = *self.failing_since.entry(key.to_string()).or_insert(now);
        now.saturating_sub(since) >= grace
    }

    pub fn evaluate(
        &mut self,
        now: Duration,
        nodes: &[NodeObservation],
    ) -> (Summary, Vec<Violation>) {
        let mut out = Vec::new();
        let mut s = Summary {
            nodes: nodes.len(),
            ..Summary::default()
        };
        let at = now.as_secs();
        let mut v = |check: &'static str, detail: String| {
            out.push(Violation {
                at_secs: at,
                check,
                detail,
            })
        };
        let grace = self.th.grace;

        let mut applied = Vec::new();
        let mut disks = Vec::new();
        let mut voters_seen = Vec::new();
        let mut learners_seen = Vec::new();

        for n in nodes {
            let down = n.scrape.is_none();
            if self.persistent(&format!("scrape:{}", n.addr), down, now, grace) {
                v("scrape", format!("{} unreachable for {:?}", n.addr, grace));
            }
            let not_ready = n.ready != Some(true);
            if !down {
                s.nodes_scraped += 1;
            }
            if n.ready == Some(true) {
                s.nodes_ready += 1;
            }
            if self.persistent(&format!("ready:{}", n.addr), not_ready, now, grace) {
                v("ready", format!("{} not ready for {:?}", n.addr, grace));
            }
            let Some(m) = &n.scrape else { continue };

            if m.get("keystone_raft_is_leader") == Some(1.0) {
                s.leaders += 1;
            }
            if let Some(x) = m.get("keystone_raft_membership_voters") {
                voters_seen.push(x as u64);
            }
            if let Some(x) = m.get("keystone_raft_membership_learners") {
                learners_seen.push(x as u64);
            }
            if let Some(x) = m.get("keystone_raft_last_applied_index") {
                applied.push(x as u64);
            }
            s.max_apply_lag = s
                .max_apply_lag
                .max(m.get("keystone_raft_apply_lag").unwrap_or(0.0) as u64);
            s.max_replication_lag = s
                .max_replication_lag
                .max(m.get("keystone_raft_replication_lag").unwrap_or(0.0) as u64);
            s.log_disk_bytes_total += m.get("keystone_raft_log_disk_space_bytes").unwrap_or(0.0);
            s.snapshot_bytes_total += m.get("keystone_raft_snapshot_size_bytes").unwrap_or(0.0);
            let disk = m.get("keystone_raft_disk_space_bytes").unwrap_or(0.0);
            s.disk_bytes_total += disk;
            disks.push(disk);

            let q = m
                .get("keystone_raft_quarantined_partitions_count")
                .unwrap_or(0.0);
            s.quarantined_total += q;
            if q > 0.0 {
                v(
                    "quarantine",
                    format!("{} has {q} quarantined partitions", n.addr),
                );
            }
            if let Some(gcm) = m.get("keystone_raft_gcm_failures_total") {
                let prev = self.last_gcm.insert(n.addr.clone(), gcm);
                if prev.is_some_and(|p| gcm > p) {
                    v("gcm", format!("{} AES-GCM failures grew to {gcm}", n.addr));
                }
            }
        }

        // Voter/learner counts are cluster-wide; every node should agree.
        s.voters = voters_seen.iter().copied().max().unwrap_or(0);
        s.learners = learners_seen.iter().copied().max().unwrap_or(0);

        let scraped_all = s.nodes_scraped == s.nodes && s.nodes > 0;
        let leader_bad = scraped_all && s.leaders != 1;
        if self.persistent("leader", leader_bad, now, grace) {
            v("leader", format!("{} leaders (want exactly 1)", s.leaders));
        }
        let voters_bad = !voters_seen.is_empty() && s.voters != self.th.expected_voters;
        if self.persistent("voters", voters_bad, now, grace) {
            v(
                "voters",
                format!("{} voters (want {})", s.voters, self.th.expected_voters),
            );
        }
        let lg = self.th.learner_grace;
        if self.persistent("learners", s.learners > 0, now, lg) {
            v(
                "learners",
                format!("{} learners lingering > {:?}", s.learners, lg),
            );
        }

        if let (Some(max), Some(min)) = (applied.iter().max(), applied.iter().min()) {
            s.applied_spread = max - min;
        }
        let spread_bad = s.applied_spread > self.th.max_applied_spread;
        if self.persistent("applied_spread", spread_bad, now, grace) {
            v(
                "applied_spread",
                format!(
                    "last_applied spread {} > {}",
                    s.applied_spread, self.th.max_applied_spread
                ),
            );
        }
        if self.persistent(
            "apply_lag",
            s.max_apply_lag > self.th.max_apply_lag,
            now,
            grace,
        ) {
            v(
                "apply_lag",
                format!("apply lag {} > {}", s.max_apply_lag, self.th.max_apply_lag),
            );
        }
        let rep_bad = s.max_replication_lag > self.th.max_replication_lag;
        if self.persistent("replication_lag", rep_bad, now, grace) {
            v(
                "replication_lag",
                format!(
                    "replication lag {} > {}",
                    s.max_replication_lag, self.th.max_replication_lag
                ),
            );
        }

        // A node holding much more data than its peers hints at failed
        // compaction or divergence. Ignore tiny stores (< 1 MiB).
        if let (Some(max), Some(min)) = (
            disks.iter().copied().reduce(f64::max),
            disks.iter().copied().reduce(f64::min),
        ) && min >= 1_048_576.0
        {
            s.disk_spread_ratio = max / min;
        }
        let disk_bad = s.disk_spread_ratio > self.th.max_disk_spread_ratio;
        if self.persistent("disk_spread", disk_bad, now, grace) {
            v(
                "disk_spread",
                format!(
                    "disk usage spread {:.2}x > {:.2}x across nodes",
                    s.disk_spread_ratio, self.th.max_disk_spread_ratio
                ),
            );
        }

        // Log plateau: purge + snapshot must bound the log size.
        if scraped_all {
            self.log_series.push_back((now, s.log_disk_bytes_total));
        }
        while self
            .log_series
            .front()
            .is_some_and(|(t, _)| now.saturating_sub(*t) > self.th.growth_window)
        {
            self.log_series.pop_front();
        }
        if now >= self.th.warmup
            && let Some(ratio) = log_growth_ratio(&self.log_series, self.th.growth_window)
            && ratio > self.th.max_log_growth_ratio
        {
            v(
                "log_growth",
                format!(
                    "log size grew {:.0}% over {:?} (limit {:.0}%)",
                    ratio * 100.0,
                    self.th.growth_window,
                    self.th.max_log_growth_ratio * 100.0
                ),
            );
        }
        (s, out)
    }
}

/// Relative growth of the mean log size between the first and last quarter
/// of the window. `None` until the series spans (almost) the whole window.
fn log_growth_ratio(series: &VecDeque<(Duration, f64)>, window: Duration) -> Option<f64> {
    let (first_t, _) = series.front()?;
    let (last_t, _) = series.back()?;
    if last_t.saturating_sub(*first_t) < window.mul_f64(0.9) {
        return None;
    }
    let quarter = window / 4;
    let mean = |it: Vec<f64>| (!it.is_empty()).then(|| it.iter().sum::<f64>() / it.len() as f64);
    let head = mean(
        series
            .iter()
            .filter(|(t, _)| *t <= *first_t + quarter)
            .map(|(_, b)| *b)
            .collect(),
    )?;
    let tail = mean(
        series
            .iter()
            .filter(|(t, _)| *t + quarter >= *last_t)
            .map(|(_, b)| *b)
            .collect(),
    )?;
    (head > 0.0).then(|| (tail - head) / head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn th() -> Thresholds {
        Thresholds {
            expected_voters: 3,
            grace: Duration::from_secs(60),
            learner_grace: Duration::from_secs(600),
            max_applied_spread: 1000,
            max_apply_lag: 1000,
            max_replication_lag: 1000,
            warmup: Duration::from_secs(0),
            growth_window: Duration::from_secs(1000),
            max_log_growth_ratio: 0.5,
            max_disk_spread_ratio: 2.0,
        }
    }

    fn node(addr: &str, leader: bool, applied: f64, log: f64) -> NodeObservation {
        let mut s = Scrape::default();
        for (k, val) in [
            ("keystone_raft_is_leader", if leader { 1.0 } else { 0.0 }),
            ("keystone_raft_membership_voters", 3.0),
            ("keystone_raft_membership_learners", 0.0),
            ("keystone_raft_last_applied_index", applied),
            ("keystone_raft_log_disk_space_bytes", log),
            ("keystone_raft_disk_space_bytes", 10_000_000.0),
            ("keystone_raft_gcm_failures_total", 0.0),
        ] {
            s.values.insert(k.into(), val);
        }
        NodeObservation {
            addr: addr.into(),
            scrape: Some(s),
            ready: Some(true),
        }
    }

    fn healthy(log: f64) -> Vec<NodeObservation> {
        vec![
            node("a", true, 100.0, log),
            node("b", false, 100.0, log),
            node("c", false, 99.0, log),
        ]
    }

    #[test]
    fn healthy_cluster_has_no_violations() {
        let mut e = Evaluator::new(th());
        let (s, v) = e.evaluate(Duration::from_secs(10), &healthy(100.0));
        assert!(v.is_empty(), "{v:?}");
        assert_eq!((s.leaders, s.voters, s.applied_spread), (1, 3, 1));
    }

    #[test]
    fn missing_leader_is_tolerated_only_within_grace() {
        let mut e = Evaluator::new(th());
        let mut nodes = healthy(100.0);
        nodes[0] = node("a", false, 100.0, 100.0);
        assert!(e.evaluate(Duration::from_secs(0), &nodes).1.is_empty());
        assert!(e.evaluate(Duration::from_secs(30), &nodes).1.is_empty());
        let (_, v) = e.evaluate(Duration::from_secs(61), &nodes);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].check, "leader");
        // Recovery resets the timer.
        assert!(
            e.evaluate(Duration::from_secs(70), &healthy(100.0))
                .1
                .is_empty()
        );
        assert!(e.evaluate(Duration::from_secs(100), &nodes).1.is_empty());
    }

    #[test]
    fn unreachable_node_is_reported() {
        let mut e = Evaluator::new(th());
        let mut nodes = healthy(100.0);
        nodes[2].scrape = None;
        nodes[2].ready = None;
        e.evaluate(Duration::from_secs(0), &nodes);
        let (_, v) = e.evaluate(Duration::from_secs(61), &nodes);
        let checks: Vec<_> = v.iter().map(|x| x.check).collect();
        assert!(
            checks.contains(&"scrape") && checks.contains(&"ready"),
            "{checks:?}"
        );
    }

    #[test]
    fn gcm_failures_and_quarantine_are_immediate() {
        let mut e = Evaluator::new(th());
        e.evaluate(Duration::from_secs(0), &healthy(100.0));
        let mut nodes = healthy(100.0);
        if let Some(s) = nodes[1].scrape.as_mut() {
            s.values
                .insert("keystone_raft_gcm_failures_total".into(), 1.0);
            s.values
                .insert("keystone_raft_quarantined_partitions_count".into(), 2.0);
        }
        let (_, v) = e.evaluate(Duration::from_secs(5), &nodes);
        let checks: Vec<_> = v.iter().map(|x| x.check).collect();
        assert!(
            checks.contains(&"gcm") && checks.contains(&"quarantine"),
            "{checks:?}"
        );
    }

    #[test]
    fn unbounded_log_growth_is_flagged_but_plateau_is_not() {
        let mut e = Evaluator::new(th());
        let mut flagged = false;
        for i in 0..=100u64 {
            let (_, v) = e.evaluate(
                Duration::from_secs(i * 10),
                &healthy(100.0 + 10.0 * i as f64),
            );
            flagged |= v.iter().any(|x| x.check == "log_growth");
        }
        assert!(flagged);

        let mut e = Evaluator::new(th());
        for i in 0..=100u64 {
            let (_, v) = e.evaluate(Duration::from_secs(i * 10), &healthy(1000.0));
            assert!(v.is_empty(), "{v:?}");
        }
    }
}
