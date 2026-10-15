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

//! Rolling restarts: replace every Raft pod, one after another, under load.
//!
//! Every `SOAK_ROLLOUT_INTERVAL` the task rolls the StatefulSet the way
//! `kubectl rollout restart` does (it changes a pod template annotation) and
//! waits until every pod runs the new revision and is ready, then until the
//! cluster has converged: one leader that every node agrees on, no apply lag,
//! all voters present. While it waits it writes through the cluster service
//! every few seconds and tracks the longest stretch without an acknowledged
//! write. Writes the cluster acknowledged but lost, and data altered by the
//! restarts, are caught by the canary `integrity` check.
//!
//! The checks are `rollout_timeout` (not rolled out and converged within the
//! timeout) and `rollout_write_gap` (writes were unavailable for too long).
//! Pod kills and partitions wait while a rollout runs, and the rollout waits
//! for them to finish.

use std::time::Duration;

use anyhow::Result;
use serde::Serialize;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::canary::{ProbeWrite, Prober};
use crate::chaos::{Kube, POLL, all_ready, sleep_until_deadline};
use crate::partition::{converged, fetch_views};
use crate::server::Shared;

/// Events kept for the report; older ones are dropped (the totals still
/// cover them).
pub const MAX_EVENTS: usize = 100;
/// Pause between two probe writes.
const PROBE_EVERY: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, Serialize)]
pub struct RolloutFailure {
    /// `rollout_timeout` or `rollout_write_gap`.
    pub check: &'static str,
    pub detail: String,
}

/// One rolling restart and what became of it.
#[derive(Clone, Debug, Serialize)]
pub struct RolloutEvent {
    /// Monotonic number, stable when old records are dropped.
    pub seq: u64,
    pub at_secs: u64,
    /// Seconds until every pod ran the new revision and was ready.
    pub rolled_secs: Option<u64>,
    /// Seconds until the cluster converged afterwards.
    pub converged_secs: Option<u64>,
    /// Longest stretch without an acknowledged write.
    pub max_write_gap_secs: u64,
    pub probes: u64,
    pub failed_probes: u64,
    pub failures: Vec<RolloutFailure>,
    /// Settled: finished or timed out, and judged.
    pub done: bool,
}

/// Counters over the whole run.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RolloutTotals {
    pub rollouts: u64,
    pub failed: u64,
    pub last_converged_secs: u64,
    pub max_converged_secs: u64,
    pub max_write_gap_secs: u64,
}

pub struct RolloutConfig {
    pub interval: Duration,
    /// The rollout must finish and converge within this time.
    pub timeout: Duration,
    /// Longest allowed stretch without an acknowledged write.
    pub max_write_gap: Duration,
    pub statefulset: String,
    pub selector: String,
    pub expected_pods: usize,
    /// Headless service of the pods.
    pub service: String,
    pub metrics_port: u16,
    /// `host:port` of the cluster service, where the probe writes go.
    pub write_node: String,
    /// Cluster service URL used to log in.
    pub host: String,
    pub start: Instant,
    pub state: Shared,
}

/// Tracks the longest stretch without a successful write.
#[derive(Debug)]
pub struct GapTracker {
    last_ok: Instant,
    pub max: Duration,
}

impl GapTracker {
    pub fn new(now: Instant) -> Self {
        Self {
            last_ok: now,
            max: Duration::ZERO,
        }
    }

    /// A write was acknowledged at `now`.
    pub fn ok(&mut self, now: Instant) {
        self.max = self.max.max(now.saturating_duration_since(self.last_ok));
        self.last_ok = now;
    }

    /// The observation ended at `now`; a trailing stretch without a write
    /// counts as well.
    pub fn finish(&mut self, now: Instant) {
        self.max = self.max.max(now.saturating_duration_since(self.last_ok));
    }
}

fn update_event(cfg: &RolloutConfig, seq: u64, f: impl FnOnce(&mut RolloutEvent)) {
    if let Ok(mut g) = cfg.state.write()
        && let Some(e) = g.rollout.events.iter_mut().find(|e| e.seq == seq)
    {
        f(e);
    }
}

fn fail(cfg: &RolloutConfig, seq: u64, check: &'static str, detail: String) {
    warn!(seq, check, %detail, "rollout check failed");
    update_event(cfg, seq, |e| {
        e.failures.push(RolloutFailure { check, detail })
    });
}

/// Where the Raft pods are and how many there must be.
pub struct Cluster<'a> {
    pub selector: &'a str,
    pub expected: usize,
    /// Headless service of the pods.
    pub service: &'a str,
    pub metrics_port: u16,
}

/// The cluster is healthy and idle: no fault task other than `own` holds it
/// down, no pod kill is recovering, every pod is ready and the Raft group has
/// converged.
pub async fn cluster_settled(
    state: &Shared,
    kube: &Kube,
    http: &reqwest::Client,
    cluster: &Cluster<'_>,
    own: &str,
) -> bool {
    let busy = state.read().is_ok_and(|g| {
        g.disrupted_except(own)
            || g.chaos
                .events
                .last()
                .is_some_and(|e| e.recovery_secs.is_none() && !e.timed_out)
    });
    if busy {
        return false;
    }
    let Ok(pods) = kube.pods(cluster.selector).await else {
        return false;
    };
    if !all_ready(&pods, cluster.expected) {
        return false;
    }
    let names: Vec<String> = pods.iter().map(|p| p.metadata.name.clone()).collect();
    converged(
        &fetch_views(http, cluster.service, cluster.metrics_port, &names).await,
        cluster.expected,
    )
}

async fn settled(cfg: &RolloutConfig, kube: &Kube, http: &reqwest::Client) -> bool {
    let cluster = Cluster {
        selector: &cfg.selector,
        expected: cfg.expected_pods,
        service: &cfg.service,
        metrics_port: cfg.metrics_port,
    };
    cluster_settled(&cfg.state, kube, http, &cluster, "rollout").await
}

pub async fn run(cfg: RolloutConfig, deadline: Option<Instant>) -> Result<()> {
    let kube = Kube::in_cluster().await?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let mut prober = Prober::new(&cfg.host)?;
    info!(interval = ?cfg.interval, statefulset = %cfg.statefulset, "rollout enabled");
    let mut seq = 0u64;
    loop {
        if !sleep_until_deadline(cfg.interval, deadline).await {
            return Ok(());
        }
        while !settled(&cfg, &kube, &http).await {
            if !sleep_until_deadline(POLL, deadline).await {
                return Ok(());
            }
        }
        if let Err(e) = prober.login().await {
            warn!(error = %format!("{e:#}"), "rollout: cannot log in");
            continue;
        }

        seq += 1;
        let started = Instant::now();
        let stamp = chrono::Utc::now().to_rfc3339();
        if let Err(e) = kube.restart_statefulset(&cfg.statefulset, &stamp).await {
            warn!(error = %format!("{e:#}"), "rollout: cannot restart the StatefulSet");
            seq -= 1;
            continue;
        }
        info!(seq, statefulset = %cfg.statefulset, "rollout: restart started");
        if let Ok(mut g) = cfg.state.write() {
            g.rollout.active = true;
            g.rollout.totals.rollouts += 1;
            g.rollout.events.push(RolloutEvent {
                seq,
                at_secs: cfg.start.elapsed().as_secs(),
                rolled_secs: None,
                converged_secs: None,
                max_write_gap_secs: 0,
                probes: 0,
                failed_probes: 0,
                failures: Vec::new(),
                done: false,
            });
            let extra = g.rollout.events.len().saturating_sub(MAX_EVENTS);
            g.rollout.events.drain(..extra);
        }

        let mut gap = GapTracker::new(started);
        let (mut probes, mut failed_probes) = (0u64, 0u64);
        let (mut rolled, mut done) = (None, None);
        while started.elapsed() < cfg.timeout && done.is_none() {
            probes += 1;
            if prober.write_via(&cfg.write_node).await == ProbeWrite::Accepted {
                gap.ok(Instant::now());
            } else {
                failed_probes += 1;
            }
            if rolled.is_none()
                && let Ok(sts) = kube.statefulset(&cfg.statefulset).await
                && sts.rolled_out()
            {
                rolled = Some(started.elapsed().as_secs());
                info!(
                    seq,
                    secs = started.elapsed().as_secs(),
                    "rollout: all pods updated"
                );
            }
            if rolled.is_some() && settled(&cfg, &kube, &http).await {
                done = Some(started.elapsed().as_secs());
            }
            update_event(&cfg, seq, |e| {
                e.rolled_secs = rolled;
                e.probes = probes;
                e.failed_probes = failed_probes;
            });
            if done.is_none() && !sleep_until_deadline(PROBE_EVERY, deadline).await {
                if let Ok(mut g) = cfg.state.write() {
                    g.rollout.active = false;
                }
                return Ok(());
            }
        }
        gap.finish(Instant::now());

        if done.is_none() {
            fail(
                &cfg,
                seq,
                "rollout_timeout",
                format!(
                    "the rollout {} within {}",
                    if rolled.is_some() {
                        "finished but the cluster did not converge"
                    } else {
                        "did not finish"
                    },
                    humantime::format_duration(cfg.timeout)
                ),
            );
        }
        if gap.max > cfg.max_write_gap {
            fail(
                &cfg,
                seq,
                "rollout_write_gap",
                format!(
                    "no write was acknowledged for {} (limit {})",
                    humantime::format_duration(Duration::from_secs(gap.max.as_secs())),
                    humantime::format_duration(cfg.max_write_gap)
                ),
            );
        }
        info!(
            seq,
            converged_secs = ?done,
            max_write_gap_secs = gap.max.as_secs(),
            "rollout: finished"
        );
        update_event(&cfg, seq, |e| {
            e.converged_secs = done;
            e.max_write_gap_secs = gap.max.as_secs();
            e.done = true;
        });
        if let Ok(mut g) = cfg.state.write() {
            let failed = g
                .rollout
                .events
                .iter()
                .find(|e| e.seq == seq)
                .is_some_and(|e| !e.failures.is_empty());
            g.rollout.active = false;
            let t = &mut g.rollout.totals;
            t.failed += u64::from(failed);
            t.max_write_gap_secs = t.max_write_gap_secs.max(gap.max.as_secs());
            if let Some(secs) = done {
                t.last_converged_secs = secs;
                t.max_converged_secs = t.max_converged_secs.max(secs);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_the_longest_stretch_without_a_write() {
        let t0 = Instant::now();
        let at = |s| t0 + Duration::from_secs(s);
        let mut g = GapTracker::new(t0);
        g.ok(at(3));
        g.ok(at(6));
        g.ok(at(40));
        g.ok(at(43));
        assert_eq!(g.max, Duration::from_secs(34));
        // Nothing acknowledged at the end counts too.
        g.finish(at(100));
        assert_eq!(g.max, Duration::from_secs(57));
    }

    #[test]
    fn no_write_at_all_is_one_gap() {
        let t0 = Instant::now();
        let mut g = GapTracker::new(t0);
        g.finish(t0 + Duration::from_secs(90));
        assert_eq!(g.max, Duration::from_secs(90));
    }
}
