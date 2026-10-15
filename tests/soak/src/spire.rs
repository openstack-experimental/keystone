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

//! SPIRE agent restarts: delete the agent pod while keystone keeps running.
//!
//! Keystone gets its SVID from the SPIRE agent's Workload API socket and the
//! agent is a node-level DaemonSet, so it restarts independently of keystone
//! (node reboot, upgrade, crash). A power cycle once left keystone
//! crash-looping because the socket came up after it. Every
//! `SOAK_SPIRE_INTERVAL` the task deletes the agent pod and checks that
//!
//! - the agent is ready again within `SOAK_SPIRE_RECOVERY`
//!   (`spire_recovery`),
//! - no keystone container restarted because of it (`spire_keystone_restart`),
//! - writes through the cluster service keep being acknowledged, the longest
//!   stretch without one staying under `SOAK_SPIRE_MAX_WRITE_GAP`
//!   (`spire_write_gap`),
//! - the cluster is converged afterwards (also `spire_recovery`).
//!
//! The agent is shared infrastructure of the node, so the task needs RBAC to
//! delete pods in the SPIRE namespace and is off by default.

use std::time::Duration;

use anyhow::Result;
use serde::Serialize;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::canary::{ProbeWrite, Prober};
use crate::chaos::{Kube, POLL, sleep_until_deadline};
use crate::rollout::{Cluster, GapTracker, cluster_settled};
use crate::server::Shared;

/// Events kept for the report; older ones are dropped (the totals still
/// cover them).
pub const MAX_EVENTS: usize = 100;
/// Pause between two probe writes.
const PROBE_EVERY: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, Serialize)]
pub struct SpireFailure {
    /// `spire_recovery`, `spire_keystone_restart` or `spire_write_gap`.
    pub check: &'static str,
    pub detail: String,
}

/// One agent restart and what became of it.
#[derive(Clone, Debug, Serialize)]
pub struct SpireEvent {
    /// Monotonic number, stable when old records are dropped.
    pub seq: u64,
    pub pod: String,
    pub at_secs: u64,
    /// Seconds until the new agent pod was ready.
    pub agent_ready_secs: Option<u64>,
    /// Keystone container restarts since the agent was deleted.
    pub keystone_restarts: u64,
    /// Longest stretch without an acknowledged write.
    pub max_write_gap_secs: u64,
    pub failures: Vec<SpireFailure>,
    /// Settled: judged.
    pub done: bool,
}

/// Counters over the whole run.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SpireTotals {
    pub restarts: u64,
    pub failed: u64,
    pub max_agent_ready_secs: u64,
    pub keystone_restarts: u64,
}

pub struct SpireConfig {
    pub interval: Duration,
    pub namespace: String,
    /// Label selector of the agent pods.
    pub agent_selector: String,
    /// The agent must be ready and the cluster converged within this time.
    pub recovery_timeout: Duration,
    /// Longest allowed stretch without an acknowledged write.
    pub max_write_gap: Duration,
    /// Keystone pods are watched for restarts for this long after the agent
    /// is back, to catch a crash loop that starts late.
    pub watch: Duration,
    pub selector: String,
    pub expected_pods: usize,
    pub service: String,
    pub metrics_port: u16,
    /// `host:port` of the cluster service, where the probe writes go.
    pub write_node: String,
    /// Cluster service URL used to log in.
    pub host: String,
    pub start: Instant,
    pub state: Shared,
}

fn update_event(cfg: &SpireConfig, seq: u64, f: impl FnOnce(&mut SpireEvent)) {
    if let Ok(mut g) = cfg.state.write()
        && let Some(e) = g.spire.events.iter_mut().find(|e| e.seq == seq)
    {
        f(e);
    }
}

fn fail(cfg: &SpireConfig, seq: u64, check: &'static str, detail: String) {
    warn!(seq, check, %detail, "spire check failed");
    update_event(cfg, seq, |e| {
        e.failures.push(SpireFailure { check, detail })
    });
}

async fn settled(cfg: &SpireConfig, kube: &Kube, http: &reqwest::Client) -> bool {
    let cluster = Cluster {
        selector: &cfg.selector,
        expected: cfg.expected_pods,
        service: &cfg.service,
        metrics_port: cfg.metrics_port,
    };
    cluster_settled(&cfg.state, kube, http, &cluster, "spire").await
}

async fn keystone_restarts(kube: &Kube, selector: &str) -> Option<u64> {
    let pods = kube.pods(selector).await.ok()?;
    Some(pods.iter().map(|p| p.restarts()).sum())
}

pub async fn run(cfg: SpireConfig, deadline: Option<Instant>) -> Result<()> {
    let kube = Kube::in_cluster().await?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let mut prober = Prober::new(&cfg.host)?;
    info!(interval = ?cfg.interval, namespace = %cfg.namespace, "spire restarts enabled");
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
        let agents = match kube.pods_in(&cfg.namespace, &cfg.agent_selector).await {
            Ok(a) if !a.is_empty() => a,
            Ok(_) => {
                warn!(selector = %cfg.agent_selector, "spire: no agent pod found");
                continue;
            }
            Err(e) => {
                warn!(error = %format!("{e:#}"), "spire: cannot list agent pods");
                continue;
            }
        };
        let (Some(restarts_before), Ok(())) = (
            keystone_restarts(&kube, &cfg.selector).await,
            prober.login().await,
        ) else {
            continue;
        };
        let victim = &agents[usize::try_from(seq).unwrap_or(0) % agents.len()];
        let (name, old_uid) = (victim.metadata.name.clone(), victim.metadata.uid.clone());

        seq += 1;
        let started = Instant::now();
        if let Err(e) = kube.delete_in(&cfg.namespace, &name).await {
            warn!(pod = %name, error = %format!("{e:#}"), "spire: cannot delete the agent");
            seq -= 1;
            continue;
        }
        info!(pod = %name, seq, "spire: agent deleted");
        if let Ok(mut g) = cfg.state.write() {
            g.spire.active = true;
            g.spire.totals.restarts += 1;
            g.spire.events.push(SpireEvent {
                seq,
                pod: name.clone(),
                at_secs: cfg.start.elapsed().as_secs(),
                agent_ready_secs: None,
                keystone_restarts: 0,
                max_write_gap_secs: 0,
                failures: Vec::new(),
                done: false,
            });
            let extra = g.spire.events.len().saturating_sub(MAX_EVENTS);
            g.spire.events.drain(..extra);
        }

        let mut gap = GapTracker::new(started);
        let (mut agent_ready, mut watching_since): (Option<u64>, Option<Instant>) = (None, None);
        let mut converged = false;
        while started.elapsed() < cfg.recovery_timeout {
            if prober.write_via(&cfg.write_node).await == ProbeWrite::Accepted {
                gap.ok(Instant::now());
            }
            if agent_ready.is_none()
                && let Ok(a) = kube.pods_in(&cfg.namespace, &cfg.agent_selector).await
                && a.iter().any(|p| p.metadata.uid != old_uid && p.ready())
            {
                agent_ready = Some(started.elapsed().as_secs());
                watching_since = Some(Instant::now());
                info!(pod = %name, secs = started.elapsed().as_secs(), "spire: agent ready");
            }
            // Keep watching for a late crash loop, then wait for the cluster.
            if watching_since.is_some_and(|w| w.elapsed() >= cfg.watch) {
                converged = settled(&cfg, &kube, &http).await;
                if converged {
                    break;
                }
            }
            if !sleep_until_deadline(PROBE_EVERY, deadline).await {
                if let Ok(mut g) = cfg.state.write() {
                    g.spire.active = false;
                }
                return Ok(());
            }
        }
        gap.finish(Instant::now());

        let restarted = keystone_restarts(&kube, &cfg.selector)
            .await
            .map_or(0, |now| now.saturating_sub(restarts_before));
        if agent_ready.is_none() || !converged {
            fail(
                &cfg,
                seq,
                "spire_recovery",
                format!(
                    "{} within {}",
                    if agent_ready.is_none() {
                        "the agent was not ready again"
                    } else {
                        "the agent is back but the cluster did not converge"
                    },
                    humantime::format_duration(cfg.recovery_timeout)
                ),
            );
        }
        if restarted > 0 {
            fail(
                &cfg,
                seq,
                "spire_keystone_restart",
                format!("{restarted} keystone container restarts after the agent was deleted"),
            );
        }
        if gap.max > cfg.max_write_gap {
            fail(
                &cfg,
                seq,
                "spire_write_gap",
                format!(
                    "no write was acknowledged for {} (limit {})",
                    humantime::format_duration(Duration::from_secs(gap.max.as_secs())),
                    humantime::format_duration(cfg.max_write_gap)
                ),
            );
        }
        info!(
            seq,
            agent_ready_secs = ?agent_ready,
            restarted,
            max_write_gap_secs = gap.max.as_secs(),
            "spire: finished"
        );
        update_event(&cfg, seq, |e| {
            e.agent_ready_secs = agent_ready;
            e.keystone_restarts = restarted;
            e.max_write_gap_secs = gap.max.as_secs();
            e.done = true;
        });
        if let Ok(mut g) = cfg.state.write() {
            let failed = g
                .spire
                .events
                .iter()
                .find(|e| e.seq == seq)
                .is_some_and(|e| !e.failures.is_empty());
            g.spire.active = false;
            let t = &mut g.spire.totals;
            t.failed += u64::from(failed);
            t.keystone_restarts += restarted;
            if let Some(secs) = agent_ready {
                t.max_agent_ready_secs = t.max_agent_ready_secs.max(secs);
            }
        }
    }
}
