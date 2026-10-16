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

//! Membership churn: replace a node that lost its storage, and grow and
//! shrink the cluster. Both need the storage operator, see `operator.rs`.
//!
//! Every `SOAK_MEMBERSHIP_INTERVAL` the task runs one of two scenarios, in
//! turn, while the load and the canaries keep running:
//!
//! - **wipe**: delete the volume and the pod of a follower voter. It comes
//!   back with empty storage and must rejoin as a learner, never as a voter
//!   (a voter with an empty log could help elect a leader that lacks
//!   acknowledged entries). Once it caught up the operator promotes it and
//!   the cluster must converge with all voters again.
//! - **scale**: scale the StatefulSet from 3 to 5. The new nodes must join as
//!   learners and catch up. Then they are removed from the membership, the
//!   StatefulSet is scaled back and their volumes are deleted, which leaves
//!   exactly the original voters.
//!
//! Checks: `membership_wiped_voter`, `membership_rejoin`,
//! `membership_promote`, `membership_scale_voters`, `membership_remove`,
//! `membership_leftover`, `membership_timeout`, `membership_operator` and
//! `membership_write_gap`. Data that the rebuilt or new nodes lack shows up as
//! a canary `integrity` or `read_after_write` failure.

use std::time::Duration;

use anyhow::Result;
use reqwest::Method;
use serde::Serialize;
use serde_json::json;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::canary::{ProbeWrite, Prober};
use crate::chaos::{Kube, all_ready, sleep_until_deadline};
use crate::operator::Operator;
use crate::partition::{converged, fetch_views};
use crate::rollout::{Cluster, GapTracker, cluster_settled};
use crate::server::Shared;

/// Events kept for the report; older ones are dropped (the totals still
/// cover them).
pub const MAX_EVENTS: usize = 100;
/// Pause between two probe writes and condition checks.
const PROBE_EVERY: Duration = Duration::from_secs(3);
/// Longest a single operator command may take.
const COMMAND: Duration = Duration::from_secs(90);

#[derive(Clone, Debug, Serialize)]
pub struct MembershipFailure {
    pub check: &'static str,
    pub detail: String,
}

/// One churn scenario and what became of it.
#[derive(Clone, Debug, Serialize)]
pub struct MembershipEvent {
    /// Monotonic number, stable when old records are dropped.
    pub seq: u64,
    /// `wipe` or `scale`.
    pub kind: &'static str,
    /// The node that was wiped; empty for `scale`.
    pub node: String,
    pub at_secs: u64,
    pub took_secs: Option<u64>,
    /// Longest stretch without an acknowledged write.
    pub max_write_gap_secs: u64,
    pub failures: Vec<MembershipFailure>,
    /// Settled: finished and judged.
    pub done: bool,
}

/// Counters over the whole run.
#[derive(Clone, Debug, Default, Serialize)]
pub struct MembershipTotals {
    pub runs: u64,
    pub wipes: u64,
    pub scales: u64,
    pub failed: u64,
    pub max_took_secs: u64,
}

pub struct MembershipConfig {
    pub interval: Duration,
    /// Every step must finish within this time.
    pub step_timeout: Duration,
    /// Longest allowed stretch without an acknowledged write.
    pub max_write_gap: Duration,
    pub statefulset: String,
    pub operator_deployment: String,
    /// Prefix of the volume claims, `<prefix>-<pod>`.
    pub claim_prefix: String,
    /// Replicas the `scale` scenario grows to.
    pub scale_to: usize,
    pub selector: String,
    /// Pod that is never wiped, see `SOAK_CONTROL_POD`; empty for none.
    pub control_pod: String,
    /// Voters (and pods) of the normal cluster.
    pub expected_pods: usize,
    pub service: String,
    pub metrics_port: u16,
    /// `host:port` of the cluster service, where the probe writes go.
    pub write_node: String,
    pub host: String,
    pub start: Instant,
    pub state: Shared,
}

/// Pod ordinal, which is also the Raft node id.
pub fn ordinal(pod: &str) -> Option<u64> {
    pod.rsplit('-').next()?.parse().ok()
}

fn update_event(cfg: &MembershipConfig, seq: u64, f: impl FnOnce(&mut MembershipEvent)) {
    if let Ok(mut g) = cfg.state.write()
        && let Some(e) = g.membership.events.iter_mut().find(|e| e.seq == seq)
    {
        f(e);
    }
}

fn fail(cfg: &MembershipConfig, seq: u64, check: &'static str, detail: String) {
    warn!(seq, check, %detail, "membership check failed");
    update_event(cfg, seq, |e| {
        e.failures.push(MembershipFailure { check, detail })
    });
}

/// Probe writes through the cluster service while a step waits.
struct Writes {
    prober: Prober,
    node: String,
    gap: GapTracker,
}

impl Writes {
    async fn tick(&mut self) {
        if self.prober.write_via(&self.node).await == ProbeWrite::Accepted {
            self.gap.ok(Instant::now());
        }
    }
}

/// How a wait ended.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Waited {
    Met,
    TimedOut,
    /// The soak is shutting down.
    Shutdown,
}

/// Probe-write and check `cond` every few seconds until it holds, the
/// timeout passes or the soak shuts down. `cond` is inlined, so it may
/// `.await`; a closure would not be `Send` enough for `tokio::spawn`.
macro_rules! wait_until {
    ($writes:expr, $timeout:expr, $deadline:expr, $cond:expr) => {{
        let began = Instant::now();
        loop {
            $writes.tick().await;
            if $cond {
                break Waited::Met;
            }
            if began.elapsed() >= $timeout {
                break Waited::TimedOut;
            }
            if !sleep_until_deadline(PROBE_EVERY, $deadline).await {
                break Waited::Shutdown;
            }
        }
    }};
}

struct Ctx<'a> {
    cfg: &'a MembershipConfig,
    kube: &'a Kube,
    http: &'a reqwest::Client,
    deadline: Option<Instant>,
    seq: u64,
}

impl Ctx<'_> {
    fn operator(&self) -> Operator<'_> {
        Operator {
            kube: self.kube,
            deployment: &self.cfg.operator_deployment,
        }
    }

    async fn settled(&self, expected: usize) -> bool {
        let cluster = Cluster {
            selector: &self.cfg.selector,
            expected,
            service: &self.cfg.service,
            metrics_port: self.cfg.metrics_port,
        };
        cluster_settled(
            &self.cfg.state,
            self.kube,
            self.http,
            &cluster,
            "membership",
        )
        .await
    }

    /// Exactly `n` pods exist and are all ready.
    async fn pods_ready(&self, n: usize) -> bool {
        self.kube
            .pods(&self.cfg.selector)
            .await
            .is_ok_and(|p| p.len() == n && all_ready(&p, n))
    }

    fn fail(&self, check: &'static str, detail: String) {
        fail(self.cfg, self.seq, check, detail);
    }

    /// Record a timed out step; `false` when the soak is shutting down.
    fn timed_out(&self, w: Waited, step: &str) -> Option<bool> {
        match w {
            Waited::Met => Some(true),
            Waited::TimedOut => {
                self.fail(
                    "membership_timeout",
                    format!(
                        "{step} did not happen within {}",
                        humantime::format_duration(self.cfg.step_timeout)
                    ),
                );
                Some(false)
            }
            Waited::Shutdown => None,
        }
    }

    async fn pvc_path(&self, pod: &str) -> String {
        format!(
            "/api/v1/namespaces/{}/persistentvolumeclaims/{}-{pod}",
            self.kube.namespace(),
            self.cfg.claim_prefix
        )
    }

    async fn set_replicas(&self, n: usize) -> Result<()> {
        let path = format!(
            "/apis/apps/v1/namespaces/{}/statefulsets/{}",
            self.kube.namespace(),
            self.cfg.statefulset
        );
        self.kube
            .json(
                Method::PATCH,
                &path,
                Some(&json!({"spec": {"replicas": n}})),
            )
            .await?;
        Ok(())
    }
}

/// `None` when the soak shut down in the middle.
async fn wipe(ctx: &Ctx<'_>, writes: &mut Writes) -> Option<()> {
    let cfg = ctx.cfg;
    let names = ctx
        .kube
        .pods(&cfg.selector)
        .await
        .map(|p| {
            p.iter()
                .map(|x| (x.metadata.name.clone(), x.metadata.uid.clone()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let pods: Vec<String> = names.iter().map(|(n, _)| n.clone()).collect();
    let seen = fetch_views(ctx.http, &cfg.service, cfg.metrics_port, &pods).await;
    let followers: Vec<&str> = seen
        .iter()
        .filter(|v| !v.is_leader && v.pod != cfg.control_pod)
        .map(|v| v.pod.as_str())
        .collect();
    let Some(victim) = followers
        .get(usize::try_from(ctx.seq / 2).unwrap_or(0) % followers.len().max(1))
        .copied()
    else {
        ctx.fail("membership_operator", "no follower to wipe".to_string());
        return Some(());
    };
    let Some(id) = ordinal(victim) else {
        ctx.fail(
            "membership_operator",
            format!("cannot derive a node id from {victim}"),
        );
        return Some(());
    };
    let old_uid = names
        .iter()
        .find(|(n, _)| n == victim)
        .map(|(_, u)| u.clone())
        .unwrap_or_default();
    update_event(cfg, ctx.seq, |e| e.node = victim.to_string());

    // The volume is only released once the pod is gone, so delete both, the
    // volume first. If the volume survives the node is not wiped.
    let pvc = ctx.pvc_path(victim).await;
    if let Err(e) = ctx.kube.json(Method::DELETE, &pvc, None).await {
        ctx.fail(
            "membership_operator",
            format!("cannot delete the volume of {victim}: {e:#}"),
        );
        return Some(());
    }
    if let Err(e) = ctx.kube.delete(victim).await {
        ctx.fail(
            "membership_operator",
            format!("cannot delete {victim}: {e:#}"),
        );
        return Some(());
    }
    info!(
        pod = victim,
        seq = ctx.seq,
        "membership: volume and pod deleted"
    );

    let back = wait_until!(writes, cfg.step_timeout, ctx.deadline, {
        ctx.kube.pods(&cfg.selector).await.is_ok_and(|p| {
            all_ready(&p, cfg.expected_pods)
                && p.iter()
                    .any(|x| x.metadata.name == victim && x.metadata.uid != old_uid)
        })
    });
    if !ctx.timed_out(back, &format!("{victim} coming back"))? {
        return Some(());
    }

    let op = ctx.operator();
    let peers = match op.peers(COMMAND).await {
        Ok(p) => p,
        Err(e) => {
            ctx.fail("membership_operator", format!("{e:#}"));
            return Some(());
        }
    };
    match peers.iter().find(|p| p.node_id == id) {
        None => {
            ctx.fail(
                "membership_rejoin",
                format!("{victim} is not a member after losing its storage"),
            );
            return Some(());
        }
        Some(p) if p.voter => {
            ctx.fail(
                "membership_wiped_voter",
                format!("{victim} is a voter again although it lost its storage"),
            );
            return Some(());
        }
        Some(_) => info!(pod = victim, "membership: rejoined as a learner"),
    }

    let caught_up = wait_until!(writes, cfg.step_timeout, ctx.deadline, {
        let views = fetch_views(ctx.http, &cfg.service, cfg.metrics_port, &pods).await;
        converged(&views, cfg.expected_pods)
    });
    if !ctx.timed_out(caught_up, &format!("{victim} catching up"))? {
        return Some(());
    }

    let id_arg = id.to_string();
    match op.run(&["promote", &id_arg], COMMAND).await {
        Ok(out) if out.success => info!(pod = victim, "membership: promoted"),
        Ok(out) => {
            ctx.fail(
                "membership_promote",
                format!("promoting {victim} failed: {}", out.log.trim()),
            );
            return Some(());
        }
        Err(e) => {
            ctx.fail("membership_operator", format!("{e:#}"));
            return Some(());
        }
    }
    let voter = wait_until!(writes, cfg.step_timeout, ctx.deadline, {
        op.peers(COMMAND)
            .await
            .is_ok_and(|p| p.iter().filter(|x| x.voter).count() == cfg.expected_pods)
    });
    if !ctx.timed_out(voter, "all voters being back")? {
        return Some(());
    }
    let done = wait_until!(writes, cfg.step_timeout, ctx.deadline, {
        ctx.settled(cfg.expected_pods).await
    });
    ctx.timed_out(done, "the cluster converging")?;
    Some(())
}

async fn scale_up(ctx: &Ctx<'_>, writes: &mut Writes) -> Option<()> {
    let cfg = ctx.cfg;
    let target = cfg.scale_to;
    if let Err(e) = ctx.set_replicas(target).await {
        ctx.fail("membership_operator", format!("cannot scale up: {e:#}"));
        return Some(());
    }
    info!(seq = ctx.seq, target, "membership: scaled up");
    let up = wait_until!(writes, cfg.step_timeout, ctx.deadline, {
        ctx.pods_ready(target).await
    });
    if !ctx.timed_out(up, "the new pods being ready")? {
        return Some(());
    }

    let op = ctx.operator();
    let joined = wait_until!(writes, cfg.step_timeout, ctx.deadline, {
        op.peers(COMMAND).await.is_ok_and(|p| p.len() == target)
    });
    if !ctx.timed_out(joined, "the new nodes joining")? {
        return Some(());
    }
    let peers = op.peers(COMMAND).await.unwrap_or_default();
    let voters = peers.iter().filter(|p| p.voter).count();
    if voters != cfg.expected_pods {
        ctx.fail(
            "membership_scale_voters",
            format!(
                "{voters} voters after scaling to {target}, expected {} (new nodes must join as learners)",
                cfg.expected_pods
            ),
        );
        return Some(());
    }
    let caught = wait_until!(writes, cfg.step_timeout, ctx.deadline, {
        ctx.settled(target).await
    });
    if !ctx.timed_out(caught, "the new nodes catching up")? {
        return Some(());
    }

    for id in (cfg.expected_pods..target).rev() {
        let arg = id.to_string();
        match op.run(&["remove-peer", &arg], COMMAND).await {
            // An older `remove-peer` answers "not a voter; nothing to do" for a learner.
            Ok(out) if out.success && out.log.contains("not a voter") => {
                ctx.fail(
                    "membership_remove",
                    format!(
                        "remove-peer cannot remove learner {id}: {}",
                        out.log.trim().lines().next().unwrap_or_default()
                    ),
                );
                return Some(());
            }
            Ok(out) if out.success => info!(node = id, "membership: removed"),
            Ok(out) => {
                ctx.fail(
                    "membership_remove",
                    format!("removing node {id} failed: {}", out.log.trim()),
                );
                return Some(());
            }
            Err(e) => {
                ctx.fail("membership_operator", format!("{e:#}"));
                return Some(());
            }
        }
    }
    Some(())
}

/// Bring the StatefulSet back to its size, drop the volumes of the extra
/// pods and check that only the original voters are left. Runs after every
/// scale scenario, also a failed one.
async fn scale_down(ctx: &Ctx<'_>, writes: &mut Writes) -> Option<()> {
    let cfg = ctx.cfg;
    if let Err(e) = ctx.set_replicas(cfg.expected_pods).await {
        ctx.fail("membership_operator", format!("cannot scale down: {e:#}"));
        return Some(());
    }
    let down = wait_until!(writes, cfg.step_timeout, ctx.deadline, {
        ctx.pods_ready(cfg.expected_pods).await
    });
    if !ctx.timed_out(down, "the extra pods going away")? {
        return Some(());
    }
    // A node that keeps its state never joins again; a stale volume would
    // break the next scale-up.
    for id in cfg.expected_pods..cfg.scale_to {
        let pod = format!("{}-{id}", cfg.statefulset);
        let _ = ctx
            .kube
            .json(Method::DELETE, &ctx.pvc_path(&pod).await, None)
            .await;
    }
    match ctx.operator().peers(COMMAND).await {
        Ok(p) if p.len() == cfg.expected_pods && p.iter().all(|x| x.voter) => {}
        Ok(p) => ctx.fail(
            "membership_leftover",
            format!(
                "{} members after scaling back, {} voters; expected {} voters only",
                p.len(),
                p.iter().filter(|x| x.voter).count(),
                cfg.expected_pods
            ),
        ),
        Err(e) => ctx.fail("membership_operator", format!("{e:#}")),
    }
    let done = wait_until!(writes, cfg.step_timeout, ctx.deadline, {
        ctx.settled(cfg.expected_pods).await
    });
    ctx.timed_out(done, "the cluster converging")?;
    Some(())
}

/// `new_until` bounds starting a new fault, `deadline` the whole run: a fault that
/// began before `new_until` is followed to the end.
pub async fn run(
    cfg: MembershipConfig,
    deadline: Option<Instant>,
    new_until: Option<Instant>,
) -> Result<()> {
    let kube = Kube::in_cluster().await?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let mut writes = Writes {
        prober: Prober::new(&cfg.host)?,
        node: cfg.write_node.clone(),
        gap: GapTracker::new(Instant::now()),
    };
    info!(interval = ?cfg.interval, "membership churn enabled");
    let mut seq = 0u64;
    loop {
        if !sleep_until_deadline(cfg.interval, new_until).await {
            return Ok(());
        }
        let ctx = Ctx {
            cfg: &cfg,
            kube: &kube,
            http: &http,
            deadline,
            seq,
        };
        while !ctx.settled(cfg.expected_pods).await {
            if !sleep_until_deadline(Duration::from_secs(5), new_until).await {
                return Ok(());
            }
        }
        if let Err(e) = writes.prober.login().await {
            warn!(error = %format!("{e:#}"), "membership: cannot log in");
            continue;
        }

        seq += 1;
        let kind = if seq % 2 == 1 { "wipe" } else { "scale" };
        let started = Instant::now();
        info!(seq, kind, "membership: scenario started");
        if let Ok(mut g) = cfg.state.write() {
            g.membership.active = true;
            g.membership.totals.runs += 1;
            if kind == "wipe" {
                g.membership.totals.wipes += 1;
            } else {
                g.membership.totals.scales += 1;
            }
            g.membership.events.push(MembershipEvent {
                seq,
                kind,
                node: String::new(),
                at_secs: cfg.start.elapsed().as_secs(),
                took_secs: None,
                max_write_gap_secs: 0,
                failures: Vec::new(),
                done: false,
            });
            let extra = g.membership.events.len().saturating_sub(MAX_EVENTS);
            g.membership.events.drain(..extra);
        }
        writes.gap = GapTracker::new(Instant::now());
        let ctx = Ctx {
            cfg: &cfg,
            kube: &kube,
            http: &http,
            deadline,
            seq,
        };
        let finished = if kind == "wipe" {
            wipe(&ctx, &mut writes).await
        } else {
            // The scale-down runs also after a failed scale-up.
            let up = scale_up(&ctx, &mut writes).await;
            match up {
                Some(()) => scale_down(&ctx, &mut writes).await,
                None => None,
            }
        };
        if finished.is_none() {
            if let Ok(mut g) = cfg.state.write() {
                g.membership.active = false;
            }
            return Ok(());
        }
        writes.gap.finish(Instant::now());
        if writes.gap.max > cfg.max_write_gap {
            fail(
                &cfg,
                seq,
                "membership_write_gap",
                format!(
                    "no write was acknowledged for {} (limit {})",
                    humantime::format_duration(Duration::from_secs(writes.gap.max.as_secs())),
                    humantime::format_duration(cfg.max_write_gap)
                ),
            );
        }
        let took = started.elapsed().as_secs();
        info!(seq, kind, took, "membership: scenario finished");
        update_event(&cfg, seq, |e| {
            e.took_secs = Some(took);
            e.max_write_gap_secs = writes.gap.max.as_secs();
            e.done = true;
        });
        if let Ok(mut g) = cfg.state.write() {
            let failed = g
                .membership
                .events
                .iter()
                .find(|e| e.seq == seq)
                .is_some_and(|e| !e.failures.is_empty());
            g.membership.active = false;
            let t = &mut g.membership.totals;
            t.failed += u64::from(failed);
            t.max_took_secs = t.max_took_secs.max(took);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_is_the_pod_ordinal() {
        assert_eq!(ordinal("keystone-rs-2"), Some(2));
        assert_eq!(ordinal("keystone-rs-12"), Some(12));
        assert_eq!(ordinal("keystone-rs"), None);
    }
}
