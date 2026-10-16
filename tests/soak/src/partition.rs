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

//! Network partitions: cut one Raft node off from its peers for a while.
//!
//! A `NetworkPolicy` on the victim pod blocks TCP port 8300 (Raft and write
//! forwarding) in both directions and leaves every other port alone, so the
//! pod stays alive, ready for probes and reachable by this controller. The
//! victim alternates between the current leader and a follower. While the
//! partition holds the task checks that
//!
//! - the majority side keeps (or regains) a leader and accepts writes within
//!   the election timeout (`partition_availability`),
//! - the isolated node does **not** acknowledge a write, which would be a
//!   split brain (`partition_split_brain`); this is only judged once the
//!   partition is confirmed effective from the nodes' own view of the
//!   leader, otherwise the event is marked ineffective and not judged,
//! - after the policy is removed the cluster converges again: one leader that
//!   every node agrees on, no apply lag (`partition_recovery`).
//!
//! Data loss or divergence caused by a partition is caught by the canary
//! integrity check.

use std::time::Duration;

use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::time::Instant;
use tracing::{info, warn};

use crate::canary::{ProbeWrite, Prober};
use crate::chaos::{Kube, POLL, all_ready, sleep_until_deadline};
use crate::server::Shared;

/// Events kept for the report; older ones are dropped (the totals still
/// cover them).
pub const MAX_EVENTS: usize = 200;
const POLICY: &str = "soak-partition";
const MANAGED_BY: &str = "app.kubernetes.io/managed-by=keystone-soak";
/// Raft and write forwarding port of the nodes.
const RAFT_PORT: u16 = 8300;
/// Writes sent to the isolated node per partition.
const MAX_PROBES: usize = 2;

#[derive(Clone, Debug, Serialize)]
pub struct PartitionFailure {
    /// `partition_availability`, `partition_split_brain` or
    /// `partition_recovery`.
    pub check: &'static str,
    pub detail: String,
}

/// One partition and what became of it.
#[derive(Clone, Debug, Serialize)]
pub struct PartitionEvent {
    /// Monotonic number, stable when old records are dropped.
    pub seq: u64,
    pub pod: String,
    /// `leader` or `follower`.
    pub role: &'static str,
    pub at_secs: u64,
    /// The nodes' own view of the leader changed, so the cut took effect.
    pub effective: bool,
    /// Seconds from removing the policy until the cluster converged.
    pub heal_secs: Option<u64>,
    pub failures: Vec<PartitionFailure>,
    /// Settled: healed and judged.
    pub done: bool,
}

/// Counters over the whole run.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PartitionTotals {
    pub partitions: u64,
    pub ineffective: u64,
    pub failed: u64,
    pub last_heal_secs: u64,
    pub max_heal_secs: u64,
}

pub struct PartitionConfig {
    pub interval: Duration,
    /// How long the victim stays cut off.
    pub duration: Duration,
    /// The majority must lead and accept writes within this time.
    pub election_timeout: Duration,
    /// The cluster must converge within this time after healing.
    pub recovery_timeout: Duration,
    pub selector: String,
    pub expected_pods: usize,
    /// Headless service of the pods.
    pub service: String,
    pub metrics_port: u16,
    pub api_port: u16,
    /// Cluster service used to log in.
    pub host: String,
    pub start: Instant,
    pub state: Shared,
}

/// What one node reports about the Raft group.
#[derive(Clone, Debug, PartialEq)]
pub struct NodeView {
    pub pod: String,
    pub is_leader: bool,
    /// Leader as seen by this node, `None` when unknown.
    pub leader_id: Option<i64>,
    pub apply_lag: f64,
}

fn gauge(text: &str, name: &str) -> Option<f64> {
    text.lines()
        .find_map(|l| l.strip_prefix(name)?.trim().parse().ok())
}

/// Parse a node's `/metrics` output. `None` when the Raft gauges are absent.
pub fn parse_view(pod: &str, text: &str) -> Option<NodeView> {
    let leader = gauge(text, "keystone_raft_current_leader_id ")?;
    Some(NodeView {
        pod: pod.to_string(),
        is_leader: gauge(text, "keystone_raft_is_leader ")? >= 1.0,
        // Truncation is intended: node ids are small integers.
        leader_id: (leader >= 0.0).then_some(leader as i64),
        apply_lag: gauge(text, "keystone_raft_apply_lag ").unwrap_or(0.0),
    })
}

/// The Raft view of each of `pods` that answers on `service`.
pub async fn fetch_views(
    http: &reqwest::Client,
    service: &str,
    port: u16,
    pods: &[String],
) -> Vec<NodeView> {
    let mut out = Vec::new();
    for pod in pods {
        let url = format!("http://{pod}.{service}:{port}/metrics");
        let Ok(resp) = http.get(url).send().await else {
            continue;
        };
        if let Ok(text) = resp.text().await
            && let Some(v) = parse_view(pod, &text)
        {
            out.push(v);
        }
    }
    out
}

async fn views(http: &reqwest::Client, cfg: &PartitionConfig, pods: &[String]) -> Vec<NodeView> {
    fetch_views(http, &cfg.service, cfg.metrics_port, pods).await
}

/// The cluster has settled: every node answers, exactly one claims to lead,
/// they all agree on who it is and nothing is waiting to be applied.
pub fn converged(views: &[NodeView], expected: usize) -> bool {
    let leaders: Vec<&NodeView> = views.iter().filter(|v| v.is_leader).collect();
    if views.len() < expected || leaders.len() != 1 {
        return false;
    }
    let ids: Vec<Option<i64>> = views.iter().map(|v| v.leader_id).collect();
    ids[0].is_some() && ids.iter().all(|i| *i == ids[0]) && views.iter().all(|v| v.apply_lag <= 0.0)
}

/// The nodes' own view shows the victim is cut off.
///
/// A leader victim is effectively cut off once a node on the majority side
/// leads, a follower once it lost sight of the leader.
pub fn partition_effective(role: &str, victim: &str, views: &[NodeView]) -> bool {
    match role {
        "leader" => views.iter().any(|v| v.pod != victim && v.is_leader),
        _ => views
            .iter()
            .any(|v| v.pod == victim && v.leader_id.is_none()),
    }
}

/// The policy that blocks the Raft port of `pod` in both directions.
pub fn policy(pod: &str) -> Value {
    // NetworkPolicy can only allow, so allow every other port with ranges.
    let tcp = |from: u16, to: u16| json!({"protocol": "TCP", "port": from, "endPort": to});
    let ports = json!([
        tcp(1, RAFT_PORT - 1),
        tcp(RAFT_PORT + 1, 65535),
        {"protocol": "UDP", "port": 1, "endPort": 65535},
    ]);
    json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": POLICY,
            "labels": {"app.kubernetes.io/managed-by": "keystone-soak"},
        },
        "spec": {
            "podSelector": {"matchLabels": {"statefulset.kubernetes.io/pod-name": pod}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{"ports": ports}],
            "egress": [{"ports": ports}],
        },
    })
}

fn update_event(cfg: &PartitionConfig, seq: u64, f: impl FnOnce(&mut PartitionEvent)) {
    if let Ok(mut g) = cfg.state.write()
        && let Some(e) = g.partition.events.iter_mut().find(|e| e.seq == seq)
    {
        f(e);
    }
}

fn fail(cfg: &PartitionConfig, seq: u64, check: &'static str, detail: String) {
    warn!(seq, check, %detail, "partition check failed");
    update_event(cfg, seq, |e| {
        e.failures.push(PartitionFailure { check, detail })
    });
}

/// Write through the first of `pods` that accepts it.
async fn write_through_any(prober: &mut Prober, cfg: &PartitionConfig, pods: &[&str]) -> bool {
    for pod in pods {
        let node = format!("{pod}.{}:{}", cfg.service, cfg.api_port);
        if prober.write_via(&node).await == ProbeWrite::Accepted {
            return true;
        }
    }
    false
}

/// The node being cut off.
struct Cut<'a> {
    seq: u64,
    victim: &'a str,
    role: &'static str,
    /// Every pod of the cluster.
    pods: &'a [String],
}

/// Hold the partition and judge what the nodes do meanwhile.
async fn hold(
    cfg: &PartitionConfig,
    http: &reqwest::Client,
    prober: &mut Prober,
    cut: &Cut<'_>,
    deadline: Option<Instant>,
) -> bool {
    let Cut {
        seq,
        victim,
        role,
        pods,
    } = *cut;
    let began = Instant::now();
    let others: Vec<&str> = pods
        .iter()
        .map(String::as_str)
        .filter(|p| *p != victim)
        .collect();
    let (mut majority_ok, mut effective) = (false, false);
    let mut probes = 0;
    while began.elapsed() < cfg.duration {
        if !sleep_until_deadline(POLL, deadline).await {
            return false;
        }
        let seen = views(http, cfg, pods).await;
        if !effective && partition_effective(role, victim, &seen) {
            effective = true;
            update_event(cfg, seq, |e| e.effective = true);
            info!(pod = %victim, seq, "partition: cut confirmed by the nodes");
        }
        if !majority_ok {
            majority_ok = write_through_any(prober, cfg, &others).await;
        }
        if effective && probes < MAX_PROBES {
            probes += 1;
            let node = format!("{victim}.{}:{}", cfg.service, cfg.api_port);
            if let ProbeWrite::Accepted = prober.write_via(&node).await {
                fail(
                    cfg,
                    seq,
                    "partition_split_brain",
                    format!("isolated {role} {victim} acknowledged a write"),
                );
                probes = MAX_PROBES;
            }
        }
        if !majority_ok && began.elapsed() >= cfg.election_timeout {
            fail(
                cfg,
                seq,
                "partition_availability",
                format!(
                    "the other nodes accepted no write within {} of isolating {role} {victim}",
                    humantime::format_duration(cfg.election_timeout)
                ),
            );
            // Judged once.
            majority_ok = true;
        }
    }
    true
}

/// Wait until the cluster converged; `None` when it did not in time.
async fn wait_converged(
    cfg: &PartitionConfig,
    http: &reqwest::Client,
    kube: &Kube,
    deadline: Option<Instant>,
) -> Option<Option<u64>> {
    let healed = Instant::now();
    while healed.elapsed() < cfg.recovery_timeout {
        if let Ok(pods) = kube.pods(&cfg.selector).await
            && all_ready(&pods, cfg.expected_pods)
        {
            let names: Vec<String> = pods.iter().map(|p| p.metadata.name.clone()).collect();
            if converged(&views(http, cfg, &names).await, cfg.expected_pods) {
                return Some(Some(healed.elapsed().as_secs()));
            }
        }
        if !sleep_until_deadline(POLL, deadline).await {
            return None;
        }
    }
    Some(None)
}

/// `new_until` bounds starting a new fault, `deadline` the whole run: a fault that
/// began before `new_until` is followed to the end.
pub async fn run(
    cfg: PartitionConfig,
    deadline: Option<Instant>,
    new_until: Option<Instant>,
) -> Result<()> {
    let kube = Kube::in_cluster().await?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let mut prober = Prober::new(&cfg.host)?;
    // A crashed run may have left a partition behind.
    if let Err(e) = kube.delete_policies(MANAGED_BY).await {
        warn!(error = %format!("{e:#}"), "partition: cannot remove leftover policies");
    }
    info!(interval = ?cfg.interval, hold = ?cfg.duration, "partition enabled");
    let mut seq = 0u64;
    loop {
        if !sleep_until_deadline(cfg.interval, new_until).await {
            return Ok(());
        }

        // Only cut a healthy, settled cluster, not one still recovering from
        // a pod kill.
        let (pods, seen) = loop {
            let rolling = cfg
                .state
                .read()
                .is_ok_and(|g| g.rollout.active || g.spire.active);
            let killing = rolling
                || cfg.state.read().is_ok_and(|g| {
                    g.chaos
                        .events
                        .last()
                        .is_some_and(|e| e.recovery_secs.is_none() && !e.timed_out)
                });
            if !killing
                && let Ok(p) = kube.pods(&cfg.selector).await
                && all_ready(&p, cfg.expected_pods)
            {
                let names: Vec<String> = p.iter().map(|x| x.metadata.name.clone()).collect();
                let seen = views(&http, &cfg, &names).await;
                if converged(&seen, cfg.expected_pods) {
                    break (names, seen);
                }
            }
            if !sleep_until_deadline(POLL, new_until).await {
                return Ok(());
            }
        };
        // Alternate between the leader and a follower.
        let role = if seq.is_multiple_of(2) {
            "leader"
        } else {
            "follower"
        };
        let want_leader = role == "leader";
        let pick = |leader: bool| seen.iter().filter(move |v| v.is_leader == leader);
        let Some(victim) = pick(want_leader)
            .nth(usize::try_from(seq / 2).unwrap_or(0) % pick(want_leader).count().max(1))
            .map(|v| v.pod.clone())
        else {
            continue;
        };

        // Log in before the cut: the login may land on the victim.
        if let Err(e) = prober.login().await {
            warn!(error = %format!("{e:#}"), "partition: cannot log in");
            continue;
        }

        seq += 1;
        if let Err(e) = kube.create_policy(&policy(&victim)).await {
            warn!(pod = %victim, error = %format!("{e:#}"), "partition: cannot create the policy");
            seq -= 1;
            continue;
        }
        info!(pod = %victim, seq, role, "partition: node isolated");
        if let Ok(mut g) = cfg.state.write() {
            g.partition.active = true;
            g.partition.totals.partitions += 1;
            g.partition.events.push(PartitionEvent {
                seq,
                pod: victim.clone(),
                role,
                at_secs: cfg.start.elapsed().as_secs(),
                effective: false,
                heal_secs: None,
                failures: Vec::new(),
                done: false,
            });
            let extra = g.partition.events.len().saturating_sub(MAX_EVENTS);
            g.partition.events.drain(..extra);
        }

        let cut = Cut {
            seq,
            victim: &victim,
            role,
            pods: &pods,
        };
        let completed = hold(&cfg, &http, &mut prober, &cut, deadline).await;
        // Always lift the cut, also on shutdown.
        let mut lifted = false;
        for _ in 0..3 {
            match kube.delete_policy(POLICY).await {
                Ok(()) => {
                    lifted = true;
                    break;
                }
                Err(e) => warn!(error = %format!("{e:#}"), "partition: cannot remove the policy"),
            }
            tokio::time::sleep(POLL).await;
        }
        if !completed {
            return Ok(());
        }
        if !lifted {
            fail(
                &cfg,
                seq,
                "partition_recovery",
                format!("the policy isolating {victim} could not be removed"),
            );
        }
        info!(pod = %victim, seq, "partition: healed");

        let Some(outcome) = wait_converged(&cfg, &http, &kube, deadline).await else {
            return Ok(());
        };
        if let Ok(mut g) = cfg.state.write() {
            g.partition.active = false;
        }
        match outcome {
            Some(secs) => info!(pod = %victim, secs, "partition: cluster converged"),
            None => fail(
                &cfg,
                seq,
                "partition_recovery",
                format!(
                    "the cluster did not converge within {} of healing {victim}",
                    humantime::format_duration(cfg.recovery_timeout)
                ),
            ),
        }

        let mut ineffective = false;
        update_event(&cfg, seq, |e| {
            e.heal_secs = outcome;
            e.done = true;
            ineffective = !e.effective;
        });
        if let Ok(mut g) = cfg.state.write() {
            let ev = g.partition.events.iter().find(|e| e.seq == seq).cloned();
            let t = &mut g.partition.totals;
            if ineffective {
                t.ineffective += 1;
            }
            if ev.is_some_and(|e| !e.failures.is_empty()) {
                t.failed += 1;
            }
            if let Some(secs) = outcome {
                t.last_heal_secs = secs;
                t.max_heal_secs = t.max_heal_secs.max(secs);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(pod: &str, leader: bool, leader_id: Option<i64>, lag: f64) -> NodeView {
        NodeView {
            pod: pod.into(),
            is_leader: leader,
            leader_id,
            apply_lag: lag,
        }
    }

    #[test]
    fn parses_metrics() {
        let text = "# TYPE x gauge\nkeystone_raft_apply_lag 3\nkeystone_raft_current_leader_id 2\n\
                    keystone_raft_is_leader 1\nkeystone_raft_is_leader_total 9\n";
        let v = parse_view("ks-1", text).expect("view");
        assert_eq!(v, node("ks-1", true, Some(2), 3.0));
        let unknown = "keystone_raft_current_leader_id -1\nkeystone_raft_is_leader 0\n";
        assert_eq!(parse_view("ks-1", unknown).map(|v| v.leader_id), Some(None));
        assert!(parse_view("ks-1", "nothing here").is_none());
    }

    #[test]
    fn converged_needs_one_agreed_leader_and_no_lag() {
        let ok = vec![
            node("a", true, Some(1), 0.0),
            node("b", false, Some(1), 0.0),
            node("c", false, Some(1), 0.0),
        ];
        assert!(converged(&ok, 3));
        assert!(!converged(&ok[..2], 3));
        let mut lag = ok.clone();
        lag[2].apply_lag = 4.0;
        assert!(!converged(&lag, 3));
        let mut disagree = ok.clone();
        disagree[2].leader_id = Some(2);
        assert!(!converged(&disagree, 3));
        let mut two = ok.clone();
        two[1].is_leader = true;
        assert!(!converged(&two, 3));
        let mut none = ok;
        none[0].is_leader = false;
        assert!(!converged(&none, 3));
    }

    #[test]
    fn detects_a_cut_from_the_nodes_view() {
        // The old leader still believes it leads, another node took over.
        let split = vec![
            node("a", true, Some(1), 0.0),
            node("b", true, Some(2), 0.0),
            node("c", false, Some(2), 0.0),
        ];
        assert!(partition_effective("leader", "a", &split));
        let calm = vec![
            node("a", true, Some(1), 0.0),
            node("b", false, Some(1), 0.0),
        ];
        assert!(!partition_effective("leader", "a", &calm));
        // A follower that lost the leader is cut, one that sees it is not.
        let lost = vec![node("a", true, Some(1), 0.0), node("b", false, None, 0.0)];
        assert!(partition_effective("follower", "b", &lost));
        assert!(!partition_effective("follower", "b", &calm));
    }

    #[test]
    fn policy_blocks_only_the_raft_port() {
        let p = policy("ks-1");
        assert_eq!(
            p["spec"]["podSelector"]["matchLabels"]["statefulset.kubernetes.io/pod-name"],
            "ks-1"
        );
        let tcp: Vec<(u64, u64)> = p["spec"]["egress"][0]["ports"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|x| x["protocol"] == "TCP")
                    .filter_map(|x| Some((x["port"].as_u64()?, x["endPort"].as_u64()?)))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(tcp, vec![(1, 8299), (8301, 65535)]);
        assert_eq!(
            p["spec"]["ingress"],
            json!([{"ports": p["spec"]["egress"][0]["ports"]}])
        );
    }
}
