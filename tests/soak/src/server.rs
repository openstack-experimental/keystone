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

//! HTTP endpoints of the controller: `/metrics` for Prometheus, `/verdict`
//! (JSON), `/report` (Markdown or JSON) and `/healthz`.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;

use crate::canary::{CanaryFailure, CanaryTotals};
use crate::chaos::{ChaosEvent, ChaosTotals};
use crate::invariants::{Summary, Violation};
use crate::partition::{PartitionEvent, PartitionTotals};
use crate::report::{self, Growth, LoadTotals, PhaseRecord};

#[derive(Clone, Debug, Default, Serialize)]
pub struct Verdict {
    pub healthy: bool,
    pub finished: bool,
    pub elapsed_secs: u64,
    pub cycles: u64,
    pub violations_total: u64,
    pub summary: Summary,
    /// The first 100 violations, oldest first.
    pub violations: Vec<Violation>,
    pub growth: Growth,
    pub load_totals: LoadTotals,
    /// Executed load phases, oldest first (capped, see `report::MAX_PHASES`).
    pub phases: Vec<PhaseRecord>,
    pub chaos: Chaos,
    pub partition: Partition,
    pub canary: Canary,
}

/// Results of the canary task.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Canary {
    pub totals: CanaryTotals,
    /// Recent failures, oldest first (capped, see `canary::MAX_FAILURES`).
    pub failures: Vec<CanaryFailure>,
}

/// Pod kills of the chaos task.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Chaos {
    pub totals: ChaosTotals,
    /// Recent kills, oldest first (capped, see `chaos::MAX_EVENTS`).
    pub events: Vec<ChaosEvent>,
}

/// Network partitions of the partition task.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Partition {
    /// A node is cut off right now; chaos kills wait.
    pub active: bool,
    pub totals: PartitionTotals,
    /// Recent partitions, oldest first (capped, see `partition::MAX_EVENTS`).
    pub events: Vec<PartitionEvent>,
}

pub type Shared = Arc<RwLock<Verdict>>;

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/verdict", get(verdict))
        .route("/report", get(report))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

async fn verdict(State(s): State<Shared>) -> impl IntoResponse {
    let mut v = s.read().map(|g| g.clone()).unwrap_or_default();
    // Series and per-phase records belong to `/report`.
    v.phases.clear();
    v.growth.points.clear();
    v.chaos.events.clear();
    v.partition.events.clear();
    let code = if v.healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(v))
}

/// Full report: Markdown by default, the whole state as JSON with
/// `?format=json`. Answers 503 once unhealthy, so `curl -f` and `soak report`
/// can use the status as a pass/fail result.
async fn report(State(s): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Response {
    let v = s.read().map(|g| g.clone()).unwrap_or_default();
    let code = if v.healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    if q.get("format").is_some_and(|f| f == "json") {
        (code, Json(v)).into_response()
    } else {
        (
            code,
            [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
            report::render_markdown(&v),
        )
            .into_response()
    }
}

async fn metrics(State(s): State<Shared>) -> String {
    render(&s.read().map(|g| g.clone()).unwrap_or_default())
}

pub fn render(v: &Verdict) -> String {
    let mut out = String::new();
    let mut g = |name: &str, help: &str, val: f64| {
        let _ = writeln!(
            out,
            "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {val}"
        );
    };
    let sm = &v.summary;
    g(
        "soak_healthy",
        "1 while no invariant has been violated",
        f64::from(u8::from(v.healthy)),
    );
    g(
        "soak_finished",
        "1 once the configured duration elapsed",
        f64::from(u8::from(v.finished)),
    );
    g(
        "soak_elapsed_seconds",
        "Seconds since the soak run started",
        v.elapsed_secs as f64,
    );
    g(
        "soak_cycles_total",
        "Completed evaluation cycles",
        v.cycles as f64,
    );
    g(
        "soak_violations_total",
        "Invariant violations observed",
        v.violations_total as f64,
    );
    g("soak_nodes", "Cluster nodes discovered", sm.nodes as f64);
    g(
        "soak_nodes_scraped",
        "Nodes whose metrics were scraped",
        sm.nodes_scraped as f64,
    );
    g(
        "soak_nodes_ready",
        "Nodes answering /ready with 200",
        sm.nodes_ready as f64,
    );
    g(
        "soak_leaders",
        "Nodes reporting themselves as leader",
        sm.leaders as f64,
    );
    g(
        "soak_voters",
        "Voters in the Raft membership",
        sm.voters as f64,
    );
    g(
        "soak_learners",
        "Learners in the Raft membership",
        sm.learners as f64,
    );
    g(
        "soak_applied_index_spread",
        "Max-min last_applied_index across nodes",
        sm.applied_spread as f64,
    );
    g(
        "soak_apply_lag_max",
        "Max apply lag across nodes",
        sm.max_apply_lag as f64,
    );
    g(
        "soak_replication_lag_max",
        "Max replication lag across peers",
        sm.max_replication_lag as f64,
    );
    g(
        "soak_disk_bytes_total",
        "Sum of disk_space_bytes over nodes",
        sm.disk_bytes_total,
    );
    g(
        "soak_log_disk_bytes_total",
        "Sum of log_disk_space_bytes over nodes",
        sm.log_disk_bytes_total,
    );
    g(
        "soak_snapshot_bytes_total",
        "Sum of snapshot_size_bytes over nodes",
        sm.snapshot_bytes_total,
    );
    g(
        "soak_disk_spread_ratio",
        "max/min disk_space_bytes across nodes",
        sm.disk_spread_ratio,
    );
    g(
        "soak_applied_index_max",
        "Highest applied Raft index (log entries so far)",
        sm.applied_index_max as f64,
    );
    g(
        "soak_disk_bytes_per_entry",
        "Average per-node disk usage per applied Raft entry",
        sm.bytes_per_entry,
    );
    let k = &v.canary.totals;
    g(
        "soak_canary_writes_total",
        "Canary records written through the API",
        k.writes as f64,
    );
    g(
        "soak_canary_reads_total",
        "Canary reads answered by a node",
        k.reads as f64,
    );
    g(
        "soak_canary_read_errors_total",
        "Canary reads that failed at the transport or with 5xx",
        k.read_errors as f64,
    );
    g(
        "soak_canary_stale_reads_total",
        "Canary reads that missed an acknowledged write",
        k.stale_reads as f64,
    );
    g(
        "soak_canary_mismatches_total",
        "Canary reads that returned altered data",
        k.mismatches as f64,
    );
    let t = &v.load_totals;
    g(
        "soak_load_phases_total",
        "Completed load phases",
        t.phases as f64,
    );
    g(
        "soak_load_requests_total",
        "Requests sent by the load generator",
        t.requests as f64,
    );
    g(
        "soak_load_failed_total",
        "Failed requests (excluding expected negatives and throttling)",
        t.failed as f64,
    );
    g(
        "soak_load_throttled_total",
        "Requests answered with 429",
        t.throttled as f64,
    );
    let c = &v.chaos.totals;
    g(
        "soak_chaos_kills_total",
        "Raft pods deleted by the chaos task",
        c.kills as f64,
    );
    g(
        "soak_chaos_recovered_total",
        "Deleted pods that came back ready in time",
        c.recovered as f64,
    );
    g(
        "soak_chaos_timed_out_total",
        "Deleted pods that did not come back in time",
        c.timed_out as f64,
    );
    g(
        "soak_chaos_last_recovery_seconds",
        "Time the last deleted pod needed to become ready again",
        c.last_recovery_secs as f64,
    );
    g(
        "soak_chaos_max_recovery_seconds",
        "Longest recovery after a pod deletion",
        c.max_recovery_secs as f64,
    );
    let p = &v.partition.totals;
    g(
        "soak_partition_total",
        "Nodes isolated by the partition task",
        p.partitions as f64,
    );
    g(
        "soak_partition_ineffective_total",
        "Partitions the nodes did not notice, so they were not judged",
        p.ineffective as f64,
    );
    g(
        "soak_partition_failed_total",
        "Partitions that broke an invariant",
        p.failed as f64,
    );
    g(
        "soak_partition_last_heal_seconds",
        "Time the cluster needed to converge after the last partition",
        p.last_heal_secs as f64,
    );
    g(
        "soak_partition_max_heal_seconds",
        "Longest convergence after a partition",
        p.max_heal_secs as f64,
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_health_gauge() {
        let text = render(&Verdict {
            healthy: true,
            ..Verdict::default()
        });
        assert!(text.contains("soak_healthy 1\n"));
        assert!(text.contains("# TYPE soak_leaders gauge"));
    }
}
