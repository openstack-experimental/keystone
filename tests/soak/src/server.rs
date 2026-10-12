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
//! (JSON) and `/healthz`.

use std::fmt::Write as _;
use std::sync::{Arc, RwLock};

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use serde::Serialize;

use crate::invariants::{Summary, Violation};

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
}

pub type Shared = Arc<RwLock<Verdict>>;

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/verdict", get(verdict))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

async fn verdict(State(s): State<Shared>) -> impl IntoResponse {
    let v = s.read().map(|g| g.clone()).unwrap_or_default();
    let code = if v.healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(v))
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
