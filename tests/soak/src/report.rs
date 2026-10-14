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

//! Data collected for the on-demand report (`GET /report`, `soak report`) and
//! its Markdown rendering.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::server::Verdict;

/// Phase records kept for the report; older ones are dropped (the totals in
/// [`LoadTotals`] still cover them).
pub const MAX_PHASES: usize = 1000;
/// Points kept in the growth series before it is thinned out.
const MAX_SERIES: usize = 512;
/// Rows shown in the Markdown growth and phase tables.
const TABLE_ROWS: usize = 12;

/// Totals of one `load_test` run, as written to `LOADTEST_SUMMARY_FILE`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct LoadSummary {
    pub duration_secs: u64,
    pub maximum_users: u64,
    pub requests: u64,
    pub failed: u64,
    pub throttled: u64,
    pub transport_errors: u64,
    pub status_codes: BTreeMap<u16, u64>,
    pub latency_ms: Latency,
    pub failing_endpoints: Vec<Endpoint>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Latency {
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub max: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Endpoint {
    pub name: String,
    pub requests: u64,
    pub failed: u64,
}

/// One executed load phase.
#[derive(Clone, Debug, Serialize)]
pub struct PhaseRecord {
    /// Monotonic phase number, stable when old records are dropped.
    pub seq: u64,
    pub kind: String,
    pub users: usize,
    pub start_secs: u64,
    pub length_secs: u64,
    /// `None` for idle phases and when the load generator left no summary.
    pub summary: Option<LoadSummary>,
}

/// Load totals over the whole run.
#[derive(Clone, Debug, Default, Serialize)]
pub struct LoadTotals {
    pub phases: u64,
    pub requests: u64,
    pub failed: u64,
    pub throttled: u64,
    pub transport_errors: u64,
}

impl LoadTotals {
    pub fn add(&mut self, s: &LoadSummary) {
        self.phases += 1;
        self.requests += s.requests;
        self.failed += s.failed;
        self.throttled += s.throttled;
        self.transport_errors += s.transport_errors;
    }
}

/// Cluster-wide storage sizes at one point in time.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Sample {
    pub at_secs: u64,
    pub disk_bytes: f64,
    pub log_bytes: f64,
    pub snapshot_bytes: f64,
}

/// Storage growth over the run, thinned to at most [`MAX_SERIES`] points.
#[derive(Clone, Debug, Serialize)]
pub struct Growth {
    pub points: Vec<Sample>,
    pub log_bytes_min: f64,
    pub log_bytes_max: f64,
    pub disk_bytes_max: f64,
    #[serde(skip)]
    stride: u64,
    #[serde(skip)]
    seen: u64,
}

impl Default for Growth {
    fn default() -> Self {
        Self {
            points: Vec::new(),
            log_bytes_min: f64::MAX,
            log_bytes_max: 0.0,
            disk_bytes_max: 0.0,
            stride: 1,
            seen: 0,
        }
    }
}

impl Growth {
    pub fn record(&mut self, s: Sample) {
        self.log_bytes_min = self.log_bytes_min.min(s.log_bytes);
        self.log_bytes_max = self.log_bytes_max.max(s.log_bytes);
        self.disk_bytes_max = self.disk_bytes_max.max(s.disk_bytes);
        if self.seen.is_multiple_of(self.stride) {
            self.points.push(s);
            if self.points.len() > MAX_SERIES {
                let thinned = self.points.iter().step_by(2).copied().collect();
                self.points = thinned;
                self.stride *= 2;
            }
        }
        self.seen += 1;
    }
}

fn mib(bytes: f64) -> String {
    format!("{:.1}", bytes / 1_048_576.0)
}

fn hms(secs: u64) -> String {
    format!("{}h{:02}m{:02}s", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// `n` evenly spaced items of `items`, always including the first and last.
fn spread<T>(items: &[T], n: usize) -> Vec<&T> {
    if items.len() <= n || n < 2 {
        return items.iter().collect();
    }
    (0..n)
        .map(|i| &items[i * (items.len() - 1) / (n - 1)])
        .collect()
}

pub fn render_markdown(v: &Verdict) -> String {
    let mut o = String::new();
    let sm = &v.summary;
    let state = match (v.healthy, v.finished) {
        (false, _) => "UNHEALTHY",
        (true, true) => "PASSED",
        (true, false) => "HEALTHY (running)",
    };
    let _ = writeln!(o, "# Soak report\n");
    let _ = writeln!(
        o,
        "- status: **{state}**\n- elapsed: {} ({} cycles)\n- violations: {}",
        hms(v.elapsed_secs),
        v.cycles,
        v.violations_total
    );

    let _ = writeln!(o, "\n## Cluster\n");
    let _ = writeln!(
        o,
        "- nodes: {} ({} scraped, {} ready), leaders: {}, voters: {}, learners: {}\n\
         - applied index spread: {}, max apply lag: {}, max replication lag: {}\n\
         - quarantined partitions: {}, disk spread ratio: {:.2}",
        sm.nodes,
        sm.nodes_scraped,
        sm.nodes_ready,
        sm.leaders,
        sm.voters,
        sm.learners,
        sm.applied_spread,
        sm.max_apply_lag,
        sm.max_replication_lag,
        sm.quarantined_total,
        sm.disk_spread_ratio
    );

    if !v.violations.is_empty() {
        let _ = writeln!(o, "\n## Violations\n");
        for x in &v.violations {
            let _ = writeln!(o, "- {} `{}`: {}", hms(x.at_secs), x.check, x.detail);
        }
        if v.violations_total as usize > v.violations.len() {
            let _ = writeln!(
                o,
                "- ... {} more not shown",
                v.violations_total as usize - v.violations.len()
            );
        }
    }

    let _ = writeln!(o, "\n## Storage (MiB, summed over nodes)\n");
    match (v.growth.points.first(), v.growth.points.last()) {
        (Some(first), Some(last)) => {
            let _ = writeln!(
                o,
                "| elapsed | disk | raft log | snapshots |\n|---|---|---|---|"
            );
            for p in spread(&v.growth.points, TABLE_ROWS) {
                let _ = writeln!(
                    o,
                    "| {} | {} | {} | {} |",
                    hms(p.at_secs),
                    mib(p.disk_bytes),
                    mib(p.log_bytes),
                    mib(p.snapshot_bytes)
                );
            }
            let ratio = if first.log_bytes > 0.0 {
                last.log_bytes / first.log_bytes
            } else {
                0.0
            };
            let _ = writeln!(
                o,
                "\nraft log: first {} last {} min {} max {} (last/first {:.2}); disk max {}",
                mib(first.log_bytes),
                mib(last.log_bytes),
                mib(v.growth.log_bytes_min),
                mib(v.growth.log_bytes_max),
                ratio,
                mib(v.growth.disk_bytes_max)
            );
        }
        _ => {
            let _ = writeln!(o, "no samples yet");
        }
    }

    let t = &v.load_totals;
    let _ = writeln!(o, "\n## Load\n");
    let _ = writeln!(
        o,
        "{} load phases: {} requests, {} failed, {} throttled (429), {} transport errors",
        t.phases, t.requests, t.failed, t.throttled, t.transport_errors
    );
    let loaded: Vec<&PhaseRecord> = v.phases.iter().filter(|p| p.summary.is_some()).collect();
    if !loaded.is_empty() {
        let _ = writeln!(
            o,
            "\n| # | kind | users | start | requests | failed | 429 | p50 ms | p95 ms | max ms |\n\
             |---|---|---|---|---|---|---|---|---|---|"
        );
        // The most recent phases, the interesting ones for a running soak.
        let tail = &loaded[loaded.len().saturating_sub(TABLE_ROWS)..];
        for p in tail {
            if let Some(s) = &p.summary {
                let _ = writeln!(
                    o,
                    "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                    p.seq,
                    p.kind,
                    p.users,
                    hms(p.start_secs),
                    s.requests,
                    s.failed,
                    s.throttled,
                    s.latency_ms.p50,
                    s.latency_ms.p95,
                    s.latency_ms.max
                );
            }
        }
    }

    let mut failing: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for e in loaded
        .iter()
        .filter_map(|p| p.summary.as_ref())
        .flat_map(|s| &s.failing_endpoints)
    {
        let x = failing.entry(e.name.as_str()).or_default();
        x.0 += e.requests;
        x.1 += e.failed;
    }
    if !failing.is_empty() {
        let mut rows: Vec<_> = failing.into_iter().collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.1.1));
        let _ = writeln!(o, "\nFailing endpoints (retained phases):\n");
        for (name, (req, failed)) in rows.into_iter().take(10) {
            let _ = writeln!(o, "- {name}: {failed} of {req} failed");
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_series_is_bounded() {
        let mut g = Growth::default();
        for i in 0..5000 {
            g.record(Sample {
                at_secs: i,
                log_bytes: i as f64,
                ..Sample::default()
            });
        }
        assert!(g.points.len() <= MAX_SERIES);
        assert_eq!(g.points.first().map(|p| p.at_secs), Some(0));
        assert_eq!(g.log_bytes_max, 4999.0);
        assert_eq!(g.log_bytes_min, 0.0);
    }

    #[test]
    fn spread_keeps_ends() {
        let v: Vec<u32> = (0..100).collect();
        let s = spread(&v, 5);
        assert_eq!(s.len(), 5);
        assert_eq!((*s[0], *s[4]), (0, 99));
        assert_eq!(spread(&v[..3], 5).len(), 3);
    }

    #[test]
    fn renders_empty_verdict() {
        let text = render_markdown(&Verdict::default());
        assert!(text.contains("UNHEALTHY"));
        assert!(text.contains("no samples yet"));
    }
}
