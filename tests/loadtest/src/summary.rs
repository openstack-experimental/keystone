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

//! Compact machine-readable run summary.
//!
//! When `LOADTEST_SUMMARY_FILE` is set, `main` writes a small JSON document
//! with the totals of the run to that path. The soak controller
//! (`tests/soak`) reads it after every load phase to judge the error rate and
//! to include per-phase numbers in its report, instead of scraping goose's
//! console output or depending on the layout of goose's own JSON report.
//!
//! `failed` follows goose semantics: expected negative responses and
//! tolerated throttling are marked successful by the transactions and do not
//! count. Status code `0` is a transport error (connect failure or timeout).

use std::collections::BTreeMap;

use goose::goose::GooseMethod;
use goose::metrics::GooseMetrics;
use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub duration_secs: usize,
    pub maximum_users: usize,
    pub requests: usize,
    pub failed: usize,
    /// Requests answered with 429 (server-side throttling).
    pub throttled: usize,
    /// Requests that never got a response (status code 0).
    pub transport_errors: usize,
    pub status_codes: BTreeMap<u16, usize>,
    pub latency_ms: Latency,
    /// Latency per kind of request: `read` (GET/HEAD), `auth` (token
    /// issuing, dominated by password hashing) and `write` (the rest).
    pub latency_by_class_ms: BTreeMap<String, Latency>,
    /// Endpoints with at least one failed request, worst first.
    pub failing_endpoints: Vec<Endpoint>,
}

#[derive(Debug, Default, Serialize)]
pub struct Latency {
    pub requests: usize,
    pub p50: usize,
    pub p95: usize,
    pub p99: usize,
    pub max: usize,
}

#[derive(Debug, Serialize)]
pub struct Endpoint {
    pub name: String,
    pub requests: usize,
    pub failed: usize,
}

/// Value at quantile `q` (0..1) of a response time histogram.
fn percentile(times: &BTreeMap<usize, usize>, total: usize, q: f64) -> usize {
    if total == 0 {
        return 0;
    }
    let target = ((total as f64) * q).ceil() as usize;
    let mut seen = 0;
    for (ms, count) in times {
        seen += count;
        if seen >= target {
            return *ms;
        }
    }
    times.keys().next_back().copied().unwrap_or(0)
}

/// `read`, `auth` or `write`.
fn class(method: &GooseMethod, name: &str) -> &'static str {
    match method {
        GooseMethod::Get | GooseMethod::Head => "read",
        GooseMethod::Post if name.contains("/auth/tokens") => "auth",
        _ => "write",
    }
}

fn latency(times: &BTreeMap<usize, usize>, max: usize) -> Latency {
    let counted: usize = times.values().sum();
    Latency {
        requests: counted,
        p50: percentile(times, counted, 0.50),
        p95: percentile(times, counted, 0.95),
        p99: percentile(times, counted, 0.99),
        max,
    }
}

pub fn summarize(metrics: &GooseMetrics) -> Summary {
    let mut s = Summary {
        duration_secs: metrics.duration,
        maximum_users: metrics.maximum_users,
        ..Summary::default()
    };
    let mut times: BTreeMap<usize, usize> = BTreeMap::new();
    let mut by_class: BTreeMap<&'static str, (BTreeMap<usize, usize>, usize)> = BTreeMap::new();
    for (name, agg) in &metrics.requests {
        let total = agg.success_count + agg.fail_count;
        s.requests += total;
        s.failed += agg.fail_count;
        for (code, n) in &agg.status_code_counts {
            *s.status_codes.entry(*code).or_default() += n;
        }
        let (class_times, class_max) = by_class.entry(class(&agg.method, name)).or_default();
        *class_max = (*class_max).max(agg.raw_data.maximum_time);
        for (ms, n) in &agg.raw_data.times {
            *times.entry(*ms).or_default() += n;
            *class_times.entry(*ms).or_default() += n;
        }
        s.latency_ms.max = s.latency_ms.max.max(agg.raw_data.maximum_time);
        if agg.fail_count > 0 {
            s.failing_endpoints.push(Endpoint {
                name: name.clone(),
                requests: total,
                failed: agg.fail_count,
            });
        }
    }
    s.throttled = s.status_codes.get(&429).copied().unwrap_or(0);
    s.transport_errors = s.status_codes.get(&0).copied().unwrap_or(0);
    let max = s.latency_ms.max;
    s.latency_ms = latency(&times, max);
    s.latency_by_class_ms = by_class
        .into_iter()
        .map(|(k, (t, m))| (k.to_string(), latency(&t, m)))
        .collect();
    s.failing_endpoints.sort_by(|a, b| b.failed.cmp(&a.failed));
    s.failing_endpoints.truncate(10);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_of_histogram() {
        let times = BTreeMap::from([(10, 90), (100, 9), (1000, 1)]);
        assert_eq!(percentile(&times, 100, 0.50), 10);
        assert_eq!(percentile(&times, 100, 0.95), 100);
        assert_eq!(percentile(&times, 100, 0.99), 100);
        assert_eq!(percentile(&times, 100, 1.0), 1000);
        assert_eq!(percentile(&BTreeMap::new(), 0, 0.5), 0);
    }

    #[test]
    fn classifies_requests() {
        assert_eq!(class(&GooseMethod::Get, "GET /v3/users"), "read");
        assert_eq!(class(&GooseMethod::Post, "POST /v3/auth/tokens"), "auth");
        assert_eq!(class(&GooseMethod::Post, "POST /v3/users"), "write");
        assert_eq!(class(&GooseMethod::Delete, "DELETE /v3/users/1"), "write");
    }

    #[test]
    fn latency_of_histogram() {
        let l = latency(&BTreeMap::from([(10, 90), (100, 10)]), 120);
        assert_eq!((l.requests, l.p50, l.p99, l.max), (100, 10, 100, 120));
    }
}
