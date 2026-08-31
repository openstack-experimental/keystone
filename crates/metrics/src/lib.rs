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
//! # Shared Prometheus text-exposition primitives (ADR 0031)
//!
//! Every subsystem (audit, HTTP, auth, tokens, policy, rate limiting, Raft,
//! ...) needs the same handful of building blocks — an atomic counter, a
//! fixed-bucket histogram, and label-value escaping — to serialise its
//! metrics as Prometheus text exposition format (v0.0.4). Rather than
//! re-deriving those in every crate (as `crates/audit/src/metrics.rs` and
//! `auth_plugin_startup::format_load_failure_metrics` each partially did
//! before this crate existed), they live here once.
//!
//! This deliberately does **not** pull in the `prometheus` or `metrics`
//! crate: per ADR 0031, the full metrics catalog is a fixed, known-at-
//! compile-time set of series, so a dynamic metric registry isn't needed.
//!
//! **Cardinality / PII guardrail (ADR 0031):** every label value handled by
//! [`LabeledCounter`], [`LabeledGauge`], and [`LabeledHistogram`] MUST come
//! from a bounded, operator-or-code-controlled set (a Rust enum's variant
//! names, an Axum `MatchedPath` route template, a config-defined name).
//! Never a raw resource ID, free-text error message, or raw request path —
//! those are unbounded and turn `/metrics` into a cardinality-explosion DoS
//! vector. This module cannot enforce that; callers must.

use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use dashmap::DashMap;

/// Standard latency bucket upper bounds (seconds), tuned for Keystone's
/// fast auth/token paths (tighter low end than the Prometheus client
/// library's defaults). Shared by every subsystem's latency histograms so
/// dashboards/alert rules can rely on one consistent bucket layout.
pub const DEFAULT_LATENCY_BUCKETS: [f64; 11] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Escapes a label value per the Prometheus text-exposition format:
/// backslash and double-quote are backslash-escaped, newline becomes `\n`.
pub fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Appends the `# HELP` and `# TYPE` header lines for one metric.
pub fn write_metric_header(out: &mut String, name: &str, help: &str, metric_type: &str) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} {metric_type}\n"
    ));
}

/// Renders a Prometheus label set, e.g. `{method="GET",route="/v3/users"}`.
/// Empty when `names` is empty (unlabeled series).
fn format_label_set(names: &[&str], values: &[String]) -> String {
    if names.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = names
        .iter()
        .zip(values.iter())
        .map(|(n, v)| format!("{n}=\"{}\"", escape_label_value(v)))
        .collect();
    format!("{{{}}}", parts.join(","))
}

/// Every subsystem contributes one `format_prometheus_text` of this shape;
/// `metrics_handler` concatenates all of them into the scrape response.
pub trait PrometheusText {
    fn format_prometheus_text(&self) -> String;
}

/// A single monotonic, unlabeled counter.
#[derive(Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    /// Appends `name value\n` (no labels, no HELP/TYPE header).
    pub fn write_line(&self, out: &mut String, name: &str) {
        out.push_str(&format!("{name} {}\n", self.get()));
    }
}

/// A single point-in-time, unlabeled gauge.
#[derive(Default)]
pub struct Gauge(AtomicI64);

impl Gauge {
    pub fn new() -> Self {
        Self(AtomicI64::new(0))
    }

    pub fn set(&self, value: i64) {
        self.0.store(value, Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }

    pub fn write_line(&self, out: &mut String, name: &str) {
        out.push_str(&format!("{name} {}\n", self.get()));
    }
}

/// A fixed-bucket histogram using [`DEFAULT_LATENCY_BUCKETS`], storing
/// per-bucket cumulative counts as `AtomicU64` plus a sum (as integer
/// microseconds, to stay lock-free) and a total count.
pub struct Histogram {
    bucket_counts: [AtomicU64; DEFAULT_LATENCY_BUCKETS.len()],
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    pub fn new() -> Self {
        Self {
            bucket_counts: std::array::from_fn(|_| AtomicU64::new(0)),
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub fn record(&self, value_seconds: f64) {
        for (bound, counter) in DEFAULT_LATENCY_BUCKETS
            .iter()
            .zip(self.bucket_counts.iter())
        {
            if value_seconds <= *bound {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        let micros = (value_seconds * 1_000_000.0).round().max(0.0) as u64;
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// `(upper_bound, cumulative_count)` pairs, ascending, plus a final
    /// `(f64::INFINITY, total_count)` entry for the `+Inf` bucket.
    pub fn bucket_counts(&self) -> Vec<(f64, u64)> {
        let mut out: Vec<(f64, u64)> = DEFAULT_LATENCY_BUCKETS
            .iter()
            .zip(self.bucket_counts.iter())
            .map(|(bound, counter)| (*bound, counter.load(Ordering::Relaxed)))
            .collect();
        out.push((f64::INFINITY, self.count()));
        out
    }

    pub fn sum(&self) -> f64 {
        self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Appends the `_bucket`/`_sum`/`_count` lines for one label set (no
    /// HELP/TYPE header — callers own that, since one histogram struct
    /// backs many label combinations).
    pub fn write_lines(
        &self,
        out: &mut String,
        name: &str,
        label_names: &[&str],
        label_values: &[String],
    ) {
        let labels = format_label_set(label_names, label_values);
        for (bound, cumulative) in self.bucket_counts() {
            let le = if bound.is_infinite() {
                "+Inf".to_owned()
            } else {
                bound.to_string()
            };
            let le_labels = if label_names.is_empty() {
                format!("{{le=\"{le}\"}}")
            } else {
                let mut names = label_names.to_vec();
                names.push("le");
                let mut values = label_values.to_vec();
                values.push(le);
                format_label_set(&names, &values)
            };
            out.push_str(&format!("{name}_bucket{le_labels} {cumulative}\n"));
        }
        out.push_str(&format!("{name}_sum{labels} {}\n", self.sum()));
        out.push_str(&format!("{name}_count{labels} {}\n", self.count()));
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

/// A monotonic counter labeled by `N` bounded dimensions (ADR 0031
/// cardinality guardrail applies to every label value passed to
/// [`LabeledCounter::inc`]). Backed by a [`DashMap`] since the label-value
/// combinations, while bounded, are not always enumerable as a `const`
/// array at construction time (e.g. operator-configured plugin names).
pub struct LabeledCounter<const N: usize> {
    label_names: [&'static str; N],
    values: DashMap<[String; N], AtomicU64>,
}

impl<const N: usize> LabeledCounter<N> {
    pub fn new(label_names: [&'static str; N]) -> Self {
        Self {
            label_names,
            values: DashMap::new(),
        }
    }

    pub fn inc(&self, label_values: [&str; N]) {
        self.add(label_values, 1);
    }

    pub fn add(&self, label_values: [&str; N], n: u64) {
        let key = label_values.map(str::to_owned);
        self.values
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self, label_values: [&str; N]) -> u64 {
        let key = label_values.map(str::to_owned);
        self.values
            .get(&key)
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Appends one `name{labels} value` line per recorded label
    /// combination, sorted by label values for deterministic output.
    pub fn write_lines(&self, out: &mut String, name: &str) {
        let mut entries: Vec<([String; N], u64)> = self
            .values
            .iter()
            .map(|e| (e.key().clone(), e.value().load(Ordering::Relaxed)))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (values, count) in entries {
            let labels = format_label_set(&self.label_names, &values);
            out.push_str(&format!("{name}{labels} {count}\n"));
        }
    }
}

/// A point-in-time gauge labeled by `N` bounded dimensions (e.g.
/// `keystone_raft_replication_lag{peer_id}`).
pub struct LabeledGauge<const N: usize> {
    label_names: [&'static str; N],
    values: DashMap<[String; N], AtomicI64>,
}

impl<const N: usize> LabeledGauge<N> {
    pub fn new(label_names: [&'static str; N]) -> Self {
        Self {
            label_names,
            values: DashMap::new(),
        }
    }

    pub fn set(&self, label_values: [&str; N], value: i64) {
        let key = label_values.map(str::to_owned);
        self.values
            .entry(key)
            .or_insert_with(|| AtomicI64::new(0))
            .store(value, Ordering::Relaxed);
    }

    pub fn get(&self, label_values: [&str; N]) -> i64 {
        let key = label_values.map(str::to_owned);
        self.values
            .get(&key)
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn write_lines(&self, out: &mut String, name: &str) {
        let mut entries: Vec<([String; N], i64)> = self
            .values
            .iter()
            .map(|e| (e.key().clone(), e.value().load(Ordering::Relaxed)))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (values, value) in entries {
            let labels = format_label_set(&self.label_names, &values);
            out.push_str(&format!("{name}{labels} {value}\n"));
        }
    }
}

/// A [`Histogram`] labeled by `N` bounded dimensions (e.g.
/// `keystone_policy_decision_duration_seconds{transport}`).
pub struct LabeledHistogram<const N: usize> {
    label_names: [&'static str; N],
    values: DashMap<[String; N], Histogram>,
    // Guards histogram creation so two racing first-observations for the
    // same label combination can't both `insert`, silently dropping one
    // Histogram (and the sample recorded into it) — DashMap::entry alone
    // would still only construct once per shard-lock, but the Mutex makes
    // the "create-if-absent" step explicit and cheap (only taken on the
    // rare first-sample-for-this-label-set path).
    create_lock: Mutex<()>,
}

impl<const N: usize> LabeledHistogram<N> {
    pub fn new(label_names: [&'static str; N]) -> Self {
        Self {
            label_names,
            values: DashMap::new(),
            create_lock: Mutex::new(()),
        }
    }

    pub fn record(&self, label_values: [&str; N], value_seconds: f64) {
        let key = label_values.map(str::to_owned);
        if let Some(hist) = self.values.get(&key) {
            hist.record(value_seconds);
            return;
        }
        let _guard = self.create_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.values.entry(key).or_default().record(value_seconds);
    }

    pub fn write_lines(&self, out: &mut String, name: &str) {
        let mut keys: Vec<[String; N]> = self.values.iter().map(|e| e.key().clone()).collect();
        keys.sort();
        for key in keys {
            if let Some(hist) = self.values.get(&key) {
                let values: Vec<String> = key.to_vec();
                hist.write_lines(out, name, &self.label_names, &values);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_increments_and_writes() {
        let c = Counter::new();
        c.inc();
        c.add(4);
        assert_eq!(c.get(), 5);
        let mut out = String::new();
        c.write_line(&mut out, "keystone_test_total");
        assert_eq!(out, "keystone_test_total 5\n");
    }

    #[test]
    fn gauge_set_inc_dec() {
        let g = Gauge::new();
        g.set(3);
        g.inc();
        g.dec();
        assert_eq!(g.get(), 3);
    }

    #[test]
    fn histogram_buckets_and_sum_count() {
        let h = Histogram::new();
        h.record(0.02);
        h.record(6.0);
        let counts = h.bucket_counts();
        // 0.025 bucket bound is the smallest bound >= 0.02.
        let (bound_0_025, count_0_025) = counts[3];
        assert_eq!(bound_0_025, 0.025);
        assert_eq!(count_0_025, 1);
        let (inf_bound, inf_count) = *counts.last().unwrap();
        assert!(inf_bound.is_infinite());
        assert_eq!(inf_count, 2);
        assert_eq!(h.count(), 2);
        assert!((h.sum() - 6.02).abs() < 1e-6);
    }

    #[test]
    fn histogram_write_lines_unlabeled() {
        let h = Histogram::new();
        h.record(0.001);
        let mut out = String::new();
        h.write_lines(&mut out, "keystone_test_duration_seconds", &[], &[]);
        assert!(out.contains("keystone_test_duration_seconds_bucket{le=\"0.001\"} 1"));
        assert!(out.contains("keystone_test_duration_seconds_bucket{le=\"+Inf\"} 1"));
        assert!(out.contains("keystone_test_duration_seconds_sum 0.001"));
        assert!(out.contains("keystone_test_duration_seconds_count 1"));
    }

    #[test]
    fn labeled_counter_tracks_independent_series() {
        let c = LabeledCounter::<2>::new(["method", "outcome"]);
        c.inc(["password", "success"]);
        c.inc(["password", "success"]);
        c.inc(["password", "failure"]);
        assert_eq!(c.get(["password", "success"]), 2);
        assert_eq!(c.get(["password", "failure"]), 1);
        assert_eq!(c.get(["token", "success"]), 0);

        let mut out = String::new();
        c.write_lines(&mut out, "keystone_auth_attempts_total");
        assert!(
            out.contains("keystone_auth_attempts_total{method=\"password\",outcome=\"success\"} 2")
        );
        assert!(
            out.contains("keystone_auth_attempts_total{method=\"password\",outcome=\"failure\"} 1")
        );
    }

    #[test]
    fn labeled_gauge_tracks_independent_series() {
        let g = LabeledGauge::<1>::new(["peer_id"]);
        g.set(["node-2"], 5);
        g.set(["node-2"], 7);
        assert_eq!(g.get(["node-2"]), 7);
        assert_eq!(g.get(["node-3"]), 0);
    }

    #[test]
    fn labeled_histogram_records_per_label_set() {
        let h = LabeledHistogram::<1>::new(["transport"]);
        h.record(["http"], 0.01);
        h.record(["wasm"], 0.02);
        h.record(["http"], 0.03);

        let mut out = String::new();
        h.write_lines(&mut out, "keystone_policy_decision_duration_seconds");
        assert!(
            out.contains("keystone_policy_decision_duration_seconds_count{transport=\"http\"} 2")
        );
        assert!(
            out.contains("keystone_policy_decision_duration_seconds_count{transport=\"wasm\"} 1")
        );
    }

    #[test]
    fn escape_label_value_handles_quotes_backslashes_newlines() {
        assert_eq!(escape_label_value("plain"), "plain");
        assert_eq!(escape_label_value("a\"b"), "a\\\"b");
        assert_eq!(escape_label_value("a\\b"), "a\\\\b");
        assert_eq!(escape_label_value("a\nb"), "a\\nb");
    }

    #[test]
    fn write_metric_header_emits_help_and_type() {
        let mut out = String::new();
        write_metric_header(
            &mut out,
            "keystone_test_total",
            "A test counter.",
            "counter",
        );
        assert_eq!(
            out,
            "# HELP keystone_test_total A test counter.\n# TYPE keystone_test_total counter\n"
        );
    }
}
