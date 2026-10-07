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
//! Audit metrics (ADR 0023 Phase 4, ADR 0031, ADR 0040).
//!
//! The writer, verifier and shipper bump plain atomic counters
//! ([`AuditMetrics`]); the dispatcher keeps its own atomics. [`register`]
//! exposes all of them as OpenTelemetry observable instruments, read when
//! metrics are collected, so the hot paths do not touch the SDK and `/metrics`
//! and OTLP report the same values.
//!
//! For the `keystone` service the metric names match the alert rules in
//! `deploy/prometheus/alert_rules.yaml`.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use openstack_keystone_telemetry::metrics::{Emit, Meter, observe_counter, observe_gauge};

use crate::{AuditDispatcher, ServiceIdentity};

/// A monotonically increasing count.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// Add `n`.
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    /// The current total.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    /// Add 1.
    pub fn inc(&self) {
        self.add(1);
    }
}

/// Counts split by a `result` label with two fixed values. A value is
/// exposed once it was added to, even by zero.
#[derive(Debug)]
pub struct ResultCounter {
    labels: [&'static str; 2],
    counts: [Counter; 2],
    touched: [AtomicBool; 2],
}

impl ResultCounter {
    fn new(labels: [&'static str; 2]) -> Self {
        Self {
            labels,
            counts: [Counter::default(), Counter::default()],
            touched: [AtomicBool::new(false), AtomicBool::new(false)],
        }
    }

    fn index(&self, result: &str) -> Option<usize> {
        self.labels.iter().position(|l| *l == result)
    }

    /// Add `n` to `result`, one of the two fixed values; any other value is
    /// ignored.
    pub fn add(&self, result: &str, n: u64) {
        if let Some(i) = self.index(result) {
            self.counts[i].add(n);
            self.touched[i].store(true, Ordering::Relaxed);
        }
    }

    /// The current total of `result`.
    pub fn get(&self, result: &str) -> u64 {
        self.index(result).map_or(0, |i| self.counts[i].get())
    }

    /// Emit every touched value with its total.
    fn emit(&self, emit: Emit<'_, 1>) {
        for i in (0..2).filter(|i| self.touched[*i].load(Ordering::Relaxed)) {
            emit([self.labels[i].into()], self.counts[i].get());
        }
    }
}

/// Counters bumped by the spool writer, verifier and segment shipper.
///
/// One instance is owned by the [`AuditDispatcher`] and shared (as an `Arc`)
/// with the background tasks through `SpoolConfig` and `ShipperConfig`.
pub struct AuditMetrics {
    /// Events handed to the sink, by `result` (`shipped` or `skipped` for an
    /// unparsable line).
    pub shipped_events: ResultCounter,
    /// Failed attempts to deliver a batch to the sink.
    pub sink_errors: Counter,
    /// Segments renamed to `*.quarantine-*` (tampered or unparsable lines).
    pub spool_quarantined: Counter,
    /// Sealed segments deleted unacknowledged by the size, age or count
    /// limits.
    pub spool_retention_deleted: Counter,
    /// Lines checked when a sealed segment is verified at startup, by
    /// `result` (`verified` or `invalid`).
    pub spool_verified: ResultCounter,
    /// Events the spool writer failed to append to the live spool.
    pub spool_write_failures: Counter,
}

impl Default for AuditMetrics {
    fn default() -> Self {
        Self {
            shipped_events: ResultCounter::new(["shipped", "skipped"]),
            sink_errors: Counter::default(),
            spool_quarantined: Counter::default(),
            spool_retention_deleted: Counter::default(),
            spool_verified: ResultCounter::new(["verified", "invalid"]),
            spool_write_failures: Counter::default(),
        }
    }
}

impl fmt::Debug for AuditMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditMetrics").finish_non_exhaustive()
    }
}

/// Expose the audit metrics of `dispatcher` on `meter`.
///
/// Metric names are `{service}_audit_*`; the list below is for the `keystone`
/// service:
/// - `keystone_audit_dropped_total`: perimeter events dropped (channel full)
/// - `keystone_audit_postaudit_dropped_total`: post-audit outcomes lost
/// - `keystone_audit_events_total`: events accepted into a channel (drops are
///   not included)
/// - `keystone_audit_channel_depth{channel}` (gauge)
/// - `keystone_audit_hmac_key_version` (gauge)
/// - `keystone_audit_spool_bytes` (gauge)
/// - `keystone_audit_spool_write_failures_total`
/// - `keystone_audit_spool_quarantined_total`
/// - `keystone_audit_spool_verified_total{result}`
/// - `keystone_audit_shipped_events_total{result}`
/// - `keystone_audit_sink_errors_total`
/// - `keystone_audit_spool_retention_deleted_total`
///
/// Call it once per dispatcher, after telemetry is initialised. The
/// instruments only hold a weak reference: once the dispatcher is dropped
/// they report nothing.
pub fn register(dispatcher: &Arc<AuditDispatcher>, meter: &Meter, service: &ServiceIdentity) {
    let dropped_name = service.metric_name("dropped_total");
    let weak = Arc::downgrade(dispatcher);
    // A reader of one dispatcher value, nothing once the dispatcher is gone.
    let from_dispatcher = |read: fn(&AuditDispatcher) -> u64| {
        let weak: Weak<AuditDispatcher> = weak.clone();
        move |emit: Emit<'_, 0>| {
            if let Some(d) = weak.upgrade() {
                emit([], read(&d));
            }
        }
    };

    observe_counter(
        meter,
        dropped_name.clone(),
        "Total perimeter audit events dropped because the best-effort channel was full.",
        [],
        from_dispatcher(AuditDispatcher::dropped_count),
    );
    observe_counter(
        meter,
        service.metric_name("postaudit_dropped_total"),
        "Post-audit outcome records (Success/Failure) that could not be recorded after the \
         operation ran; compensating local log entries were written.",
        [],
        from_dispatcher(AuditDispatcher::postaudit_dropped_count),
    );
    observe_counter(
        meter,
        service.metric_name("events_total"),
        format!(
            "Audit events accepted into the perimeter or critical channel. Dropped events are \
             counted in {dropped_name} instead."
        ),
        [],
        from_dispatcher(AuditDispatcher::events_total),
    );
    let channels = weak.clone();
    observe_gauge(
        meter,
        service.metric_name("channel_depth"),
        "Audit events queued in a channel, waiting for the spool writer.",
        ["channel"],
        move |emit| {
            if let Some(d) = channels.upgrade() {
                let (perimeter, critical) = d.channel_depths();
                emit(["perimeter".into()], perimeter as u64);
                emit(["critical".into()], critical as u64);
            }
        },
    );
    observe_gauge(
        meter,
        service.metric_name("hmac_key_version"),
        "Version of the HMAC key currently signing audit events.",
        [],
        from_dispatcher(AuditDispatcher::hmac_key_version),
    );
    observe_gauge(
        meter,
        service.metric_name("spool_bytes"),
        "Bytes held on disk by the audit spool (live file plus sealed segments).",
        [],
        from_dispatcher(AuditDispatcher::spool_bytes),
    );

    // The counters live in `AuditMetrics`, shared with the background tasks.
    let m = Arc::clone(dispatcher.metrics());
    let counter = |name: &str, help: &'static str, read: fn(&AuditMetrics) -> u64| {
        let m = Arc::clone(&m);
        observe_counter(meter, service.metric_name(name), help, [], move |emit| {
            emit([], read(&m))
        });
    };
    counter(
        "spool_write_failures_total",
        "Audit events the spool writer failed to append to the spool; each is lost.",
        |m| m.spool_write_failures.get(),
    );
    counter(
        "spool_quarantined_total",
        "Spool segments quarantined because of tampered or unparsable lines.",
        |m| m.spool_quarantined.get(),
    );
    counter(
        "sink_errors_total",
        "Failed attempts to deliver a batch to the audit sink.",
        |m| m.sink_errors.get(),
    );
    counter(
        "spool_retention_deleted_total",
        "Sealed spool segments deleted unacknowledged by the size, age or count limits.",
        |m| m.spool_retention_deleted.get(),
    );
    let verified = Arc::clone(&m);
    observe_counter(
        meter,
        service.metric_name("spool_verified_total"),
        "Lines checked when a sealed spool segment was verified at startup.",
        ["result"],
        move |emit| verified.spool_verified.emit(emit),
    );
    let shipped = Arc::clone(&m);
    observe_counter(
        meter,
        service.metric_name("shipped_events_total"),
        "Events handed to the audit sink; result=skipped counts unparsable spool lines.",
        ["result"],
        move |emit| shipped.shipped_events.emit(emit),
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use openstack_keystone_telemetry::metrics::MetricsPipeline;

    use super::*;
    use crate::{CadfEventPayload, Initiator, Observer, Target};

    const SERVICE: ServiceIdentity = ServiceIdentity::new("keystone");

    fn event(dispatcher: &AuditDispatcher) -> crate::CadfEvent {
        CadfEventPayload::new(
            "n:1".to_string(),
            "1.0".to_string(),
            "c".to_string(),
            "2026-10-03T20:00:00+00:00".to_string(),
            "authenticate".to_string(),
            crate::types::Outcome::Success,
            None,
            Initiator::new("unknown".to_string(), None, None, None),
            Target::new("keystone", "service/security/keystone/auth"),
            Observer::new("n", "service/security/keystone/n"),
        )
        .sign(dispatcher)
    }

    /// Render the metrics of `dispatcher` the way `/metrics` serves them.
    fn render(dispatcher: &Arc<AuditDispatcher>, service: &ServiceIdentity) -> String {
        let pipeline = MetricsPipeline::new();
        register(dispatcher, &pipeline.meter(), service);
        pipeline.render()
    }

    /// Pins the rendered exposition text against `tests/golden/audit.prom`
    /// (ADR 0040). All series are rendered, with their zero values.
    #[test]
    fn golden_exposition() {
        let dispatcher = AuditDispatcher::noop();
        openstack_keystone_telemetry::assert_golden!("audit", render(&dispatcher, &SERVICE));
    }

    #[test]
    fn every_series_has_help_and_type() {
        let dispatcher = AuditDispatcher::noop();
        dispatcher.metrics().spool_verified.add("verified", 0);
        dispatcher.metrics().shipped_events.add("shipped", 0);
        let text = render(&dispatcher, &SERVICE);
        for name in [
            "keystone_audit_dropped_total",
            "keystone_audit_postaudit_dropped_total",
            "keystone_audit_events_total",
            "keystone_audit_channel_depth",
            "keystone_audit_hmac_key_version",
            "keystone_audit_spool_bytes",
            "keystone_audit_spool_write_failures_total",
            "keystone_audit_spool_quarantined_total",
            "keystone_audit_spool_verified_total",
            "keystone_audit_shipped_events_total",
            "keystone_audit_sink_errors_total",
            "keystone_audit_spool_retention_deleted_total",
        ] {
            assert!(text.contains(&format!("# HELP {name} ")), "{name}");
            assert!(text.contains(&format!("# TYPE {name} ")), "{name}");
        }
        assert_eq!(text.matches("# HELP").count(), 12);
        assert_eq!(text.matches("# TYPE").count(), 12);
        assert_eq!(text.matches(" gauge\n").count(), 3);
    }

    #[test]
    fn metric_names_use_the_service_prefix() {
        let dispatcher = AuditDispatcher::noop();
        let text = render(&dispatcher, &ServiceIdentity::new("glance"));
        assert!(text.contains("# TYPE glance_audit_dropped_total counter"));
        assert!(text.contains("counted in glance_audit_dropped_total instead."));
        assert!(!text.contains("keystone"));
    }

    #[test]
    fn format_zero_values() {
        let dispatcher = AuditDispatcher::noop();
        let text = render(&dispatcher, &SERVICE);
        assert!(text.contains("keystone_audit_dropped_total 0"));
        assert!(text.contains("keystone_audit_postaudit_dropped_total 0"));
        assert!(text.contains("keystone_audit_events_total 0"));
        assert!(text.contains("keystone_audit_spool_bytes 0"));
        assert!(text.contains("keystone_audit_spool_write_failures_total 0"));
        assert!(text.contains("keystone_audit_spool_quarantined_total 0"));
        assert!(text.contains("keystone_audit_sink_errors_total 0"));
        assert!(text.contains("keystone_audit_spool_retention_deleted_total 0"));
        assert!(text.contains("keystone_audit_channel_depth{channel=\"perimeter\"} 0"));
        assert!(text.contains("keystone_audit_hmac_key_version 0"));
    }

    #[test]
    fn events_total_counts_only_accepted_events() {
        let key: Arc<[u8]> = Arc::from(b"k".as_slice());
        let (d, _rx) = AuditDispatcher::new("n", "b".to_string(), key, 7);
        // The perimeter channel holds 4096 events; the last four are dropped.
        for _ in 0..4100 {
            d.dispatch(event(&d));
        }
        let text = render(&d, &SERVICE);
        assert!(
            text.contains("keystone_audit_events_total 4096\n"),
            "{text}"
        );
        assert!(text.contains("keystone_audit_dropped_total 4\n"), "{text}");
        assert!(text.contains("keystone_audit_channel_depth{channel=\"perimeter\"} 4096\n"));
        assert!(text.contains("keystone_audit_hmac_key_version 7\n"));
    }

    #[test]
    fn labeled_and_plain_counters_are_exported() {
        let d = AuditDispatcher::noop();
        let m = Arc::clone(d.metrics());
        m.spool_write_failures.add(2);
        m.spool_quarantined.inc();
        m.spool_verified.add("verified", 5);
        m.spool_verified.add("invalid", 1);
        m.shipped_events.add("shipped", 9);
        m.sink_errors.inc();
        let text = render(&d, &SERVICE);
        assert!(text.contains("keystone_audit_spool_write_failures_total 2\n"));
        assert!(text.contains("keystone_audit_spool_quarantined_total 1\n"));
        assert!(text.contains("keystone_audit_spool_verified_total{result=\"verified\"} 5\n"));
        assert!(text.contains("keystone_audit_spool_verified_total{result=\"invalid\"} 1\n"));
        assert!(text.contains("keystone_audit_shipped_events_total{result=\"shipped\"} 9\n"));
        assert!(text.contains("keystone_audit_sink_errors_total 1\n"));
    }
}
