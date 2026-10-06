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
//! Prometheus text-format scrape endpoint helpers (ADR 0023 Phase 4,
//! ADR 0031).
//!
//! [`format_prometheus_text`] serialises the audit metrics into the Prometheus
//! text exposition format (version 0.0.4) using the shared primitives of
//! `openstack-keystone-metrics`, so they can be scraped by any
//! Prometheus-compatible collector.
//!
//! For the `keystone` service the metric names match the alert rules in
//! `deploy/prometheus/alert_rules.yaml`.

use std::fmt;

use openstack_keystone_metrics::{Counter, LabeledCounter, write_metric_header};

use crate::{AuditDispatcher, ServiceIdentity};

/// Counters bumped by the spool writer, verifier and segment shipper.
///
/// One instance is owned by the [`AuditDispatcher`] and shared (as an `Arc`)
/// with the background tasks through `SpoolConfig` and `ShipperConfig`.
pub struct AuditMetrics {
    /// Events handed to the sink, by `result` (`shipped` or `skipped` for an
    /// unparsable line).
    pub shipped_events: LabeledCounter<1>,
    /// Failed attempts to deliver a batch to the sink.
    pub sink_errors: Counter,
    /// Segments renamed to `*.quarantine-*` (tampered or unparsable lines).
    pub spool_quarantined: Counter,
    /// Sealed segments deleted unacknowledged by the size, age or count
    /// limits.
    pub spool_retention_deleted: Counter,
    /// Lines checked when a sealed segment is verified at startup, by
    /// `result` (`verified` or `invalid`).
    pub spool_verified: LabeledCounter<1>,
    /// Events the spool writer failed to append to the live spool.
    pub spool_write_failures: Counter,
}

impl Default for AuditMetrics {
    fn default() -> Self {
        Self {
            shipped_events: LabeledCounter::new(["result"]),
            sink_errors: Counter::new(),
            spool_quarantined: Counter::new(),
            spool_retention_deleted: Counter::new(),
            spool_verified: LabeledCounter::new(["result"]),
            spool_write_failures: Counter::new(),
        }
    }
}

impl fmt::Debug for AuditMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditMetrics").finish_non_exhaustive()
    }
}

/// Serialise the audit metrics as Prometheus text format.
///
/// Metric names are `{service}_audit_*`; the list below is for the `keystone`
/// service. Output is valid for Prometheus text format version 0.0.4 and
/// contains:
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
pub fn format_prometheus_text(dispatcher: &AuditDispatcher, service: &ServiceIdentity) -> String {
    let m = dispatcher.metrics();
    let mut out = String::new();

    write_metric_header(
        &mut out,
        &service.metric_name("dropped_total"),
        "Total perimeter audit events dropped because the best-effort channel was full.",
        "counter",
    );
    out.push_str(&format!(
        "{} {}\n",
        service.metric_name("dropped_total"),
        dispatcher.dropped_count()
    ));

    write_metric_header(
        &mut out,
        &service.metric_name("postaudit_dropped_total"),
        "Post-audit outcome records (Success/Failure) that could not be recorded after the \
         operation ran; compensating local log entries were written.",
        "counter",
    );
    out.push_str(&format!(
        "{} {}\n",
        service.metric_name("postaudit_dropped_total"),
        dispatcher.postaudit_dropped_count()
    ));

    write_metric_header(
        &mut out,
        &service.metric_name("events_total"),
        &format!(
            "Audit events accepted into the perimeter or critical channel. Dropped events are \
             counted in {} instead.",
            service.metric_name("dropped_total")
        ),
        "counter",
    );
    out.push_str(&format!(
        "{} {}\n",
        service.metric_name("events_total"),
        dispatcher.events_total()
    ));

    write_metric_header(
        &mut out,
        &service.metric_name("channel_depth"),
        "Audit events queued in a channel, waiting for the spool writer.",
        "gauge",
    );
    let (perimeter, critical) = dispatcher.channel_depths();
    let depth = service.metric_name("channel_depth");
    out.push_str(&format!(
        "{depth}{{channel=\"perimeter\"}} {perimeter}\n\
         {depth}{{channel=\"critical\"}} {critical}\n"
    ));

    write_metric_header(
        &mut out,
        &service.metric_name("hmac_key_version"),
        "Version of the HMAC key currently signing audit events.",
        "gauge",
    );
    out.push_str(&format!(
        "{} {}\n",
        service.metric_name("hmac_key_version"),
        dispatcher.hmac_key_version()
    ));

    write_metric_header(
        &mut out,
        &service.metric_name("spool_bytes"),
        "Bytes held on disk by the audit spool (live file plus sealed segments).",
        "gauge",
    );
    out.push_str(&format!(
        "{} {}\n",
        service.metric_name("spool_bytes"),
        dispatcher.spool_bytes()
    ));

    write_metric_header(
        &mut out,
        &service.metric_name("spool_write_failures_total"),
        "Audit events the spool writer failed to append to the spool; each is lost.",
        "counter",
    );
    m.spool_write_failures
        .write_line(&mut out, &service.metric_name("spool_write_failures_total"));

    write_metric_header(
        &mut out,
        &service.metric_name("spool_quarantined_total"),
        "Spool segments quarantined because of tampered or unparsable lines.",
        "counter",
    );
    m.spool_quarantined
        .write_line(&mut out, &service.metric_name("spool_quarantined_total"));

    write_metric_header(
        &mut out,
        &service.metric_name("spool_verified_total"),
        "Lines checked when a sealed spool segment was verified at startup.",
        "counter",
    );
    m.spool_verified
        .write_lines(&mut out, &service.metric_name("spool_verified_total"));

    write_metric_header(
        &mut out,
        &service.metric_name("shipped_events_total"),
        "Events handed to the audit sink; result=skipped counts unparsable spool lines.",
        "counter",
    );
    m.shipped_events
        .write_lines(&mut out, &service.metric_name("shipped_events_total"));

    write_metric_header(
        &mut out,
        &service.metric_name("sink_errors_total"),
        "Failed attempts to deliver a batch to the audit sink.",
        "counter",
    );
    m.sink_errors
        .write_line(&mut out, &service.metric_name("sink_errors_total"));

    write_metric_header(
        &mut out,
        &service.metric_name("spool_retention_deleted_total"),
        "Sealed spool segments deleted unacknowledged by the size, age or count limits.",
        "counter",
    );
    m.spool_retention_deleted.write_line(
        &mut out,
        &service.metric_name("spool_retention_deleted_total"),
    );

    out
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

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

    #[test]
    fn every_series_has_help_and_type() {
        let dispatcher = AuditDispatcher::noop();
        let text = format_prometheus_text(&dispatcher, &SERVICE);
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
        let text = format_prometheus_text(&dispatcher, &ServiceIdentity::new("glance"));
        assert!(text.contains("# TYPE glance_audit_dropped_total counter"));
        assert!(text.contains("counted in glance_audit_dropped_total instead."));
        assert!(!text.contains("keystone"));
    }

    #[test]
    fn format_zero_values() {
        let dispatcher = AuditDispatcher::noop();
        let text = format_prometheus_text(&dispatcher, &SERVICE);
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
        let text = format_prometheus_text(&d, &SERVICE);
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
        let m = d.metrics();
        m.spool_write_failures.add(2);
        m.spool_quarantined.inc();
        m.spool_verified.add(["verified"], 5);
        m.spool_verified.inc(["invalid"]);
        m.shipped_events.add(["shipped"], 9);
        m.sink_errors.inc();
        let text = format_prometheus_text(&d, &SERVICE);
        assert!(text.contains("keystone_audit_spool_write_failures_total 2\n"));
        assert!(text.contains("keystone_audit_spool_quarantined_total 1\n"));
        assert!(text.contains("keystone_audit_spool_verified_total{result=\"verified\"} 5\n"));
        assert!(text.contains("keystone_audit_spool_verified_total{result=\"invalid\"} 1\n"));
        assert!(text.contains("keystone_audit_shipped_events_total{result=\"shipped\"} 9\n"));
        assert!(text.contains("keystone_audit_sink_errors_total 1\n"));
    }
}
