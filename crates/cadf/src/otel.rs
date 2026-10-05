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

//! OpenTelemetry view of the audit metrics (`otel` feature).
//!
//! [`register`] exposes the same series as
//! [`format_prometheus_text`](crate::metrics::format_prometheus_text) on an
//! OpenTelemetry [`Meter`]. The existing counters stay the single source of
//! truth: every instrument is an *observable* one whose callback reads the
//! current value at collection time. No call site in the dispatcher, spool
//! writer or shipper changes, nothing is counted twice, and a service that
//! never calls [`register`] pays nothing.
//!
//! Instrument names follow OpenTelemetry conventions, `{service}.audit.*`
//! without the `_total` suffix (for example `keystone.audit.dropped`). An
//! OpenTelemetry-to-Prometheus pipeline maps dots to underscores and appends
//! `_total` to monotonic sums, which yields the names the text endpoint
//! already serves.

use std::sync::{Arc, Weak};

use opentelemetry::KeyValue;
use opentelemetry::metrics::Meter;

use crate::{AuditDispatcher, ServiceIdentity};

/// Label values of the `result` dimension of the verification counter.
const VERIFIED_RESULTS: [&str; 2] = ["verified", "invalid"];
/// Label values of the `result` dimension of the shipped-events counter.
const SHIPPED_RESULTS: [&str; 2] = ["shipped", "skipped"];

/// OpenTelemetry instrument name for `suffix`: `{service}.audit.{suffix}`.
fn name(service: &ServiceIdentity, suffix: &str) -> String {
    format!("{}.audit.{suffix}", service.name())
}

/// Register the audit instruments of `dispatcher` on `meter`.
///
/// Callbacks hold the dispatcher weakly, so registering does not keep it
/// alive: once it is dropped the instruments simply report nothing.
pub fn register(dispatcher: &Arc<AuditDispatcher>, service: &ServiceIdentity, meter: &Meter) {
    macro_rules! counter {
        ($suffix:expr, $help:expr, |$d:ident| $value:expr) => {{
            let weak: Weak<AuditDispatcher> = Arc::downgrade(dispatcher);
            meter
                .u64_observable_counter(name(service, $suffix))
                .with_description($help)
                .with_callback(move |observer| {
                    if let Some($d) = weak.upgrade() {
                        observer.observe($value, &[]);
                    }
                })
                .build();
        }};
    }
    macro_rules! gauge {
        ($suffix:expr, $help:expr, |$d:ident| $value:expr) => {{
            let weak: Weak<AuditDispatcher> = Arc::downgrade(dispatcher);
            meter
                .u64_observable_gauge(name(service, $suffix))
                .with_description($help)
                .with_callback(move |observer| {
                    if let Some($d) = weak.upgrade() {
                        observer.observe($value, &[]);
                    }
                })
                .build();
        }};
    }

    counter!(
        "dropped",
        "Perimeter audit events dropped because the best-effort channel was full.",
        |d| d.dropped_count()
    );
    counter!(
        "postaudit_dropped",
        "Post-audit outcome records that could not be recorded after the operation ran.",
        |d| d.postaudit_dropped_count()
    );
    counter!(
        "events",
        "Audit events accepted into the perimeter or critical channel.",
        |d| d.events_total()
    );
    counter!(
        "spool_write_failures",
        "Audit events the spool writer failed to append to the spool.",
        |d| d.metrics().spool_write_failures.get()
    );
    counter!(
        "spool_quarantined",
        "Spool segments quarantined because of tampered or unparsable lines.",
        |d| d.metrics().spool_quarantined.get()
    );
    counter!(
        "sink_errors",
        "Failed attempts to deliver a batch to the sink.",
        |d| d.metrics().sink_errors.get()
    );
    counter!(
        "spool_retention_deleted",
        "Sealed segments deleted unacknowledged by the size, age or count limits.",
        |d| d.metrics().spool_retention_deleted.get()
    );
    gauge!(
        "hmac_key_version",
        "Version of the HMAC key currently signing audit events.",
        |d| d.hmac_key_version()
    );
    gauge!(
        "spool_bytes",
        "Bytes held on disk by the audit spool (live file plus sealed segments).",
        |d| d.spool_bytes()
    );

    let weak = Arc::downgrade(dispatcher);
    meter
        .u64_observable_gauge(name(service, "channel_depth"))
        .with_description("Audit events queued in a channel, waiting for the spool writer.")
        .with_callback(move |observer| {
            if let Some(d) = weak.upgrade() {
                let (perimeter, critical) = d.channel_depths();
                observer.observe(perimeter as u64, &[KeyValue::new("channel", "perimeter")]);
                observer.observe(critical as u64, &[KeyValue::new("channel", "critical")]);
            }
        })
        .build();

    let weak = Arc::downgrade(dispatcher);
    meter
        .u64_observable_counter(name(service, "spool_verified"))
        .with_description("Lines checked when a sealed spool segment was verified at startup.")
        .with_callback(move |observer| {
            if let Some(d) = weak.upgrade() {
                for result in VERIFIED_RESULTS {
                    observer.observe(
                        d.metrics().spool_verified.get([result]),
                        &[KeyValue::new("result", result)],
                    );
                }
            }
        })
        .build();

    let weak = Arc::downgrade(dispatcher);
    meter
        .u64_observable_counter(name(service, "shipped_events"))
        .with_description("Events handed to the sink.")
        .with_callback(move |observer| {
            if let Some(d) = weak.upgrade() {
                for result in SHIPPED_RESULTS {
                    observer.observe(
                        d.metrics().shipped_events.get([result]),
                        &[KeyValue::new("result", result)],
                    );
                }
            }
        })
        .build();
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::metrics::MeterProvider;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};

    const SERVICE: ServiceIdentity = ServiceIdentity::new("testsvc");

    fn dispatcher() -> Arc<AuditDispatcher> {
        let (dispatcher, _receivers) = AuditDispatcher::new(
            "node-1",
            "observer".to_string(),
            Arc::from(&[7u8; 32][..]),
            3,
        );
        dispatcher
    }

    /// Sum of the data points of the instrument `metric`, plus the data
    /// points' `result`/`channel` attribute values, after one collection.
    fn collect(
        exporter: &InMemoryMetricExporter,
        provider: &SdkMeterProvider,
        metric: &str,
    ) -> Vec<(Option<String>, u64)> {
        // Each flush exports every instrument again; keep only this one.
        exporter.reset();
        provider.force_flush().unwrap();
        let mut points = Vec::new();
        for resource in exporter.get_finished_metrics().unwrap() {
            for scope in resource.scope_metrics() {
                for m in scope.metrics().filter(|m| m.name() == metric) {
                    let (values, attrs): (Vec<u64>, Vec<Option<String>>) = match m.data() {
                        AggregatedMetrics::U64(MetricData::Sum(sum)) => sum
                            .data_points()
                            .map(|p| (p.value(), label(p.attributes())))
                            .unzip(),
                        AggregatedMetrics::U64(MetricData::Gauge(gauge)) => gauge
                            .data_points()
                            .map(|p| (p.value(), label(p.attributes())))
                            .unzip(),
                        other => panic!("unexpected data for {metric}: {other:?}"),
                    };
                    points.extend(attrs.into_iter().zip(values));
                }
            }
        }
        points
    }

    fn label<'a>(attributes: impl Iterator<Item = &'a KeyValue>) -> Option<String> {
        attributes
            .map(|kv| format!("{}={}", kv.key, kv.value))
            .next()
    }

    fn setup() -> (
        Arc<AuditDispatcher>,
        InMemoryMetricExporter,
        SdkMeterProvider,
    ) {
        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(exporter.clone()).build())
            .build();
        let dispatcher = dispatcher();
        register(&dispatcher, &SERVICE, &provider.meter("cadf-test"));
        (dispatcher, exporter, provider)
    }

    #[test]
    fn instruments_follow_the_service_identity_and_live_counters() {
        let (dispatcher, exporter, provider) = setup();
        let metrics = dispatcher.metrics();
        metrics.sink_errors.inc();
        metrics.sink_errors.inc();
        metrics.spool_quarantined.inc();

        let sink_errors = collect(&exporter, &provider, "testsvc.audit.sink_errors");
        assert_eq!(sink_errors, vec![(None, 2)]);
        let quarantined = collect(&exporter, &provider, "testsvc.audit.spool_quarantined");
        assert_eq!(quarantined, vec![(None, 1)]);
        let key_version = collect(&exporter, &provider, "testsvc.audit.hmac_key_version");
        assert_eq!(key_version, vec![(None, 3)]);
    }

    #[test]
    fn labeled_series_report_every_known_result() {
        let (dispatcher, exporter, provider) = setup();
        let metrics = dispatcher.metrics();
        metrics.shipped_events.add(["shipped"], 5);
        metrics.shipped_events.add(["skipped"], 1);
        metrics.spool_verified.add(["verified"], 9);

        let mut shipped = collect(&exporter, &provider, "testsvc.audit.shipped_events");
        shipped.sort();
        assert_eq!(
            shipped,
            vec![
                (Some("result=shipped".to_string()), 5),
                (Some("result=skipped".to_string()), 1),
            ]
        );
        let mut verified = collect(&exporter, &provider, "testsvc.audit.spool_verified");
        verified.sort();
        assert_eq!(
            verified,
            vec![
                (Some("result=invalid".to_string()), 0),
                (Some("result=verified".to_string()), 9),
            ]
        );
        let depth = collect(&exporter, &provider, "testsvc.audit.channel_depth");
        assert_eq!(depth.len(), 2);
    }

    #[test]
    fn dropped_dispatcher_stops_reporting_instead_of_being_kept_alive() {
        let (dispatcher, exporter, provider) = setup();
        let weak = Arc::downgrade(&dispatcher);
        drop(dispatcher);
        assert!(
            weak.upgrade().is_none(),
            "the meter must not keep the dispatcher alive"
        );
        assert!(collect(&exporter, &provider, "testsvc.audit.events").is_empty());
    }
}
