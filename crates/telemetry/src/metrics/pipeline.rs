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

//! One `MeterProvider` behind both the Prometheus pull view and the optional
//! OTLP push (ADR 0040).
//!
//! The SDK's pull reader (`ManualReader`) is experimental in the version we
//! use, so the provider has a single stable `PeriodicReader` whose exporter
//! ([`Tee`]) does two things on every collection: it renders the Prometheus
//! text into a snapshot, and it forwards the data to the OTLP exporter when
//! one is configured. A scrape forces a collection and reads the snapshot; the
//! forward is skipped for those forced collections, so scraping does not
//! cause extra OTLP requests.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use opentelemetry::metrics::Meter;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::metrics::data::ResourceMetrics;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider, Temporality};

use super::encoder::encode;

/// Name of the instrumentation scope of Keystone's own metrics.
const SCOPE: &str = "openstack-keystone";

/// Collection interval when nothing is pushed: only scrapes read the data.
const PULL_ONLY_INTERVAL: Duration = Duration::from_secs(3600);

/// Object-safe view of the OTLP metric exporter, which is generic and has
/// `impl Future` methods.
pub(crate) trait Push: Send + Sync + 'static {
    fn export<'a>(
        &'a self,
        metrics: &'a ResourceMetrics,
    ) -> Pin<Box<dyn Future<Output = OTelSdkResult> + Send + 'a>>;
    fn force_flush(&self) -> OTelSdkResult;
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult;
}

impl<E: PushMetricExporter> Push for E {
    fn export<'a>(
        &'a self,
        metrics: &'a ResourceMetrics,
    ) -> Pin<Box<dyn Future<Output = OTelSdkResult> + Send + 'a>> {
        Box::pin(PushMetricExporter::export(self, metrics))
    }
    fn force_flush(&self) -> OTelSdkResult {
        PushMetricExporter::force_flush(self)
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        PushMetricExporter::shutdown_with_timeout(self, timeout)
    }
}

/// OTLP side of a pipeline: the exporter and how often to push.
#[cfg_attr(not(feature = "sdk"), allow(dead_code))]
pub(crate) struct PushConfig {
    pub(crate) exporter: Box<dyn Push>,
    pub(crate) interval: Duration,
}

/// State shared between the reader's thread and scrapes.
struct Tee {
    /// Prometheus text of the latest collection.
    snapshot: Mutex<String>,
    push: Option<Box<dyn Push>>,
    /// Set while a scrape forces a collection: the data is for the snapshot
    /// only.
    scraping: AtomicBool,
}

/// The exporter handed to the `PeriodicReader`.
struct TeeExporter(Arc<Tee>);

impl PushMetricExporter for TeeExporter {
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        let tee = &self.0;
        let text = encode(metrics);
        *tee.snapshot.lock().unwrap_or_else(PoisonError::into_inner) = text;
        if tee.scraping.load(Ordering::Acquire) {
            return Ok(());
        }
        match &tee.push {
            Some(push) => push.export(metrics).await,
            None => Ok(()),
        }
    }

    fn force_flush(&self) -> OTelSdkResult {
        match &self.0.push {
            Some(push) if !self.0.scraping.load(Ordering::Acquire) => push.force_flush(),
            _ => Ok(()),
        }
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        match &self.0.push {
            Some(push) => push.shutdown_with_timeout(timeout),
            None => Ok(()),
        }
    }

    fn temporality(&self) -> Temporality {
        // Prometheus is cumulative, and so is the OTLP default.
        Temporality::Cumulative
    }
}

/// A meter provider with its Prometheus view.
///
/// The process has one ([`global`]); tests build their own for isolation.
pub struct MetricsPipeline {
    provider: SdkMeterProvider,
    meter: Meter,
    tee: Arc<Tee>,
    /// Serialises scrapes: the `scraping` flag is per pipeline.
    scrape: Mutex<()>,
}

impl MetricsPipeline {
    /// A pipeline that only serves scrapes.
    pub fn new() -> Self {
        Self::build(Resource::builder_empty().build(), None)
    }

    pub(crate) fn build(resource: Resource, push: Option<PushConfig>) -> Self {
        let (push, interval) = match push {
            Some(PushConfig { exporter, interval }) => (Some(exporter), interval),
            None => (None, PULL_ONLY_INTERVAL),
        };
        let tee = Arc::new(Tee {
            snapshot: Mutex::new(String::new()),
            push,
            scraping: AtomicBool::new(false),
        });
        let reader = PeriodicReader::builder(TeeExporter(tee.clone()))
            .with_interval(interval)
            .build();
        let provider = SdkMeterProvider::builder()
            .with_resource(resource)
            .with_reader(reader)
            .build();
        let meter = opentelemetry::metrics::MeterProvider::meter(&provider, SCOPE);
        Self {
            provider,
            meter,
            tee,
            scrape: Mutex::new(()),
        }
    }

    /// The meter instruments are created from.
    pub fn meter(&self) -> Meter {
        self.meter.clone()
    }

    /// The current values as Prometheus text (v0.0.4).
    ///
    /// Forces a collection and waits for it, so call it from a blocking
    /// context (`spawn_blocking` in async code). Empty if nothing was
    /// recorded yet or the pipeline is shut down.
    pub fn render(&self) -> String {
        let _serialised = self.scrape.lock().unwrap_or_else(PoisonError::into_inner);
        self.tee.scraping.store(true, Ordering::Release);
        // An error here means the pipeline is shut down; the snapshot then
        // keeps the last collection.
        let _ = self.provider.force_flush();
        self.tee.scraping.store(false, Ordering::Release);
        self.tee
            .snapshot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Flush what is queued and stop the reader.
    #[cfg(feature = "sdk")]
    pub(crate) fn shutdown(&self) -> OTelSdkResult {
        self.provider.shutdown()
    }
}

impl Default for MetricsPipeline {
    fn default() -> Self {
        Self::new()
    }
}

static GLOBAL: OnceLock<MetricsPipeline> = OnceLock::new();

/// The process-wide pipeline. Created pull-only on first use unless
/// [`install`] ran first.
pub(crate) fn global() -> &'static MetricsPipeline {
    GLOBAL.get_or_init(MetricsPipeline::new)
}

/// The OTLP export was requested after the process-wide pipeline had been
/// created, so it cannot be added any more.
#[derive(Debug, thiserror::Error)]
#[error("the metrics pipeline was already created (an instrument was used before telemetry init)")]
pub struct AlreadyStarted;

/// Create the process-wide pipeline with OTLP push. Must run before the
/// first instrument is created.
#[cfg(feature = "sdk")]
pub(crate) fn install(resource: Resource, push: PushConfig) -> Result<(), AlreadyStarted> {
    GLOBAL
        .set(MetricsPipeline::build(resource, Some(push)))
        .map_err(|_| AlreadyStarted)
}

#[cfg(test)]
mod tests {
    use opentelemetry::KeyValue;

    use super::*;

    #[test]
    fn counter_gauge_and_histogram_are_exposed() {
        let pipeline = MetricsPipeline::new();
        let meter = pipeline.meter();
        let counter = meter
            .u64_counter("keystone_test_requests_total")
            .with_description("Requests.")
            .build();
        counter.add(2, &[KeyValue::new("kind", "b")]);
        counter.add(1, &[KeyValue::new("kind", "a")]);
        counter.add(1, &[KeyValue::new("kind", "a")]);
        let gauge = meter
            .i64_up_down_counter("keystone_test_in_flight")
            .with_description("In flight.")
            .build();
        gauge.add(3, &[]);
        gauge.add(-1, &[]);
        let histogram = meter
            .f64_histogram("keystone_test_duration_seconds")
            .with_description("Duration.")
            .with_boundaries(vec![0.1, 1.0])
            .build();
        histogram.record(0.05, &[KeyValue::new("kind", "a")]);
        histogram.record(0.5, &[KeyValue::new("kind", "a")]);
        histogram.record(5.0, &[KeyValue::new("kind", "a")]);

        assert_eq!(
            pipeline.render(),
            "\
# HELP keystone_test_duration_seconds Duration.
# TYPE keystone_test_duration_seconds histogram
keystone_test_duration_seconds_bucket{kind=\"a\",le=\"0.1\"} 1
keystone_test_duration_seconds_bucket{kind=\"a\",le=\"1\"} 2
keystone_test_duration_seconds_bucket{kind=\"a\",le=\"+Inf\"} 3
keystone_test_duration_seconds_sum{kind=\"a\"} 5.55
keystone_test_duration_seconds_count{kind=\"a\"} 3
# HELP keystone_test_in_flight In flight.
# TYPE keystone_test_in_flight gauge
keystone_test_in_flight 2
# HELP keystone_test_requests_total Requests.
# TYPE keystone_test_requests_total counter
keystone_test_requests_total{kind=\"a\"} 2
keystone_test_requests_total{kind=\"b\"} 2
"
        );
    }

    #[test]
    fn nothing_recorded_renders_nothing() {
        assert_eq!(MetricsPipeline::new().render(), "");
    }

    #[test]
    fn repeated_scrapes_are_cumulative() {
        let pipeline = MetricsPipeline::new();
        let counter = pipeline
            .meter()
            .u64_counter("keystone_test_n_total")
            .build();
        counter.add(1, &[]);
        assert!(pipeline.render().contains("keystone_test_n_total 1\n"));
        counter.add(1, &[]);
        assert!(pipeline.render().contains("keystone_test_n_total 2\n"));
    }
}
