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

//! OpenTelemetry SDK setup: resource, samplers, OTLP exporters and the
//! providers behind them (ADR 0040).
//!
//! Compiled with the `otel` feature only. Export is asynchronous and bounded:
//! the batch span processor and the periodic metric reader run on their own
//! threads, drop on overflow and never block a request.

use std::collections::HashMap;

use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{ExporterBuildError, MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{BatchSpanProcessor, Sampler, SdkTracer, SdkTracerProvider};
use secrecy::ExposeSecret;
use thiserror::Error;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::registry::LookupSpan;

use crate::config::{OtlpProtocol, SamplerKind, TelemetrySettings};
use crate::metrics::{self, AlreadyStarted, PushConfig};
use crate::redact::PersonalDataFilter;

/// Name of the instrumentation scope of Keystone's own spans and metrics.
const SCOPE: &str = "openstack-keystone";

/// Failure to bring up the OTLP pipeline.
#[derive(Debug, Error)]
pub enum TelemetryInitError {
    /// The configured protocol is not compiled into this build.
    #[error("OTLP protocol {0:?} is not compiled into this build (cargo feature missing)")]
    ProtocolNotCompiled(OtlpProtocol),
    /// An exporter could not be built.
    #[error("building the OTLP {signal} exporter: {source}")]
    Exporter {
        /// `traces` or `metrics`.
        signal: &'static str,
        /// Underlying error.
        #[source]
        source: ExporterBuildError,
    },
    /// An instrument was created before this ran, so the process-wide
    /// metrics pipeline exists without OTLP.
    #[error("starting OTLP metrics: {0}")]
    MetricsAlreadyStarted(#[from] AlreadyStarted),
}

/// Failure while flushing and stopping the pipeline.
#[derive(Debug, Error)]
#[error("shutting down the {signal} pipeline: {message}")]
pub struct TelemetryShutdownError {
    /// `traces` or `metrics`.
    pub signal: &'static str,
    /// Error text reported by the SDK.
    pub message: String,
}

/// Owns the providers. Flush with [`TelemetryGuard::shutdown`] before the
/// process exits; dropping the guard does it as a best effort.
pub struct TelemetryGuard {
    tracer_provider: Option<SdkTracerProvider>,
    metrics: bool,
}

impl std::fmt::Debug for TelemetryGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetryGuard")
            .field("traces", &self.tracer_provider.is_some())
            .field("metrics", &self.metrics)
            .finish()
    }
}

impl TelemetryGuard {
    /// The `tracing` layer that turns spans into OpenTelemetry spans, or
    /// `None` when traces are disabled. Give it its own filter (see
    /// `[otel] span_level`) so only coarse spans reach the exporter.
    pub fn tracing_layer<S>(&self) -> Option<OpenTelemetryLayer<S, SdkTracer>>
    where
        S: tracing::Subscriber + for<'span> LookupSpan<'span>,
    {
        self.tracer_provider
            .as_ref()
            .map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer(SCOPE)))
    }

    /// Flush what is queued and stop the exporters. Blocks for up to the
    /// exporter timeout per signal: call it from a blocking context.
    /// Idempotent.
    pub fn shutdown(&mut self) -> Vec<TelemetryShutdownError> {
        let mut errors = Vec::new();
        if let Some(provider) = self.tracer_provider.take()
            && let Err(err) = provider.shutdown()
        {
            errors.push(TelemetryShutdownError {
                signal: "traces",
                message: err.to_string(),
            });
        }
        if std::mem::take(&mut self.metrics)
            && let Err(err) = metrics::shutdown()
        {
            errors.push(TelemetryShutdownError {
                signal: "metrics",
                message: err.to_string(),
            });
        }
        errors
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        for err in self.shutdown() {
            tracing::warn!("{err}");
        }
    }
}

/// Build the pipeline described by `settings` and register it globally (the
/// W3C `traceparent` propagator and the meter provider).
///
/// `service_version` becomes the `service.version` resource attribute.
pub fn init(
    settings: &TelemetrySettings,
    service_version: &str,
) -> Result<TelemetryGuard, TelemetryInitError> {
    let resource = resource(settings, service_version);

    let tracer_provider = settings
        .traces_enabled
        .then(|| build_tracer_provider(settings, &resource))
        .transpose()?;
    let metrics = settings.metrics_enabled;
    if metrics {
        start_metrics(settings, &resource)?;
    }

    if tracer_provider.is_some() {
        global::set_text_map_propagator(TraceContextPropagator::new());
    }
    Ok(TelemetryGuard {
        tracer_provider,
        metrics,
    })
}

/// The resource: environment detectors, the configured attributes, then
/// `service.name` / `service.version` so those two cannot be overridden by
/// `resource_attributes`.
fn resource(settings: &TelemetrySettings, service_version: &str) -> Resource {
    Resource::builder()
        .with_attributes(
            settings
                .resource_attributes
                .iter()
                .map(|(k, v)| KeyValue::new(k.clone(), v.clone())),
        )
        .with_service_name(settings.service_name.clone())
        .with_attribute(KeyValue::new(
            "service.version",
            service_version.to_string(),
        ))
        .build()
}

fn sampler(settings: &TelemetrySettings) -> Sampler {
    match settings.sampler {
        SamplerKind::ParentBasedRatio => {
            Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(settings.sampling_rate)))
        }
        SamplerKind::Ratio => Sampler::TraceIdRatioBased(settings.sampling_rate),
        SamplerKind::AlwaysOn => Sampler::AlwaysOn,
        SamplerKind::AlwaysOff => Sampler::AlwaysOff,
    }
}

fn build_tracer_provider(
    settings: &TelemetrySettings,
    resource: &Resource,
) -> Result<SdkTracerProvider, TelemetryInitError> {
    let exporter =
        build_span_exporter(settings).map_err(|source| TelemetryInitError::Exporter {
            signal: "traces",
            source,
        })?;
    Ok(SdkTracerProvider::builder()
        .with_sampler(sampler(settings))
        .with_resource(resource.clone())
        .with_span_processor(
            BatchSpanProcessor::builder(PersonalDataFilter::new(
                exporter,
                settings.include_user_ids,
            ))
            .build(),
        )
        .build())
}

/// Start the process-wide metrics pipeline with the OTLP exporter. Without
/// `[otel]` metrics the pipeline is created pull-only on first use instead.
fn start_metrics(
    settings: &TelemetrySettings,
    resource: &Resource,
) -> Result<(), TelemetryInitError> {
    let exporter =
        build_metric_exporter(settings).map_err(|source| TelemetryInitError::Exporter {
            signal: "metrics",
            source,
        })?;
    metrics::install(
        resource.clone(),
        PushConfig {
            exporter: Box::new(exporter),
            interval: settings.metrics_interval,
        },
    )?;
    Ok(())
}

/// Endpoint of one signal over HTTP: the configured base URL plus
/// `/v1/<signal>`. The exporter uses a programmatic endpoint verbatim, so the
/// signal path is appended here, as `oslo.middleware` does.
fn http_signal_endpoint(settings: &TelemetrySettings, signal: &str) -> String {
    format!(
        "{}/v1/{signal}",
        settings.endpoint.as_str().trim_end_matches('/')
    )
}

/// Exporter headers as the plain map the HTTP exporter takes.
fn header_map(settings: &TelemetrySettings) -> HashMap<String, String> {
    settings
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.expose_secret().to_string()))
        .collect()
}

fn build_span_exporter(settings: &TelemetrySettings) -> Result<SpanExporter, ExporterBuildError> {
    match settings.protocol {
        #[cfg(feature = "otlp-http")]
        OtlpProtocol::HttpProtobuf => {
            use opentelemetry_otlp::{Protocol, WithHttpConfig};
            SpanExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                .with_endpoint(http_signal_endpoint(settings, "traces"))
                .with_timeout(settings.timeout)
                .with_headers(header_map(settings))
                .build()
        }
        #[cfg(feature = "otlp-grpc")]
        OtlpProtocol::Grpc => {
            use opentelemetry_otlp::WithTonicConfig;
            let (endpoint, tls) = grpc::endpoint(settings);
            let mut builder = SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .with_timeout(settings.timeout)
                .with_metadata(grpc::metadata(settings)?);
            if let Some(tls) = tls {
                builder = builder.with_tls_config(tls);
            }
            builder.build()
        }
        #[allow(unreachable_patterns)]
        other => Err(not_compiled(other)),
    }
}

fn build_metric_exporter(
    settings: &TelemetrySettings,
) -> Result<MetricExporter, ExporterBuildError> {
    match settings.protocol {
        #[cfg(feature = "otlp-http")]
        OtlpProtocol::HttpProtobuf => {
            use opentelemetry_otlp::{Protocol, WithHttpConfig};
            MetricExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                .with_endpoint(http_signal_endpoint(settings, "metrics"))
                .with_timeout(settings.timeout)
                .with_headers(header_map(settings))
                .build()
        }
        #[cfg(feature = "otlp-grpc")]
        OtlpProtocol::Grpc => {
            use opentelemetry_otlp::WithTonicConfig;
            let (endpoint, tls) = grpc::endpoint(settings);
            let mut builder = MetricExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .with_timeout(settings.timeout)
                .with_metadata(grpc::metadata(settings)?);
            if let Some(tls) = tls {
                builder = builder.with_tls_config(tls);
            }
            builder.build()
        }
        #[allow(unreachable_patterns)]
        other => Err(not_compiled(other)),
    }
}

/// The requested protocol is not compiled in. Reported as an invalid
/// configuration of the exporter.
#[allow(dead_code)]
fn not_compiled(protocol: OtlpProtocol) -> ExporterBuildError {
    ExporterBuildError::InvalidConfiguration(format!(
        "protocol: {protocol:?} is not compiled into this build"
    ))
}

#[cfg(feature = "otlp-grpc")]
mod grpc {
    use http::{HeaderMap, HeaderName, HeaderValue};
    use opentelemetry_otlp::ExporterBuildError;
    use opentelemetry_otlp::tonic_types::metadata::MetadataMap;
    use opentelemetry_otlp::tonic_types::transport::ClientTlsConfig;
    use secrecy::ExposeSecret;

    use crate::config::TelemetrySettings;

    /// Endpoint plus the TLS config it needs. An `https` endpoint gets the
    /// webpki roots; `insecure` forces plaintext (as in `oslo.middleware`),
    /// by connecting over `http` instead.
    pub(super) fn endpoint(settings: &TelemetrySettings) -> (String, Option<ClientTlsConfig>) {
        let url = &settings.endpoint;
        let base = url.as_str().trim_end_matches('/').to_string();
        match (url.scheme(), settings.insecure) {
            ("https", true) => (base.replacen("https://", "http://", 1), None),
            ("https", false) => (base, Some(ClientTlsConfig::new().with_webpki_roots())),
            _ => (base, None),
        }
    }

    /// Exporter headers as gRPC metadata.
    pub(super) fn metadata(
        settings: &TelemetrySettings,
    ) -> Result<MetadataMap, ExporterBuildError> {
        let mut headers = HeaderMap::new();
        for (name, value) in &settings.headers {
            let name =
                HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()).map_err(|_| {
                    ExporterBuildError::InvalidConfiguration(
                        "headers: a header name is not valid".to_string(),
                    )
                })?;
            let value = HeaderValue::from_str(value.expose_secret()).map_err(|_| {
                ExporterBuildError::InvalidConfiguration(
                    "headers: a header value is not valid".to_string(),
                )
            })?;
            headers.insert(name, value);
        }
        Ok(MetadataMap::from_headers(headers))
    }
}

#[cfg(test)]
#[cfg(feature = "otlp-http")]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use tracing_subscriber::prelude::*;

    use super::*;
    use crate::config::{OsloMiddlewareTracingConfig, OtelConfig, resolve};

    /// One request the fake collector received.
    #[derive(Debug)]
    struct Received {
        path: String,
        authorization: Option<String>,
        content_type: Option<String>,
        body_len: usize,
    }

    /// A one-thread OTLP/HTTP collector that answers `200` to everything and
    /// reports each request it sees.
    fn collector() -> (String, mpsc::Receiver<Received>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // Read until the headers and the declared body are complete.
                let (head_end, content_len) = loop {
                    let n = stream.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break (buf.len(), 0);
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (pos + 4, len);
                    }
                };
                while buf.len() < head_end + content_len {
                    let n = stream.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let head = String::from_utf8_lossy(&buf[..head_end.min(buf.len())]).to_string();
                let header = |name: &str| {
                    head.lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                    })
                };
                let _ = tx.send(Received {
                    path: head
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or_default()
                        .to_string(),
                    authorization: header("authorization"),
                    content_type: header("content-type"),
                    body_len: buf.len().saturating_sub(head_end),
                });
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        (format!("http://{addr}"), rx)
    }

    fn settings(endpoint: &str) -> TelemetrySettings {
        let otel: OtelConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "endpoint": endpoint,
            "headers": "authorization=Bearer s3cret",
            "sampler": "always_on",
            "metrics_interval": 0.1,
            "timeout": 5,
            "service_name": "ks-test",
            "resource_attributes": "deployment.environment=test",
        }))
        .unwrap();
        resolve(&otel, &OsloMiddlewareTracingConfig::default())
            .unwrap()
            .settings
            .unwrap()
    }

    fn wait_for(rx: &mpsc::Receiver<Received>, path: &str) -> Received {
        let deadline = Instant::now() + Duration::from_secs(10);
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match rx.recv_timeout(left) {
                Ok(r) if r.path == path => return r,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        panic!("no request for {path} within 10s");
    }

    /// Started the way `keystone` does: inside a tokio runtime, flushed from a
    /// blocking task. A span and a metric must reach the collector on the
    /// signal paths, with the configured headers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spans_and_metrics_reach_the_collector() {
        let (endpoint, rx) = collector();
        let mut guard = init(&settings(&endpoint), "0.0.0-test").unwrap();

        let subscriber = tracing_subscriber::registry().with(guard.tracing_layer().unwrap());
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("exported_span", answer = 42);
            let _entered = span.enter();
        });
        crate::metrics::CounterVec::new(
            &crate::metrics::meter(),
            "keystone_test_total",
            "Test.",
            ["kind"],
        )
        .inc(["x".into()]);

        let errors = tokio::task::spawn_blocking(move || guard.shutdown())
            .await
            .unwrap();
        assert!(errors.is_empty(), "{errors:?}");

        let traces = wait_for(&rx, "/v1/traces");
        assert_eq!(
            traces.content_type.as_deref(),
            Some("application/x-protobuf")
        );
        assert_eq!(traces.authorization.as_deref(), Some("Bearer s3cret"));
        assert!(traces.body_len > 0);
        let metrics = wait_for(&rx, "/v1/metrics");
        assert_eq!(metrics.authorization.as_deref(), Some("Bearer s3cret"));
        assert!(metrics.body_len > 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn traces_only_has_no_metrics_pipeline() {
        let (endpoint, _rx) = collector();
        let mut s = settings(&endpoint);
        s.metrics_enabled = false;
        let mut guard = init(&s, "0.0.0-test").unwrap();
        assert!(
            guard
                .tracing_layer::<tracing_subscriber::Registry>()
                .is_some()
        );
        assert!(!guard.metrics);
        let errors = tokio::task::spawn_blocking(move || guard.shutdown())
            .await
            .unwrap();
        assert!(errors.is_empty());
    }

    #[test]
    fn disabled_traces_give_no_layer() {
        let (endpoint, _rx) = collector();
        let mut s = settings(&endpoint);
        s.traces_enabled = false;
        s.metrics_enabled = false;
        let guard = init(&s, "0.0.0-test").unwrap();
        assert!(
            guard
                .tracing_layer::<tracing_subscriber::Registry>()
                .is_none()
        );
    }

    #[test]
    fn http_signal_endpoint_appends_the_signal_path() {
        let mut s = settings("http://collector:4318");
        assert_eq!(
            http_signal_endpoint(&s, "traces"),
            "http://collector:4318/v1/traces"
        );
        s.endpoint = url::Url::parse("https://host/otlp/").unwrap();
        assert_eq!(
            http_signal_endpoint(&s, "metrics"),
            "https://host/otlp/v1/metrics"
        );
    }

    #[test]
    fn shutdown_is_idempotent() {
        let (endpoint, _rx) = collector();
        // The process-wide metrics pipeline can be installed once per
        // process; `spans_and_metrics_reach_the_collector` owns that.
        let mut s = settings(&endpoint);
        s.metrics_enabled = false;
        let mut guard = init(&s, "0.0.0-test").unwrap();
        assert!(guard.shutdown().is_empty());
        assert!(guard.shutdown().is_empty());
    }
}

#[cfg(test)]
#[cfg(feature = "otlp-grpc")]
mod grpc_tests {
    use super::*;
    use crate::config::{OsloMiddlewareTracingConfig, OtelConfig, resolve};

    fn settings(json: serde_json::Value) -> TelemetrySettings {
        let otel: OtelConfig = serde_json::from_value(json).unwrap();
        resolve(&otel, &OsloMiddlewareTracingConfig::default())
            .unwrap()
            .settings
            .unwrap()
    }

    #[test]
    fn https_gets_tls_and_http_does_not() {
        let s = settings(serde_json::json!({
            "enabled": true, "protocol": "grpc", "endpoint": "https://collector:4317"
        }));
        let (endpoint, tls) = grpc::endpoint(&s);
        assert_eq!(endpoint, "https://collector:4317");
        assert!(tls.is_some());

        let s = settings(serde_json::json!({
            "enabled": true, "protocol": "grpc", "endpoint": "http://collector:4317"
        }));
        let (endpoint, tls) = grpc::endpoint(&s);
        assert_eq!(endpoint, "http://collector:4317");
        assert!(tls.is_none());
    }

    #[test]
    fn insecure_forces_plaintext_on_an_https_endpoint() {
        let s = settings(serde_json::json!({
            "enabled": true, "protocol": "grpc", "insecure": true,
            "endpoint": "https://collector:4317"
        }));
        let (endpoint, tls) = grpc::endpoint(&s);
        assert_eq!(endpoint, "http://collector:4317");
        assert!(tls.is_none());
    }

    #[test]
    fn headers_become_lowercase_metadata_and_bad_ones_are_rejected() {
        let s = settings(serde_json::json!({
            "enabled": true, "protocol": "grpc", "headers": "Authorization=Bearer x"
        }));
        let md = grpc::metadata(&s).unwrap();
        assert_eq!(
            md.get("authorization").unwrap().to_str().unwrap(),
            "Bearer x"
        );

        let s = settings(serde_json::json!({
            "enabled": true, "protocol": "grpc", "headers": "bad name=v"
        }));
        let err = grpc::metadata(&s).unwrap_err().to_string();
        assert!(err.contains("headers"), "{err}");
    }

    /// The tonic exporters build lazily (no connection is made), also for an
    /// `https` endpoint with TLS, inside a runtime as in `keystone`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn grpc_pipeline_builds_and_shuts_down() {
        let mut s = settings(serde_json::json!({
            "enabled": true, "protocol": "grpc",
            "endpoint": "https://127.0.0.1:1", "metrics_interval": 3600
        }));
        // The process-wide metrics pipeline is installed once per process
        // (by the HTTP test); only check that the gRPC exporter builds.
        assert!(build_metric_exporter(&s).is_ok());
        s.metrics_enabled = false;
        let mut guard = init(&s, "0.0.0-test").unwrap();
        assert!(
            guard
                .tracing_layer::<tracing_subscriber::Registry>()
                .is_some()
        );
        let errors = tokio::task::spawn_blocking(move || guard.shutdown())
            .await
            .unwrap();
        assert!(errors.is_empty(), "{errors:?}");
    }
}
