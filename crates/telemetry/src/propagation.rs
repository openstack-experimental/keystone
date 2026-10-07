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

//! W3C trace context propagation over HTTP headers (ADR 0040).
//!
//! The headers are untrusted client input: a malformed `traceparent` is
//! ignored by the propagator and the request simply starts a new trace. A
//! valid one chooses the trace id and, under the default `parent_based_ratio`
//! sampler, the sampling decision.

use http::{HeaderMap, HeaderName, HeaderValue};
use opentelemetry::global;
use opentelemetry::propagation::{Extractor, Injector};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Reads propagation headers out of a [`HeaderMap`].
struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(HeaderName::as_str).collect()
    }
}

/// Writes propagation headers into a [`HeaderMap`]; entries that are not valid
/// header names or values are dropped.
struct HeaderInjector<'a>(&'a mut HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            self.0.insert(name, value);
        }
    }
}

/// Make the remote caller's trace context (the `traceparent` and
/// `tracestate` request headers) the parent of `span`.
///
/// Call it right after creating the span, before anything is recorded into
/// it. A no-op when there is no valid context in `headers`, or when `span` is
/// not exported by an OpenTelemetry layer.
pub fn set_remote_parent(span: &tracing::Span, headers: &HeaderMap) {
    let parent =
        global::get_text_map_propagator(|propagator| propagator.extract(&HeaderExtractor(headers)));
    // Fails only when the span has no OpenTelemetry data, i.e. it is not
    // exported; there is nothing to parent then.
    let _ = span.set_parent(parent);
}

/// Write the `traceparent` (and `tracestate`) of `span` into `headers`, so a
/// response can be correlated with its trace.
pub fn inject_traceparent(span: &tracing::Span, headers: &mut HeaderMap) {
    let context = span.context();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&context, &mut HeaderInjector(headers));
    });
}

#[cfg(test)]
mod tests {
    use opentelemetry::trace::{SpanId, TraceId, TracerProvider as _};
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SimpleSpanProcessor};
    use tracing_subscriber::prelude::*;

    use super::*;

    const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const PARENT_SPAN_ID: &str = "00f067aa0ba902b7";

    /// A subscriber exporting every span to the returned in-memory exporter.
    fn pipeline() -> (
        impl tracing::Subscriber + Send + Sync,
        InMemorySpanExporter,
        SdkTracerProvider,
    ) {
        global::set_text_map_propagator(TraceContextPropagator::new());
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_span_processor(SimpleSpanProcessor::new(exporter.clone()))
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));
        (subscriber, exporter, provider)
    }

    fn headers(traceparent: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("traceparent", HeaderValue::from_str(traceparent).unwrap());
        h
    }

    #[test]
    fn a_valid_traceparent_becomes_the_parent() {
        let (subscriber, exporter, _provider) = pipeline();
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("http.server");
            set_remote_parent(
                &span,
                &headers(&format!("00-{TRACE_ID}-{PARENT_SPAN_ID}-01")),
            );
            let _entered = span.enter();
        });
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(
            spans[0].span_context.trace_id(),
            TraceId::from_hex(TRACE_ID).unwrap()
        );
        assert_eq!(
            spans[0].parent_span_id,
            SpanId::from_hex(PARENT_SPAN_ID).unwrap()
        );
        assert!(spans[0].span_context.is_sampled());
    }

    #[test]
    fn a_malformed_traceparent_starts_a_new_trace() {
        let (subscriber, exporter, _provider) = pipeline();
        let dispatch = tracing::Dispatch::new(subscriber);
        let all_zero_trace = format!("00-{}-{PARENT_SPAN_ID}-01", "0".repeat(32));
        let bad_version = format!("ff-{TRACE_ID}-{PARENT_SPAN_ID}-01");
        for bad in [
            "garbage",
            "00-zzzz-yyyy-01",
            all_zero_trace.as_str(),
            bad_version.as_str(),
        ] {
            tracing::dispatcher::with_default(&dispatch, || {
                let span = tracing::info_span!("http.server");
                set_remote_parent(&span, &headers(bad));
                let _entered = span.enter();
            });
        }
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 4);
        for span in spans {
            assert_ne!(
                span.span_context.trace_id(),
                TraceId::from_hex(TRACE_ID).unwrap()
            );
            assert_eq!(span.parent_span_id, SpanId::INVALID);
        }
    }

    #[test]
    fn the_response_traceparent_continues_the_trace() {
        let (subscriber, _exporter, _provider) = pipeline();
        let injected = tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("http.server");
            set_remote_parent(
                &span,
                &headers(&format!("00-{TRACE_ID}-{PARENT_SPAN_ID}-01")),
            );
            let _entered = span.enter();
            let mut out = HeaderMap::new();
            inject_traceparent(&span, &mut out);
            out
        });
        let value = injected.get("traceparent").unwrap().to_str().unwrap();
        let parts: Vec<&str> = value.split('-').collect();
        assert_eq!(parts[0], "00");
        assert_eq!(parts[1], TRACE_ID);
        // The span's own id, not the remote parent's.
        assert_ne!(parts[2], PARENT_SPAN_ID);
        assert_eq!(parts[2].len(), 16);
    }
}
