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

//! Metrics (ADR 0040): typed instruments on one OpenTelemetry meter, served
//! as Prometheus text on `/metrics` and, when configured, pushed over OTLP.
//!
//! The instruments keep the ADR 0031 cardinality rule at the type level. Label
//! names are fixed per instrument (`const N` array) and a label value is a
//! [`Label`]: a `&'static str` (also what an enum maps to) or, explicitly, a
//! [`Label::bounded`] value that a reviewer can see is drawn from a finite,
//! operator-configured set. An owned `String` or a request-derived `&str` does
//! not convert.
//!
//! Instruments are built from a [`Meter`]. Production code takes it from
//! [`meter`]; tests build a [`MetricsPipeline`] of their own so counts do not
//! leak between tests.
//!
//! Unlike the hand-rolled counters this replaces, a series exists only once it
//! was recorded. Where a series must be visible at zero, record it with
//! `add(0, ..)` at startup.

mod encoder;
mod pipeline;

use std::borrow::Cow;

use opentelemetry::metrics::{Counter, Gauge, Histogram, UpDownCounter};
use opentelemetry::{Key, KeyValue, StringValue, Value};

pub use opentelemetry::metrics::Meter;
pub use pipeline::{AlreadyStarted, MetricsPipeline};
#[cfg(feature = "sdk")]
pub(crate) use pipeline::{PushConfig, install};

/// Upper bounds (seconds) of the latency histograms, shared by every
/// subsystem so dashboards can compare them.
pub const LATENCY_BUCKETS: [f64; 11] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// The process-wide meter. Create instruments after telemetry init: an
/// instrument made earlier would not be exported over OTLP.
pub fn meter() -> Meter {
    pipeline::global().meter()
}

/// The process-wide metrics as Prometheus text (v0.0.4). Blocks while the
/// SDK collects, so call it from `spawn_blocking` in async code.
pub fn render_prometheus() -> String {
    pipeline::global().render()
}

/// Flush and stop the process-wide pipeline.
#[cfg(feature = "sdk")]
pub(crate) fn shutdown() -> opentelemetry_sdk::error::OTelSdkResult {
    pipeline::global().shutdown()
}

/// A metric label value that is bounded by construction (ADR 0031).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label<'a>(Inner<'a>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Inner<'a> {
    Static(&'static str),
    Bounded(&'a str),
}

impl<'a> Label<'a> {
    /// A value from a finite set known when the program is written.
    pub const fn fixed(value: &'static str) -> Self {
        Self(Inner::Static(value))
    }

    /// A value read at run time from a finite, operator-configured set (for
    /// example the identity providers a deployment registered). Never use it
    /// for anything a client chooses: user names, ids, paths, error text.
    pub const fn bounded(value: &'a str) -> Self {
        Self(Inner::Bounded(value))
    }

    fn value(self) -> Value {
        match self.0 {
            Inner::Static(value) => Value::String(StringValue::from(value)),
            Inner::Bounded(value) => Value::String(StringValue::from(value.to_string())),
        }
    }
}

impl From<&'static str> for Label<'_> {
    fn from(value: &'static str) -> Self {
        Self::fixed(value)
    }
}

/// Attributes of one measurement: the instrument's label names paired with
/// the given values.
fn attributes<const N: usize>(names: &[&'static str; N], values: [Label<'_>; N]) -> [KeyValue; N] {
    std::array::from_fn(|i| KeyValue::new(Key::from_static_str(names[i]), values[i].value()))
}

/// A monotonic counter with `N` labels, exposed under exactly `name` (which
/// should end in `_total`).
#[derive(Clone, Debug)]
pub struct CounterVec<const N: usize> {
    names: [&'static str; N],
    inner: Counter<u64>,
}

impl<const N: usize> CounterVec<N> {
    /// `name` is the exposed series name, ending in `_total` by convention.
    pub fn new(
        meter: &Meter,
        name: &'static str,
        help: &'static str,
        label_names: [&'static str; N],
    ) -> Self {
        Self {
            names: label_names,
            inner: meter.u64_counter(name).with_description(help).build(),
        }
    }

    /// Add 1.
    pub fn inc(&self, labels: [Label<'_>; N]) {
        self.add(1, labels);
    }

    /// Add `n`. `add(0, ..)` makes the series visible at zero.
    pub fn add(&self, n: u64, labels: [Label<'_>; N]) {
        self.inner.add(n, &attributes(&self.names, labels));
    }
}

/// A value that goes up and down by deltas (in-flight requests), exposed as a
/// `gauge`.
#[derive(Clone, Debug)]
pub struct UpDownCounterVec<const N: usize> {
    names: [&'static str; N],
    inner: UpDownCounter<i64>,
}

impl<const N: usize> UpDownCounterVec<N> {
    /// `name` is the exposed series name.
    pub fn new(
        meter: &Meter,
        name: &'static str,
        help: &'static str,
        label_names: [&'static str; N],
    ) -> Self {
        Self {
            names: label_names,
            inner: meter
                .i64_up_down_counter(name)
                .with_description(help)
                .build(),
        }
    }

    /// Add `delta` (negative to decrease). `add(0, ..)` makes the series
    /// visible at zero.
    pub fn add(&self, delta: i64, labels: [Label<'_>; N]) {
        self.inner.add(delta, &attributes(&self.names, labels));
    }
}

/// A value that is set to the latest reading (a size, a backlog), exposed as
/// a `gauge`. Nothing is exposed until it is set once.
#[derive(Clone, Debug)]
pub struct GaugeVec<const N: usize> {
    names: [&'static str; N],
    inner: Gauge<i64>,
}

impl<const N: usize> GaugeVec<N> {
    /// `name` is the exposed series name.
    pub fn new(
        meter: &Meter,
        name: &'static str,
        help: &'static str,
        label_names: [&'static str; N],
    ) -> Self {
        Self {
            names: label_names,
            inner: meter.i64_gauge(name).with_description(help).build(),
        }
    }

    /// Set the current value.
    pub fn set(&self, value: i64, labels: [Label<'_>; N]) {
        self.inner.record(value, &attributes(&self.names, labels));
    }
}

/// A distribution with explicit bucket bounds, exposed as `_bucket`, `_sum`
/// and `_count`.
#[derive(Clone, Debug)]
pub struct HistogramVec<const N: usize> {
    names: [&'static str; N],
    inner: Histogram<f64>,
}

impl<const N: usize> HistogramVec<N> {
    /// `name` is the exposed series base name; `bounds` are the ascending
    /// upper bounds of the buckets, `+Inf` being implied.
    pub fn new(
        meter: &Meter,
        name: &'static str,
        help: &'static str,
        label_names: [&'static str; N],
        bounds: &[f64],
    ) -> Self {
        Self {
            names: label_names,
            inner: meter
                .f64_histogram(name)
                .with_description(help)
                .with_boundaries(bounds.to_vec())
                .build(),
        }
    }

    /// Record one observation.
    pub fn record(&self, value: f64, labels: [Label<'_>; N]) {
        self.inner.record(value, &attributes(&self.names, labels));
    }
}

/// Receives the series of one observation: label values and the value.
pub type Emit<'e, const N: usize> = &'e dyn Fn([Label<'_>; N], u64);

/// Register a counter whose value is read when metrics are collected, for
/// totals a subsystem already keeps (an atomic) and that must not be counted a
/// second time. `read` calls `emit` once per series; a series it leaves out is
/// not exposed. `name` is the exposed name.
pub fn observe_counter<const N: usize>(
    meter: &Meter,
    name: impl Into<Cow<'static, str>>,
    help: impl Into<Cow<'static, str>>,
    label_names: [&'static str; N],
    read: impl Fn(Emit<'_, N>) + Send + Sync + 'static,
) {
    let _ = meter
        .u64_observable_counter(name)
        .with_description(help)
        .with_callback(move |observer| {
            read(&|values, total| observer.observe(total, &attributes(&label_names, values)));
        })
        .build();
}

/// Register a gauge whose value is read when metrics are collected (a queue
/// depth, a size kept elsewhere). See [`observe_counter`].
pub fn observe_gauge<const N: usize>(
    meter: &Meter,
    name: impl Into<Cow<'static, str>>,
    help: impl Into<Cow<'static, str>>,
    label_names: [&'static str; N],
    read: impl Fn(Emit<'_, N>) + Send + Sync + 'static,
) {
    let _ = meter
        .u64_observable_gauge(name)
        .with_description(help)
        .with_callback(move |observer| {
            read(&|values, value| observer.observe(value, &attributes(&label_names, values)));
        })
        .build();
}

/// Receives the series of one signed observation: label values and the value.
pub type EmitSigned<'e, const N: usize> = &'e dyn Fn([Label<'_>; N], i64);

/// Like [`observe_gauge`] for a value that can be negative (a sentinel such as
/// `-1` for "unknown").
pub fn observe_gauge_signed<const N: usize>(
    meter: &Meter,
    name: impl Into<Cow<'static, str>>,
    help: impl Into<Cow<'static, str>>,
    label_names: [&'static str; N],
    read: impl Fn(EmitSigned<'_, N>) + Send + Sync + 'static,
) {
    let _ = meter
        .i64_observable_gauge(name)
        .with_description(help)
        .with_callback(move |observer| {
            read(&|values, value| observer.observe(value, &attributes(&label_names, values)));
        })
        .build();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_instruments_render_with_their_labels() {
        let pipeline = MetricsPipeline::new();
        let meter = pipeline.meter();
        let counter = CounterVec::new(&meter, "keystone_t_events_total", "Events.", ["kind"]);
        counter.inc(["a".into()]);
        counter.add(2, [Label::bounded(&String::from("b"))]);
        let gauge = UpDownCounterVec::new(&meter, "keystone_t_open", "Open.", []);
        gauge.add(0, []);
        GaugeVec::new(&meter, "keystone_t_size", "Size.", []).set(7, []);
        let histogram = HistogramVec::new(&meter, "keystone_t_seconds", "Time.", [], &[1.0]);
        histogram.record(0.5, []);

        let text = pipeline.render();
        assert!(
            text.contains("keystone_t_events_total{kind=\"a\"} 1\n"),
            "{text}"
        );
        assert!(
            text.contains("keystone_t_events_total{kind=\"b\"} 2\n"),
            "{text}"
        );
        assert!(
            text.contains("# TYPE keystone_t_open gauge\nkeystone_t_open 0\n"),
            "{text}"
        );
        assert!(
            text.contains("keystone_t_seconds_bucket{le=\"+Inf\"} 1\n"),
            "{text}"
        );
    }
}
