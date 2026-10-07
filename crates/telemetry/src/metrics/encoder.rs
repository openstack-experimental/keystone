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

//! Prometheus text exposition (v0.0.4) of the SDK's collected metrics.
//!
//! Naming is explicit, as ADR 0031 and `deploy/prometheus/alert_rules.yaml`
//! expect: names are exactly the instrument names; monotonic sums are
//! `counter`s, non-monotonic
//! sums and gauges are `gauge`s, histograms expose `_bucket`/`_sum`/`_count`
//! with cumulative buckets. Labels are sorted by name;
//! families are ordered by name and series by their rendered text, so the
//! output is stable.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, Metric, MetricData, ResourceMetrics};

/// Render `metrics` in the Prometheus text exposition format.
pub(crate) fn encode(metrics: &ResourceMetrics) -> String {
    // `BTreeMap` keeps families sorted by name; a family appearing in several
    // scopes is merged under one header.
    let mut families: BTreeMap<String, Family> = BTreeMap::new();
    for scope in metrics.scope_metrics() {
        for metric in scope.metrics() {
            add_metric(&mut families, metric);
        }
    }

    let mut out = String::new();
    for (name, family) in families {
        write_header(&mut out, &name, &family.help, family.kind);
        let mut series = family.series;
        series.sort();
        for line in series {
            out.push_str(&line);
        }
    }
    out
}

#[derive(Clone, Copy)]
enum Kind {
    Counter,
    Gauge,
    Histogram,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

struct Family {
    help: String,
    kind: Kind,
    /// Rendered lines, one series (or one histogram) per entry.
    series: Vec<String>,
}

fn add_metric(families: &mut BTreeMap<String, Family>, metric: &Metric) {
    match metric.data() {
        AggregatedMetrics::F64(data) => add_data(families, metric, data),
        AggregatedMetrics::U64(data) => add_data(families, metric, data),
        AggregatedMetrics::I64(data) => add_data(families, metric, data),
    }
}

/// Number types an instrument can report, as exposition text.
trait Number: Copy {
    fn render(self) -> String;
    fn as_f64(self) -> f64;
}

impl Number for f64 {
    fn render(self) -> String {
        float(self)
    }
    fn as_f64(self) -> f64 {
        self
    }
}

impl Number for u64 {
    fn render(self) -> String {
        self.to_string()
    }
    fn as_f64(self) -> f64 {
        self as f64
    }
}

impl Number for i64 {
    fn render(self) -> String {
        self.to_string()
    }
    fn as_f64(self) -> f64 {
        self as f64
    }
}

fn add_data<T: Number>(
    families: &mut BTreeMap<String, Family>,
    metric: &Metric,
    data: &MetricData<T>,
) {
    match data {
        MetricData::Sum(sum) => {
            let (name, kind) = if sum.is_monotonic() {
                (metric.name().to_string(), Kind::Counter)
            } else {
                (metric.name().to_string(), Kind::Gauge)
            };
            let family = family(families, name.clone(), metric, kind);
            for point in sum.data_points() {
                family
                    .series
                    .push(sample(&name, point.attributes(), &point.value().render()));
            }
        }
        MetricData::Gauge(gauge) => {
            let name = metric.name().to_string();
            let family = family(families, name.clone(), metric, Kind::Gauge);
            for point in gauge.data_points() {
                family
                    .series
                    .push(sample(&name, point.attributes(), &point.value().render()));
            }
        }
        MetricData::Histogram(histogram) => {
            let name = metric.name().to_string();
            let family = family(families, name.clone(), metric, Kind::Histogram);
            for point in histogram.data_points() {
                let series_labels = labels(point.attributes());
                let mut block = String::new();
                let mut cumulative = 0u64;
                for (bound, count) in point.bounds().zip(point.bucket_counts()) {
                    cumulative += count;
                    block.push_str(&line(
                        &format!("{name}_bucket"),
                        &series_labels,
                        Some(&float(bound)),
                        &cumulative.to_string(),
                    ));
                }
                block.push_str(&line(
                    &format!("{name}_bucket"),
                    &series_labels,
                    Some("+Inf"),
                    &point.count().to_string(),
                ));
                block.push_str(&line(
                    &format!("{name}_sum"),
                    &series_labels,
                    None,
                    &float(point.sum().as_f64()),
                ));
                block.push_str(&line(
                    &format!("{name}_count"),
                    &series_labels,
                    None,
                    &point.count().to_string(),
                ));
                family.series.push(block);
            }
        }
        // Not produced by Keystone's instruments; skipped rather than
        // rendered in a form Prometheus text cannot express.
        MetricData::ExponentialHistogram(_) => {}
    }
}

fn family<'a>(
    families: &'a mut BTreeMap<String, Family>,
    name: String,
    metric: &Metric,
    kind: Kind,
) -> &'a mut Family {
    families.entry(name).or_insert_with(|| Family {
        help: metric.description().to_string(),
        kind,
        series: Vec::new(),
    })
}

/// One exposition sample line for a plain sum or gauge point.
fn sample<'a>(name: &str, attributes: impl Iterator<Item = &'a KeyValue>, value: &str) -> String {
    line(name, &labels(attributes), None, value)
}

/// Labels sorted by name: the SDK does not keep one attribute order per
/// series, so the exposition fixes it.
fn labels<'a>(attributes: impl Iterator<Item = &'a KeyValue>) -> Vec<(String, String)> {
    let mut labels: Vec<(String, String)> = attributes
        .map(|kv| (kv.key.as_str().to_string(), kv.value.as_str().to_string()))
        .collect();
    labels.sort();
    labels
}

fn line(name: &str, labels: &[(String, String)], le: Option<&str>, value: &str) -> String {
    let mut out = String::new();
    out.push_str(name);
    if !labels.is_empty() || le.is_some() {
        out.push('{');
        let mut first = true;
        for (key, val) in labels {
            if !first {
                out.push(',');
            }
            first = false;
            let _ = write!(out, "{key}=\"{}\"", escape_label_value(val));
        }
        if let Some(le) = le {
            if !first {
                out.push(',');
            }
            let _ = write!(out, "le=\"{le}\"");
        }
        out.push('}');
    }
    out.push(' ');
    out.push_str(value);
    out.push('\n');
    out
}

fn write_header(out: &mut String, name: &str, help: &str, kind: Kind) {
    let _ = writeln!(out, "# HELP {name} {}", escape_help(help));
    let _ = writeln!(out, "# TYPE {name} {}", kind.as_str());
}

/// `f64` as Prometheus text: `1` rather than `1.0`, `+Inf`/`-Inf`/`NaN`.
fn float(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_string()
    } else if value.is_infinite() {
        if value > 0.0 { "+Inf" } else { "-Inf" }.to_string()
    } else {
        value.to_string()
    }
}

fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn escape_help(help: &str) -> String {
    help.replace('\\', "\\\\").replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_render_like_prometheus() {
        assert_eq!(float(1.0), "1");
        assert_eq!(float(0.005), "0.005");
        assert_eq!(float(f64::INFINITY), "+Inf");
        assert_eq!(float(f64::NEG_INFINITY), "-Inf");
        assert_eq!(float(f64::NAN), "NaN");
    }

    #[test]
    fn label_values_and_help_are_escaped() {
        assert_eq!(escape_label_value("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
        assert_eq!(escape_help("a\\b\nc"), "a\\\\b\\nc");
    }
}
