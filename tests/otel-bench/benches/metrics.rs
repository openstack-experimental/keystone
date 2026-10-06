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

//! ADR 0040: hot-path cost of the current `openstack-keystone-metrics`
//! primitives versus OpenTelemetry SDK synchronous instruments.
//!
//! Each pair mirrors a real Keystone call site: `auth_attempts_total{method,
//! outcome}` (labeled counter), an unlabeled counter, and
//! `policy_decision_duration_seconds{transport}` (labeled histogram).

use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use openstack_keystone_metrics::{Counter, LabeledCounter, LabeledHistogram};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter as OtelCounter, Histogram as OtelHistogram, MeterProvider};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};

const THREADS: usize = 4;

fn provider() -> SdkMeterProvider {
    // A very long interval so the reader never competes with the benchmark.
    let reader = PeriodicReader::builder(InMemoryMetricExporter::default())
        .with_interval(Duration::from_secs(3600))
        .build();
    SdkMeterProvider::builder().with_reader(reader).build()
}

/// Run `f` on `THREADS` threads, `iters` calls each, and return the wall time
/// of the slowest thread (per-call cost under contention).
fn contended<F>(iters: u64, f: F) -> Duration
where
    F: Fn() + Send + Sync + 'static,
{
    let f = Arc::new(f);
    let barrier = Arc::new(std::sync::Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let f = f.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let start = Instant::now();
                for _ in 0..iters {
                    f();
                }
                start.elapsed()
            })
        })
        .collect();
    handles
        .into_iter()
        .filter_map(|h| h.join().ok())
        .max()
        .unwrap_or_default()
}

fn bench(c: &mut Criterion) {
    let provider = provider();
    let meter = provider.meter("bench");

    // --- unlabeled counter -------------------------------------------------
    let old_counter = Arc::new(Counter::new());
    let otel_counter: OtelCounter<u64> = meter.u64_counter("keystone_test_total").build();

    let mut g = c.benchmark_group("counter_unlabeled");
    g.bench_function("keystone-metrics", |b| b.iter(|| old_counter.inc()));
    g.bench_function("otel-sdk", |b| b.iter(|| otel_counter.add(1, &[])));
    g.finish();

    // --- labeled counter (2 labels) ----------------------------------------
    let old_labeled = Arc::new(LabeledCounter::<2>::new(["method", "outcome"]));
    let otel_labeled: OtelCounter<u64> = meter.u64_counter("keystone_auth_attempts_total").build();

    let mut g = c.benchmark_group("counter_labeled_2");
    g.bench_function("keystone-metrics", |b| {
        b.iter(|| old_labeled.inc(black_box(["password", "success"])))
    });
    g.bench_function("otel-sdk", |b| {
        b.iter(|| {
            otel_labeled.add(
                1,
                &[
                    KeyValue::new("method", black_box("password")),
                    KeyValue::new("outcome", black_box("success")),
                ],
            )
        })
    });
    g.finish();

    // --- labeled histogram (1 label) ---------------------------------------
    let old_hist = Arc::new(LabeledHistogram::<1>::new(["transport"]));
    let otel_hist: OtelHistogram<f64> = meter
        .f64_histogram("keystone_policy_decision_duration_seconds")
        .with_boundaries(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
        ])
        .build();

    let mut g = c.benchmark_group("histogram_labeled_1");
    g.bench_function("keystone-metrics", |b| {
        b.iter(|| old_hist.record(black_box(["http"]), black_box(0.012)))
    });
    g.bench_function("otel-sdk", |b| {
        b.iter(|| {
            otel_hist.record(
                black_box(0.012),
                &[KeyValue::new("transport", black_box("http"))],
            )
        })
    });
    g.finish();

    // --- contention: THREADS threads hammer one series ----------------------
    let mut g = c.benchmark_group("counter_labeled_2_contended_4_threads");
    {
        let old = old_labeled.clone();
        g.bench_function("keystone-metrics", move |b| {
            let old = old.clone();
            b.iter_custom(|iters| {
                let old = old.clone();
                contended(iters, move || old.inc(["password", "success"]))
            })
        });
    }
    {
        let otel = otel_labeled.clone();
        g.bench_function("otel-sdk", move |b| {
            let otel = otel.clone();
            b.iter_custom(|iters| {
                let otel = otel.clone();
                contended(iters, move || {
                    otel.add(
                        1,
                        &[
                            KeyValue::new("method", "password"),
                            KeyValue::new("outcome", "success"),
                        ],
                    )
                })
            })
        });
    }
    g.finish();

    let mut g = c.benchmark_group("histogram_labeled_1_contended_4_threads");
    {
        let old = old_hist.clone();
        g.bench_function("keystone-metrics", move |b| {
            let old = old.clone();
            b.iter_custom(|iters| {
                let old = old.clone();
                contended(iters, move || old.record(["http"], 0.012))
            })
        });
    }
    {
        let otel = otel_hist.clone();
        g.bench_function("otel-sdk", move |b| {
            let otel = otel.clone();
            b.iter_custom(|iters| {
                let otel = otel.clone();
                contended(iters, move || {
                    otel.record(0.012, &[KeyValue::new("transport", "http")])
                })
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
