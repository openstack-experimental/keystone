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

//! ADR 0040: per-span overhead of the `tracing-opentelemetry` layer on a
//! `#[instrument]`-style span with two fields, as on the token and policy
//! paths.
//!
//! Scenarios: no OTel layer (today), layer with the sampler off, 10 % ratio,
//! and always-on with a batch processor feeding an in-memory exporter.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::{
    BatchSpanProcessor, InMemorySpanExporter, Sampler, SdkTracerProvider,
};
use tracing::dispatcher::{self, Dispatch};
use tracing_subscriber::prelude::*;

fn work(i: u64) -> u64 {
    let span = tracing::info_span!("validate_token", method = "fernet", outcome = "success");
    let _g = span.enter();
    black_box(i).wrapping_mul(31)
}

fn run(c: &mut Criterion, name: &str, dispatch: Dispatch) {
    dispatcher::with_default(&dispatch, || {
        c.bench_function(name, |b| {
            let mut i = 0u64;
            b.iter(|| {
                i = work(i);
            })
        });
    });
}

fn otel_dispatch(sampler: Sampler) -> (Dispatch, SdkTracerProvider) {
    let provider = SdkTracerProvider::builder()
        .with_sampler(sampler)
        .with_span_processor(BatchSpanProcessor::builder(InMemorySpanExporter::default()).build())
        .build();
    let tracer = provider.tracer("bench");
    let subscriber =
        tracing_subscriber::registry().with(tracing_opentelemetry::layer().with_tracer(tracer));
    (Dispatch::new(subscriber), provider)
}

fn bench(c: &mut Criterion) {
    // Baselines: no subscriber at all (spans compiled in but disabled), and a
    // bare registry (span ids are allocated, nothing consumes them).
    run(c, "span/no-subscriber", Dispatch::none());
    run(
        c,
        "span/registry-only",
        Dispatch::new(tracing_subscriber::registry()),
    );

    for (name, sampler) in [
        ("span/otel-sampler-off", Sampler::AlwaysOff),
        ("span/otel-ratio-0.1", Sampler::TraceIdRatioBased(0.1)),
        ("span/otel-always-on", Sampler::AlwaysOn),
    ] {
        let (dispatch, provider) = otel_dispatch(sampler);
        run(c, name, dispatch);
        drop(provider);
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
